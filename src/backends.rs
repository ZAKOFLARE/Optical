//! 后端服务管理：命名上游池 + 分组 + 负载均衡 + 主动健康检查。
//!
//! 对应需求里的「类似宝塔面板中对接的 nginx」：后端是独立实体，有名字、分组、备注、
//! 权重、探活路径和间隔；路由通过 `backend = "app"` 或 `backend_group = "app"` 引用。
//!
//! 两条硬规则：
//! 1. **选路永远不跨组**。早期实现把"命中的后端"和"全库所有健康后端"混在一个池里轮询，
//!    结果是路由指向 app-1，流量却可能落到 api 组的机器上——分组形同虚设，还很难排查。
//! 2. 组内全不健康时才降级到"组内按权重赌一把"，并打 warn；不会去借别的组的成员。

use crate::config::{BackendConfig, BackendGroupConfig, Config, LbStrategy, TargetSpec};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct BackendState {
    pub healthy: AtomicBool,
    /// 最近一次探测的 unix 毫秒
    pub last_check_ms: AtomicI64,
    pub last_status: AtomicU16,
    pub consecutive_failures: AtomicU32,
    pub checks: AtomicU64,
    pub failures: AtomicU64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendView {
    pub name: String,
    pub url: String,
    pub group: String,
    pub note: String,
    pub weight: u32,
    pub enabled: bool,
    pub health_path: String,
    pub healthy: bool,
    pub last_status: u16,
    pub last_check_ms: i64,
    pub checks: u64,
    pub failures: u64,
}

/// 分组视图：成员数 / 健康数 / 实际生效的策略，一次给全，面板不用自己算。
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendGroupView {
    pub name: String,
    pub note: String,
    pub strategy: LbStrategy,
    /// 是否在 `[[backend_groups]]` 里显式声明（false = 只在成员 group 字段里出现的隐式分组）
    pub declared: bool,
    pub members: usize,
    pub healthy: usize,
    pub weight: u32,
}

/// 一次选路的结果。
pub struct Pick {
    pub backend: BackendConfig,
    pub strategy: LbStrategy,
    /// 组内没有健康成员，本次是降级选择
    pub degraded: bool,
}

/// 后端运行时状态 + 每目标的轮询游标。
pub struct BackendRegistry {
    states: Mutex<HashMap<String, Arc<BackendState>>>,
    /// key 形如 `s:app-1` / `g:app`：分组之间互不干扰，权重不同也不会互相带偏
    cursors: Mutex<HashMap<String, u64>>,
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            cursors: Mutex::new(HashMap::new()),
        }
    }
}

impl BackendRegistry {
    fn state_of(&self, name: &str) -> Arc<BackendState> {
        let mut g = self.states.lock().unwrap_or_else(|e| e.into_inner());
        g.entry(name.to_string()).or_default().clone()
    }

    fn is_healthy(&self, name: &str) -> bool {
        self.state_of(name).healthy.load(Ordering::Relaxed)
    }

    fn next_ticket(&self, key: &str) -> u64 {
        let mut g = self.cursors.lock().unwrap_or_else(|e| e.into_inner());
        let slot = g.entry(key.to_string()).or_insert(0);
        let v = *slot;
        *slot = slot.wrapping_add(1);
        v
    }

    /// 按目标（单后端 / 分组）+ 策略挑一个后端。
    pub fn pick(
        &self,
        cfg: &Config,
        target: TargetSpec<'_>,
        strategy: LbStrategy,
        client_ip: Option<IpAddr>,
    ) -> Option<Pick> {
        let members: Vec<&BackendConfig> = match target {
            TargetSpec::Single(name) => cfg
                .backends
                .iter()
                .filter(|b| b.enabled && b.name == name)
                .collect(),
            TargetSpec::Group(group) => cfg
                .backends
                .iter()
                .filter(|b| b.enabled && b.group == group)
                .collect(),
        };
        if members.is_empty() {
            return None;
        }

        let healthy: Vec<&BackendConfig> = members
            .iter()
            .copied()
            .filter(|b| self.is_healthy(&b.name))
            .collect();

        // 全不健康：组内降级。绝不跨组借成员，否则"分组"只是界面上的装饰。
        let degraded = healthy.is_empty();
        let pool = if degraded { members } else { healthy };
        if degraded {
            tracing::warn!(
                target = target.name(),
                group = target.is_group(),
                "组内没有健康成员，降级为组内按权重挑选"
            );
        }

        let key = format!("{}:{}", if target.is_group() { "g" } else { "s" }, target.name());
        let total_weight: u64 = pool.iter().map(|b| b.weight.max(1) as u64).sum();

        let chosen = match strategy {
            LbStrategy::Rr => {
                let idx = (self.next_ticket(&key) % pool.len() as u64) as usize;
                pool[idx]
            }
            LbStrategy::Wrr => {
                let ticket = self.next_ticket(&key) % total_weight;
                walk_weighted(&pool, ticket)
            }
            LbStrategy::IpHash => {
                // 权重仍然生效：哈希落在权重区间里，同一 IP 稳定落到同一台
                let ticket = hash_ip(client_ip) % total_weight;
                walk_weighted(&pool, ticket)
            }
            LbStrategy::Random => {
                let ticket = rand::random::<u64>() % total_weight;
                walk_weighted(&pool, ticket)
            }
        };

        Some(Pick {
            backend: chosen.clone(),
            strategy,
            degraded,
        })
    }

    pub fn snapshot(&self, cfg: &Config) -> Vec<BackendView> {
        cfg.backends
            .iter()
            .map(|b| {
                let st = self.state_of(&b.name);
                BackendView {
                    name: b.name.clone(),
                    url: b.url.clone(),
                    group: b.group.clone(),
                    note: b.note.clone(),
                    weight: b.weight,
                    enabled: b.enabled,
                    health_path: b.health_path.clone(),
                    healthy: st.healthy.load(Ordering::Relaxed),
                    last_status: st.last_status.load(Ordering::Relaxed),
                    last_check_ms: st.last_check_ms.load(Ordering::Relaxed),
                    checks: st.checks.load(Ordering::Relaxed),
                    failures: st.failures.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// 分组视图：显式声明的分组 + 成员里出现的隐式分组，合并去重。
    pub fn groups(&self, cfg: &Config) -> Vec<BackendGroupView> {
        let mut names: Vec<String> = cfg.backend_groups.iter().map(|g| g.name.clone()).collect();
        for b in &cfg.backends {
            if !b.group.is_empty() && !names.iter().any(|n| n == &b.group) {
                names.push(b.group.clone());
            }
        }

        names
            .into_iter()
            .map(|name| {
                let declared: Option<&BackendGroupConfig> =
                    cfg.backend_groups.iter().find(|g| g.name == name);
                let members: Vec<&BackendConfig> = cfg
                    .backends
                    .iter()
                    .filter(|b| b.group == name && b.enabled)
                    .collect();
                BackendGroupView {
                    note: declared.map(|g| g.note.clone()).unwrap_or_default(),
                    strategy: cfg.resolve_lb(None, Some(name.as_str())),
                    declared: declared.is_some(),
                    members: members.len(),
                    healthy: members.iter().filter(|b| self.is_healthy(&b.name)).count(),
                    weight: members.iter().map(|b| b.weight.max(1)).sum(),
                    name,
                }
            })
            .collect()
    }
}

/// 在权重区间里走一步。调用方保证 ticket < 总权重。
fn walk_weighted<'a>(pool: &[&'a BackendConfig], ticket: u64) -> &'a BackendConfig {
    let mut acc = 0u64;
    for b in pool {
        acc += b.weight.max(1) as u64;
        if ticket < acc {
            return b;
        }
    }
    pool[pool.len() - 1]
}

/// IP 哈希：只需要进程内稳定，不追求跨进程一致（跨进程粘性请用 cookie/header）。
fn hash_ip(ip: Option<IpAddr>) -> u64 {
    let mut h = DefaultHasher::new();
    match ip {
        Some(ip) => ip.hash(&mut h),
        None => "unknown".hash(&mut h),
    }
    h.finish()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 后台探活：每个后端按自己的间隔跑，串行执行，简单可预测。
pub fn spawn_health_checks<F>(registry: Arc<BackendRegistry>, snapshot: F)
where
    F: Fn() -> Option<Config> + Send + Sync + 'static,
{
    let cfg = Arc::new(snapshot);
    tokio::spawn(async move {
        let mut last: HashMap<String, Instant> = HashMap::new();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            // 拿不到配置（正在热重载）就跳过这一轮，绝不能拿空配置去判断后端存不存在
            let Some(current) = cfg() else { continue };
            for b in &current.backends {
                if !b.enabled || b.health_interval_secs == 0 {
                    continue;
                }
                let due = last
                    .get(&b.name)
                    .map(|t| t.elapsed() >= Duration::from_secs(b.health_interval_secs))
                    .unwrap_or(true);
                if !due {
                    continue;
                }
                last.insert(b.name.clone(), Instant::now());

                let st = registry.state_of(&b.name);
                let url = format!(
                    "{}{}",
                    b.url.trim_end_matches('/'),
                    if b.health_path.starts_with('/') {
                        b.health_path.clone()
                    } else {
                        format!("/{}", b.health_path)
                    }
                );
                let ok = probe(&url, Duration::from_millis(b.timeout_ms.max(500))).await;
                st.checks.fetch_add(1, Ordering::Relaxed);
                st.last_check_ms.store(now_ms(), Ordering::Relaxed);
                match ok {
                    Some(status) => {
                        let healthy = status < 500;
                        st.last_status.store(status, Ordering::Relaxed);
                        st.healthy.store(healthy, Ordering::Relaxed);
                        if healthy {
                            st.consecutive_failures.store(0, Ordering::Relaxed);
                        } else {
                            st.failures.fetch_add(1, Ordering::Relaxed);
                            st.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => {
                        st.failures.fetch_add(1, Ordering::Relaxed);
                        st.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                        st.healthy.store(false, Ordering::Relaxed);
                        st.last_status.store(0, Ordering::Relaxed);
                    }
                }
            }
        }
    });
}

/// 裸 TCP 发一个最小 HTTP/1.1 请求做探活，避免为一个探针再养一套 client。
async fn probe(url: &str, timeout: Duration) -> Option<u16> {
    let uri: http::Uri = url.parse().ok()?;
    if uri.scheme_str() != Some("http") {
        return None; // https 探活留给上游负载均衡器，这里不假装支持
    }
    let addr = uri.authority()?.as_str().to_string();
    let path = if uri.path().is_empty() { "/" } else { uri.path() };

    let connect = tokio::net::TcpStream::connect(&addr);
    let stream = tokio::time::timeout(timeout, connect).await.ok()?.ok()?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = stream;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: optical-health/1\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(timeout, s.write_all(req.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(timeout, s.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let mut parts = head.split_whitespace();
    parts.next()?; // HTTP/1.1
    parts.next()?.parse::<u16>().ok()
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::config::{BackendConfig, BackendGroupConfig, RouteConfig};

    fn b(name: &str, weight: u32) -> BackendConfig {
        BackendConfig {
            name: name.into(),
            url: format!("http://127.0.0.1:{}", 9000 + weight),
            weight,
            ..Default::default()
        }
    }

    fn group_member(name: &str, group: &str, weight: u32) -> BackendConfig {
        BackendConfig {
            group: group.into(),
            ..b(name, weight)
        }
    }

    #[test]
    fn picks_single_backend() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backends = vec![b("a", 1)];
        let p = r
            .pick(&cfg, TargetSpec::Single("a"), LbStrategy::Wrr, None)
            .unwrap();
        assert_eq!(p.backend.name, "a");
    }

    #[test]
    fn unknown_backend_returns_none() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backends = vec![b("a", 1)];
        assert!(r
            .pick(&cfg, TargetSpec::Single("zzz"), LbStrategy::Wrr, None)
            .is_none());
    }

    #[test]
    fn single_target_never_leaks_to_other_groups() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backends = vec![b("solo", 1), group_member("api-1", "api", 1)];
        r.state_of("api-1").healthy.store(true, Ordering::Relaxed);
        for _ in 0..20 {
            let p = r
                .pick(&cfg, TargetSpec::Single("solo"), LbStrategy::Wrr, None)
                .unwrap();
            assert_eq!(p.backend.name, "solo", "单后端目标绝不能落到别的后端");
        }
    }

    #[test]
    fn group_only_picks_its_members() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backends = vec![
            group_member("api-1", "api", 1),
            group_member("api-2", "api", 1),
            group_member("web-1", "web", 1),
        ];
        for n in ["api-1", "api-2", "web-1"] {
            r.state_of(n).healthy.store(true, Ordering::Relaxed);
        }
        let mut seen = std::collections::HashSet::new();
        for _ in 0..30 {
            let p = r
                .pick(&cfg, TargetSpec::Group("api"), LbStrategy::Wrr, None)
                .unwrap();
            assert!(p.backend.name.starts_with("api-"));
            seen.insert(p.backend.name);
        }
        assert_eq!(seen.len(), 2, "组内两台都应被轮询到: {seen:?}");
    }

    #[test]
    fn group_falls_back_inside_group_when_all_down() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backends = vec![
            group_member("api-1", "api", 1),
            group_member("api-2", "api", 1),
            group_member("web-1", "web", 1),
        ];
        // 全部不健康
        let p = r
            .pick(&cfg, TargetSpec::Group("api"), LbStrategy::Wrr, None)
            .unwrap();
        assert!(p.backend.name.starts_with("api-"));
        assert!(p.degraded, "全不健康时应标记 degraded");
    }

    #[test]
    fn iphash_is_sticky_within_group() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backends = vec![
            group_member("api-1", "api", 1),
            group_member("api-2", "api", 1),
        ];
        r.state_of("api-1").healthy.store(true, Ordering::Relaxed);
        r.state_of("api-2").healthy.store(true, Ordering::Relaxed);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let first = r
            .pick(&cfg, TargetSpec::Group("api"), LbStrategy::IpHash, Some(ip))
            .unwrap()
            .backend
            .name;
        for _ in 0..10 {
            let again = r
                .pick(&cfg, TargetSpec::Group("api"), LbStrategy::IpHash, Some(ip))
                .unwrap()
                .backend
                .name;
            assert_eq!(first, again);
        }
    }

    #[test]
    fn group_view_merges_declared_and_implicit() {
        let r = BackendRegistry::default();
        let mut cfg = Config::default();
        cfg.backend_groups = vec![BackendGroupConfig {
            name: "api".into(),
            note: "主 API".into(),
            strategy: Some(LbStrategy::Rr),
        }];
        cfg.backends = vec![
            group_member("api-1", "api", 2),
            group_member("api-2", "api", 1),
            group_member("web-1", "web", 1),
        ];
        r.state_of("api-1").healthy.store(true, Ordering::Relaxed);
        let g = r.groups(&cfg);
        assert_eq!(g.len(), 2);
        let api = g.iter().find(|x| x.name == "api").unwrap();
        assert_eq!(api.members, 2);
        assert_eq!(api.healthy, 1);
        assert_eq!(api.strategy, LbStrategy::Rr);
        assert_eq!(api.note, "主 API");
        assert!(api.declared);
        let web = g.iter().find(|x| x.name == "web").unwrap();
        assert!(!web.declared);
        assert_eq!(web.strategy, cfg.server.lb);
    }

    #[test]
    fn route_lb_beats_group_strategy() {
        let mut cfg = Config::default();
        cfg.backend_groups = vec![BackendGroupConfig {
            name: "api".into(),
            strategy: Some(LbStrategy::Rr),
            ..Default::default()
        }];
        let mut route = RouteConfig::new("r", "*", "/", "");
        route.backend_group = "api".into();
        route.lb = Some(LbStrategy::Random);
        assert_eq!(cfg.resolve_lb(Some(&route), Some("api")), LbStrategy::Random);
        route.lb = None;
        assert_eq!(cfg.resolve_lb(Some(&route), Some("api")), LbStrategy::Rr);
        assert_eq!(cfg.resolve_lb(None, None), cfg.server.lb);
    }
}
