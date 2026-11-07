//! 进程级共享状态：配置 + 指标 + 缓存 + 后端池 + 认证 + 存储。
//!
//! 网关面与管理面都持有同一个 `Arc<AppState>`，因此 WebUI 改完配置，
//! 正在处理中的连接和新连接都会立刻看到新值，无需重启。
//!
//! 覆盖语义（行为契约，别改）：
//! 1. 启动参数只影响本次进程的生效值，永不写回文件；
//! 2. 文件被外部改动后重新加载，覆盖继续生效；
//! 3. 管理面显式提交等于"用户此刻的明确意图"，解除行为类覆盖；
//!    监听地址已 bind，只能重启换端口。

use crate::auth::AuthState;
use crate::backends::BackendRegistry;
use crate::cache::{CacheStats, ResponseCache};
use crate::config::{Config, Overrides, ResolvedPaths, MAX_SAMPLE_MS, MIN_SAMPLE_MS};
use crate::storage::{AuditEntry, AuditLog, ConfigHistory, SnapshotMeta};
use crate::waf::BolaTracker;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// 计数器上限，防止被扫描器刷爆内存
const MAX_TRACKED_KEYS: usize = 2048;

#[derive(Debug, Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub errors: AtomicU64,
    pub upstream_ms: AtomicU64,
    pub reloads: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub cache_hit: AtomicU64,
    pub cache_miss: AtomicU64,
    pub waf_hits: AtomicU64,
    pub waf_blocks: AtomicU64,
    pub waf_skipped: AtomicU64,
    pub ws_upgrades: AtomicU64,
    /// 当前管理面 WebSocket 连接数（0 = 前端已回退到轮询）
    pub ws_clients: AtomicU64,
    pub tls_handshakes: AtomicU64,
    /// UA 计数
    pub ua: Mutex<HashMap<String, u64>>,
    /// 客户端 IP 计数
    pub ip: Mutex<HashMap<String, u64>>,
    /// 规则命中计数
    pub rules: Mutex<HashMap<String, u64>>,
    /// 状态码分布
    pub status: Mutex<HashMap<u16, u64>>,
}

fn bump(map: &Mutex<HashMap<String, u64>>, key: &str) {
    if key.is_empty() {
        return;
    }
    let mut g = map.lock().unwrap_or_else(|e| e.into_inner());
    if g.len() >= MAX_TRACKED_KEYS && !g.contains_key(key) {
        return;
    }
    *g.entry(key.to_string()).or_insert(0) += 1;
}

pub fn top_of(map: &Mutex<HashMap<String, u64>>, n: usize) -> Vec<(String, u64)> {
    let g = map.lock().unwrap_or_else(|e| e.into_inner());
    let mut v: Vec<(String, u64)> = g.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MetricsSnapshot {
    pub requests: u64,
    pub errors: u64,
    pub avg_upstream_ms: u64,
    pub reloads: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub cache_hit: u64,
    pub cache_miss: u64,
    pub cache_hit_rate: f64,
    pub cache: CacheStats,
    pub waf_hits: u64,
    pub waf_blocks: u64,
    pub waf_skipped: u64,
    pub waf_hit_rate: f64,
    pub ws_upgrades: u64,
    pub tls_handshakes: u64,
    pub status: Vec<(u16, u64)>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Sample {
    pub requests: u32,
    pub errors: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub cache_hit: u32,
    pub cache_miss: u32,
    pub waf_blocks: u32,
    pub upstream_ms: u64,
}

impl Sample {
    /// 合并两个桶：这些都是"桶内增量"，相加即可。
    /// upstream_ms 是累计耗时，合并后除以 requests 仍是正确的平均延迟。
    pub fn merge(&mut self, o: &Sample) {
        self.requests = self.requests.saturating_add(o.requests);
        self.errors = self.errors.saturating_add(o.errors);
        self.bytes_in = self.bytes_in.saturating_add(o.bytes_in);
        self.bytes_out = self.bytes_out.saturating_add(o.bytes_out);
        self.cache_hit = self.cache_hit.saturating_add(o.cache_hit);
        self.cache_miss = self.cache_miss.saturating_add(o.cache_miss);
        self.waf_blocks = self.waf_blocks.saturating_add(o.waf_blocks);
        self.upstream_ms = self.upstream_ms.saturating_add(o.upstream_ms);
    }
}

/// 每个 IP 的连接记账（连接池限流用）。
struct ConnStat {
    active: u32,
    window_start: Instant,
    window_count: u32,
}

pub struct AppState {
    config: RwLock<Config>,
    pub config_path: PathBuf,
    /// 配置版本号：每次成功写盘/重载自增，用于管理面乐观锁，防止旧页面覆盖新配置
    config_rev: AtomicU64,
    /// 启动时解析出的落盘路径；配置文件里改了目录，下次启动生效（错误页除外，按请求重算）
    pub paths: ResolvedPaths,
    overrides: RwLock<Overrides>,
    pub started_at: Instant,
    pub metrics: Metrics,
    history: Mutex<crate::history::History>,
    last_sample: Mutex<LastSample>,
    pub cache: ResponseCache,
    pub backends: Arc<BackendRegistry>,
    pub auth: AuthState,
    pub conf_history: ConfigHistory,
    pub audit: AuditLog,
    pub bola: BolaTracker,
    conns: Mutex<HashMap<IpAddr, ConnStat>>,
}

#[derive(Default)]
struct LastSample {
    requests: u64,
    errors: u64,
    bytes_in: u64,
    bytes_out: u64,
    cache_hit: u64,
    cache_miss: u64,
    waf_blocks: u64,
    upstream_ms: u64,
}

/// 单 IP 连接的 RAII 守卫：连接关闭即归还名额。
pub struct ConnGuard {
    state: Arc<AppState>,
    ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut g = self.state.conns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = g.get_mut(&self.ip) {
            s.active = s.active.saturating_sub(1);
            if s.active == 0 {
                g.remove(&self.ip);
            }
        }
    }
}

impl AppState {
    pub fn new(config: Config, config_path: PathBuf, overrides: Overrides) -> Self {
        // 所有落盘位置统一由 resolve_paths 算，绝不在各处拼 "conf-history" / ".audit.jsonl"
        let paths = config.resolve_paths(&config_path);
        let (sample_ms, history_points) = (
            config.metrics.sample_interval_ms,
            config.metrics.history_points,
        );
        Self {
            conf_history: ConfigHistory::with_dir(paths.config_history.clone()),
            audit: AuditLog::with_file(paths.audit_file.clone()),
            config: RwLock::new(config),
            config_rev: AtomicU64::new(1),
            config_path,
            paths,
            overrides: RwLock::new(overrides),
            started_at: Instant::now(),
            metrics: Metrics::default(),
            history: Mutex::new(crate::history::History::new(sample_ms, history_points)),
            last_sample: Mutex::new(LastSample::default()),
            cache: ResponseCache::default(),
            backends: Arc::new(BackendRegistry::default()),
            auth: AuthState::new(),
            bola: BolaTracker::default(),
            conns: Mutex::new(HashMap::new()),
        }
    }

    /// 配置校验的基准目录：证书这类相对路径以配置文件所在目录为准。
    pub fn base_dir(&self) -> &Path {
        self.config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    /// 错误页目录按**当前配置**重算，这样 WebUI 改完 error_pages.dir 立刻生效。
    pub fn error_pages_dir(&self, cfg: &Config) -> std::path::PathBuf {
        cfg.resolve_paths(&self.config_path).error_pages_dir
    }

    pub fn config_rev(&self) -> u64 {
        self.config_rev.load(Ordering::Relaxed)
    }

    pub async fn snapshot(&self) -> Config {
        self.config.read().await.clone()
    }

    /// 非阻塞取配置：accept 热路径用，拿不到锁就用默认值。
    pub fn try_config(&self) -> Option<Config> {
        self.config.try_read().ok().map(|g| g.clone())
    }

    pub async fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub async fn override_keys(&self) -> Vec<&'static str> {
        self.overrides.read().await.keys()
    }

    /// 管理面显式提交：校验 → 落盘（含快照）→ 解除行为类覆盖 → 换内存。
    pub async fn apply(&self, cfg: Config) -> anyhow::Result<()> {
        cfg.validate_ok_in(self.base_dir())?;
        let text = cfg.to_toml();
        let storage = self.config.read().await.storage.clone();
        self.conf_history.record(&text, "apply", &storage)?;
        cfg.save(&self.config_path)?;

        self.overrides.write().await.clear_behavior();

        let mut effective = cfg;
        self.overrides.read().await.apply(&mut effective);
        effective.validate_ok_in(self.base_dir())?;
        *self.config.write().await = effective;
        self.metrics.reloads.fetch_add(1, Ordering::Relaxed);
        self.audit.push(
            &storage,
            AuditEntry {
                ts_ms: crate::storage::now_ms(),
                kind: "config.apply".into(),
                detail: "配置已通过管理面提交".into(),
                identity: "admin".into(),
                path: String::new(),
                rule: String::new(),
            },
        );
        Ok(())
    }

    /// 从磁盘重新加载（CLI 改完文件 / 手工编辑后触发）。
    pub async fn reload_from_disk(&self) -> anyhow::Result<()> {
        let mut cfg = Config::load(&self.config_path)?;
        cfg.validate_ok_in(self.base_dir())?;
        self.overrides.read().await.apply(&mut cfg);
        *self.config.write().await = cfg;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
        self.metrics.reloads.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// 回溯到某个快照：写回文件并立即生效（同时会再产生一条快照，保留操作痕迹）。
    pub async fn restore_snapshot(&self, id: &str) -> anyhow::Result<()> {
        let raw = self.conf_history.read(id)?;
        let body: String = raw
            .lines()
            .filter(|l| !l.starts_with("# optical snapshot"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut cfg: Config = toml::from_str(&body)?;
        cfg.validate_ok_in(self.base_dir())?;
        let storage = self.config.read().await.storage.clone();
        self.conf_history
            .record(&cfg.to_toml(), &format!("restore-{}", id[..13.min(id.len())].replace('-', "")), &storage)?;
        cfg.save(&self.config_path)?;
        self.overrides.read().await.apply(&mut cfg);
        *self.config.write().await = cfg;
        self.config_rev.fetch_add(1, Ordering::Relaxed);
        self.metrics.reloads.fetch_add(1, Ordering::Relaxed);
        self.audit.push(
            &storage,
            AuditEntry {
                ts_ms: crate::storage::now_ms(),
                kind: "config.restore".into(),
                detail: format!("回溯到快照 {id}"),
                identity: "admin".into(),
                path: String::new(),
                rule: String::new(),
            },
        );
        Ok(())
    }

    pub fn snapshots(&self) -> Vec<SnapshotMeta> {
        self.conf_history.list_meta()
    }

    // ---------- 指标 ----------

    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        let requests = self.metrics.requests.load(Ordering::Relaxed);
        let errors = self.metrics.errors.load(Ordering::Relaxed);
        let total_ms = self.metrics.upstream_ms.load(Ordering::Relaxed);
        let hit = self.metrics.cache_hit.load(Ordering::Relaxed);
        let miss = self.metrics.cache_miss.load(Ordering::Relaxed);
        let waf_hits = self.metrics.waf_hits.load(Ordering::Relaxed);
        let status = {
            let g = self.metrics.status.lock().unwrap_or_else(|e| e.into_inner());
            let mut v: Vec<(u16, u64)> = g.iter().map(|(k, c)| (*k, *c)).collect();
            v.sort_by_key(|(k, _)| *k);
            v
        };
        MetricsSnapshot {
            requests,
            errors,
            avg_upstream_ms: total_ms.checked_div(requests).unwrap_or(0),
            reloads: self.metrics.reloads.load(Ordering::Relaxed),
            bytes_in: self.metrics.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.metrics.bytes_out.load(Ordering::Relaxed),
            cache_hit: hit,
            cache_miss: miss,
            cache_hit_rate: if hit + miss == 0 {
                0.0
            } else {
                hit as f64 / (hit + miss) as f64 * 100.0
            },
            cache: self.cache.stats(),
            waf_hits,
            waf_blocks: self.metrics.waf_blocks.load(Ordering::Relaxed),
            waf_skipped: self.metrics.waf_skipped.load(Ordering::Relaxed),
            waf_hit_rate: if requests == 0 {
                0.0
            } else {
                waf_hits as f64 / requests as f64 * 100.0
            },
            ws_upgrades: self.metrics.ws_upgrades.load(Ordering::Relaxed),
            tls_handshakes: self.metrics.tls_handshakes.load(Ordering::Relaxed),
            status,
        }
    }

    pub fn top_ua(&self, n: usize) -> Vec<(String, u64)> {
        top_of(&self.metrics.ua, n)
    }
    pub fn top_ip(&self, n: usize) -> Vec<(String, u64)> {
        top_of(&self.metrics.ip, n)
    }
    pub fn top_rules(&self, n: usize) -> Vec<(String, u64)> {
        top_of(&self.metrics.rules, n)
    }

    pub fn record_upstream(&self, elapsed: Duration) {
        self.metrics
            .upstream_ms
            .fetch_add(elapsed.as_millis() as u64, Ordering::Relaxed);
    }

    /// 单请求的画像记录（UA / IP / 状态码）。
    pub fn record_profile(&self, ua: &str, ip: &str, status: u16) {
        bump(&self.metrics.ua, ua);
        bump(&self.metrics.ip, ip);
        let mut g = self.metrics.status.lock().unwrap_or_else(|e| e.into_inner());
        *g.entry(status).or_insert(0) += 1;
    }

    /// 单条规则计数（体积闸门、帧策略这类不走 Finding 的路径用它）。
    pub fn record_rule_hit(&self, rule: &str) {
        if rule.is_empty() {
            return;
        }
        let mut g = self.metrics.rules.lock().unwrap_or_else(|e| e.into_inner());
        *g.entry(rule.to_string()).or_insert(0) += 1;
    }

    /// 记录 WAF 命中：既按具体规则（sql-union-select）计数，也按族（family:sql）汇总，
    /// WebUI 的「规则命中率」和分族占比都吃这份数据。
    pub fn record_findings(&self, findings: &[crate::waf::Finding]) {
        if findings.is_empty() {
            return;
        }
        let mut g = self.metrics.rules.lock().unwrap_or_else(|e| e.into_inner());
        for f in findings {
            *g.entry(f.rule.to_string()).or_insert(0) += 1;
            *g.entry(format!("family:{}", f.family)).or_insert(0) += 1;
        }
    }

    /// 每秒采样：从累计计数算差值，推进环形缓冲。
    pub fn sample_once(&self) -> Sample {
        let cur = (
            self.metrics.requests.load(Ordering::Relaxed),
            self.metrics.errors.load(Ordering::Relaxed),
            self.metrics.bytes_in.load(Ordering::Relaxed),
            self.metrics.bytes_out.load(Ordering::Relaxed),
            self.metrics.cache_hit.load(Ordering::Relaxed),
            self.metrics.cache_miss.load(Ordering::Relaxed),
            self.metrics.waf_blocks.load(Ordering::Relaxed),
            self.metrics.upstream_ms.load(Ordering::Relaxed),
        );
        let mut last = self.last_sample.lock().unwrap_or_else(|e| e.into_inner());
        let sample = Sample {
            requests: cur.0.saturating_sub(last.requests).min(u32::MAX as u64) as u32,
            errors: cur.1.saturating_sub(last.errors).min(u32::MAX as u64) as u32,
            bytes_in: cur.2.saturating_sub(last.bytes_in),
            bytes_out: cur.3.saturating_sub(last.bytes_out),
            cache_hit: cur.4.saturating_sub(last.cache_hit).min(u32::MAX as u64) as u32,
            cache_miss: cur.5.saturating_sub(last.cache_miss).min(u32::MAX as u64) as u32,
            waf_blocks: cur.6.saturating_sub(last.waf_blocks).min(u32::MAX as u64) as u32,
            upstream_ms: cur.7.saturating_sub(last.upstream_ms),
        };
        *last = LastSample {
            requests: cur.0,
            errors: cur.1,
            bytes_in: cur.2,
            bytes_out: cur.3,
            cache_hit: cur.4,
            cache_miss: cur.5,
            waf_blocks: cur.6,
            upstream_ms: cur.7,
        };
        drop(last);

        let mut h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        h.record(now_ms(), sample.clone());
        sample
    }

    /// 采样设置：采集间隔 + 点数上限。读不到配置时用默认值，绝不 panic。
    pub fn sampling(&self) -> (u64, usize) {
        match self.try_config() {
            Some(c) => (
                c.metrics.sample_interval_ms.clamp(MIN_SAMPLE_MS, MAX_SAMPLE_MS),
                c.metrics.history_points.clamp(32, 20_000),
            ),
            None => {
                let d = crate::config::MetricsConfig::default();
                (d.sample_interval_ms, d.history_points)
            }
        }
    }

    /// 把当前配置套到历史序列上（间隔变了清空、点数变少了裁剪）。
    /// 采样循环和查询前都调一次，配置热重载后立刻生效。
    pub fn sync_history(&self) {
        let (interval, cap) = self.sampling();
        self.history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reconfigure(interval, cap);
    }

    /// 按请求的粒度/范围取历史。粒度只是查询参数，不碰配置。
    pub fn history_query(&self, gran_ms: u64, range_secs: u64) -> crate::history::Bucketed {
        self.sync_history();
        let h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        h.query(gran_ms, range_secs, now_ms())
    }

    /// 历史序列当前的分辨率与规模，供状态接口展示"已经降采样到多粗"。
    pub fn history_meta(&self) -> (u64, usize) {
        let h = self.history.lock().unwrap_or_else(|e| e.into_inner());
        (h.bucket_ms(), h.len())
    }

    // ---------- 连接池 ----------

    /// 单 IP 并发/新建速率双闸门。超限返回 None，调用方直接断连。
    pub fn try_acquire_conn(
        self: &Arc<Self>,
        ip: IpAddr,
        max_active: usize,
        max_per_sec: u32,
    ) -> Option<ConnGuard> {
        let mut g = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() > 8192 {
            let now = Instant::now();
            g.retain(|_, s| s.active > 0 || now.duration_since(s.window_start) < Duration::from_secs(2));
        }
        let stat = g.entry(ip).or_insert(ConnStat {
            active: 0,
            window_start: Instant::now(),
            window_count: 0,
        });
        if stat.window_start.elapsed() >= Duration::from_secs(1) {
            stat.window_start = Instant::now();
            stat.window_count = 0;
        }
        if max_active > 0 && stat.active as usize >= max_active {
            return None;
        }
        if max_per_sec > 0 && stat.window_count >= max_per_sec {
            return None;
        }
        stat.active += 1;
        stat.window_count += 1;
        Some(ConnGuard {
            state: self.clone(),
            ip,
        })
    }

    pub fn active_conns(&self) -> usize {
        let g = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        g.values().map(|s| s.active as usize).sum()
    }

    pub fn active_ips(&self) -> usize {
        self.conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

/// Unix 毫秒时间戳：采样点的时间轴用它，换档位/重启都不影响已存点的真实时间。
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 按配置的采集间隔采样，供 WebUI 画折线图。
///
/// 不能直接 `sleep(interval)` 了事：配置随时可能被热重载改掉（比如把 15 秒调成 60 秒），
/// 死等一个旧周期会让"改完没反应"变成一次真实的 bug 报告。这里按 ≤1 秒醒来检查，
/// 间隔一变立刻重算并补点。
pub fn spawn_sampler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut due = std::time::Instant::now();
        let mut active: u64 = 0;
        loop {
            state.sync_history();
            let (interval_ms, _) = state.sampling();
            if interval_ms != active {
                // 采集间隔变了：旧点的时间宽度不一样，sync_history 已经清空。
                // 立刻补一个点，否则图会空一整个周期——最粗的档位要空 10 分钟。
                active = interval_ms;
                state.sample_once();
                due = std::time::Instant::now() + Duration::from_millis(active);
                continue;
            }
            tokio::time::sleep(Duration::from_millis(interval_ms.min(1000))).await;
            if std::time::Instant::now() >= due {
                state.sample_once();
                due = std::time::Instant::now() + Duration::from_millis(active);
            }
        }
    });
}

/// mtime 轮询热重载。
pub fn spawn_watcher(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut last = mtime(&state.config_path);
        loop {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let cur = mtime(&state.config_path);
            if cur.is_none() || cur == last {
                continue;
            }
            last = cur;
            match Config::load(&state.config_path) {
                Ok(cfg) => match cfg.validate_ok_in(state.base_dir()) {
                    Ok(()) => {
                        let mut cfg = cfg;
                        state.overrides.read().await.apply(&mut cfg);
                        let routes = cfg.routes.len();
                        let listen = cfg.server.listen.clone();
                        *state.config.write().await = cfg;
                        state.config_rev.fetch_add(1, Ordering::Relaxed);
                        state.metrics.reloads.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(routes, listen = %listen, "配置已热重载");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "配置文件校验失败，保持旧配置继续运行")
                    }
                },
                Err(e) => tracing::warn!(error = %e, "配置文件解析失败，保持旧配置继续运行"),
            }
        }
    });
}

fn mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn state() -> Arc<AppState> {
        Arc::new(AppState::new(
            Config::default(),
            PathBuf::from("/tmp/optical-test.toml"),
            Overrides::default(),
        ))
    }

    #[test]
    fn conn_limit_per_ip() {
        let s = state();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let a = s.try_acquire_conn(ip, 2, 100).unwrap();
        let b = s.try_acquire_conn(ip, 2, 100).unwrap();
        assert!(s.try_acquire_conn(ip, 2, 100).is_none());
        drop(a);
        drop(b);
        assert!(s.try_acquire_conn(ip, 2, 100).is_some());
    }

    #[test]
    fn burst_limit_per_second() {
        let s = state();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        let mut guards = Vec::new();
        for _ in 0..3 {
            guards.push(s.try_acquire_conn(ip, 100, 3).unwrap());
        }
        assert!(s.try_acquire_conn(ip, 100, 3).is_none());
    }

    #[test]
    fn sampling_produces_deltas() {
        let s = state();
        s.metrics.requests.store(10, Ordering::Relaxed);
        s.metrics.bytes_out.store(2048, Ordering::Relaxed);
        let a = s.sample_once();
        assert_eq!(a.requests, 10);
        assert_eq!(a.bytes_out, 2048);
        s.metrics.requests.store(15, Ordering::Relaxed);
        let b = s.sample_once();
        assert_eq!(b.requests, 5);
        assert_eq!(b.bytes_out, 0);
    }

    #[test]
    fn top_n_sorted_desc() {
        let s = state();
        for _ in 0..3 {
            s.record_profile("curl/8", "1.1.1.1", 200);
        }
        s.record_profile("Mozilla/5.0", "2.2.2.2", 200);
        let top = s.top_ua(2);
        assert_eq!(top[0].0, "curl/8");
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn rule_hits_counted() {
        let s = state();
        let f = crate::waf::Finding {
            family: "sql",
            rule: "sql-union-select",
            severity: 4,
            detail: String::new(),
        };
        s.record_findings(&[f.clone(), f]);
        let top = s.top_rules(5);
        assert!(top.iter().any(|(k, c)| k == "sql-union-select" && *c == 2));
        assert!(top.iter().any(|(k, c)| k == "family:sql" && *c == 2));
    }
}
