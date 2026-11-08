//! IP 黑白名单：在网络入口最早处决定"这个请求要不要继续"。
//!
//! 三个刻意的设计：
//!
//! 1. **只作用于数据面**。管理面（REST + WebUI）不经过这里——否则一条
//!    `0.0.0.0/0 deny` 就能把你自己锁在控制台外面，只能上服务器改文件。
//! 2. **先命中先算**。`allow` 条目可以写在 `deny` 网段前面做例外，顺序有意义。
//!    本地条目永远排在远程条目之前——自己写的规则不该被一个远程列表盖掉。
//! 3. **远程列表拉不到就用上一次的**。订阅源挂了不代表内网就该全放开；
//!    缓存会落盘，重启后先按旧名单干活，拉到了再换。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpAction {
    Allow,
    Deny,
}

impl Default for IpAction {
    fn default() -> Self {
        IpAction::Allow
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpEntry {
    pub action: IpAction,
    /// CIDR 或单个地址；单个地址等价于 /32、/128
    pub cidr: String,
    pub note: String,
    pub enabled: bool,
}

impl Default for IpEntry {
    fn default() -> Self {
        Self {
            action: IpAction::Deny,
            cidr: String::new(),
            note: String::new(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IpFilterConfig {
    pub enabled: bool,
    /// 名单没命中时怎么处理：allow = 黑名单模式，deny = 白名单模式
    pub default_action: IpAction,
    /// 被拒绝时返回的状态码
    pub status_code: u16,
    /// 远程名单地址，每行一个 CIDR（# 起头是注释）。支持 http / https。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remote: Vec<String>,
    /// 远程名单刷新间隔（秒），0 = 不自动刷新
    pub remote_refresh_secs: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<IpEntry>,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: IpAction::Allow,
            status_code: 403,
            remote: Vec::new(),
            remote_refresh_secs: 3600,
            entries: Vec::new(),
        }
    }
}

/// 一条编译好的规则
#[derive(Debug, Clone)]
struct Rule {
    net: IpAddr,
    prefix: u8,
    action: IpAction,
    /// 来源：`` 表示本地配置，否则是远程地址
    from: String,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: IpAction,
    /// 命中的规则（`None` = 名单没命中，走默认动作）
    pub rule: Option<String>,
    pub from: String,
}

/// 把 "1.2.3.0/24"、"1.2.3.4"、"::1"、"2001:db8::/32" 解析成 (地址, 前缀)
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (ip_part, prefix_part) = match s.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };
    let ip: IpAddr = ip_part.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_part {
        None => max,
        Some(p) => {
            let p = p.trim();
            if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let v: u16 = p.parse().ok()?;
            if v > max as u16 {
                return None;
            }
            v as u8
        }
    };
    Some((ip, prefix))
}

/// 地址是否落在网段里。v4 用 u32、v6 用 u128，掩码高位比对——
/// 不引 ipnet，这点位运算不值得为它多一个依赖。
pub fn within(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        // v4 与 v6 不互相匹配；映射地址（::ffff:1.2.3.4）按 v6 处理，
        // 想覆盖请显式写 ::ffff:0:0/96
        _ => false,
    }
}

/// 解析文本名单：每行一个 CIDR / IP，`#` 起头或行尾都当注释。
/// 返回（有效行, 无效行），无效行要如实报给管理面，不能默默吞掉。
pub fn parse_list(text: &str) -> (Vec<String>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for raw in text.lines() {
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 容忍 "1.2.3.0/24, 4.5.6.0/24" 这种单行多值，以及每行带个备注
        for piece in line.split(|c| c == ',' || c == ';' || c == '\t' || c == ' ') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            if parse_cidr(piece).is_some() {
                ok.push(piece.to_string());
            } else {
                bad.push(piece.to_string());
            }
        }
    }
    ok.dedup();
    (ok, bad)
}

fn compile_rules(cfg: &IpFilterConfig, remote: &RemoteList) -> Vec<Rule> {
    let mut out = Vec::new();
    for e in &cfg.entries {
        if !e.enabled {
            continue;
        }
        if let Some((net, prefix)) = parse_cidr(&e.cidr) {
            out.push(Rule {
                net,
                prefix,
                action: e.action,
                from: String::new(),
            });
        }
    }
    // 远程条目排在本地之后：自己写的规则优先，远程订阅只能补充
    for src in &remote.lists {
        for cidr in &src.cidrs {
            if let Some((net, prefix)) = parse_cidr(cidr) {
                out.push(Rule {
                    net,
                    prefix,
                    action: src.action,
                    from: src.url.clone(),
                });
            }
        }
    }
    out
}

/// 远程订阅的解析结果
#[derive(Debug, Clone, Default, Serialize)]
pub struct RemoteSource {
    pub url: String,
    pub action: IpAction,
    pub cidrs: Vec<String>,
    pub bad: Vec<String>,
    pub fetched_at: i64,
    pub error: String,
}

#[derive(Debug, Clone, Default)]
pub struct RemoteList {
    pub lists: Vec<RemoteSource>,
}

/// 远程名单的落盘缓存：订阅源挂了、或者刚重启还没拉到，先用上次的。
pub fn cache_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("ipfilter-remote.json")
}

pub fn save_cache(data_dir: &Path, list: &RemoteList) {
    if !data_dir.exists() {
        std::fs::create_dir_all(data_dir).ok();
    }
    let payload: Vec<serde_json::Value> = list
        .lists
        .iter()
        .map(|s| {
            serde_json::json!({
                "url": s.url, "action": s.action, "cidrs": s.cidrs,
                "fetched_at": s.fetched_at, "error": s.error,
            })
        })
        .collect();
    if let Ok(text) = serde_json::to_string_pretty(&payload) {
        std::fs::write(cache_path(data_dir), text).ok();
    }
}

pub fn load_cache(data_dir: &Path) -> RemoteList {
    let mut out = RemoteList::default();
    let Ok(text) = std::fs::read_to_string(cache_path(data_dir)) else {
        return out;
    };
    let Ok(v) = serde_json::from_str::<Vec<serde_json::Value>>(&text) else {
        return out;
    };
    for item in v {
        let url = item["url"].as_str().unwrap_or_default().to_string();
        if url.is_empty() {
            continue;
        }
        out.lists.push(RemoteSource {
            url,
            action: serde_json::from_value(item["action"].clone()).unwrap_or(IpAction::Deny),
            cidrs: item["cidrs"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default(),
            bad: Vec::new(),
            fetched_at: item["fetched_at"].as_i64().unwrap_or(0),
            error: item["error"].as_str().unwrap_or_default().to_string(),
        });
    }
    out
}

/// 运行时快照：编译结果跟着（config_rev, remote_gen）走，任一变化就重建。
/// 请求热路径上只做一次读锁 + 位比较，不解析字符串。
pub struct Runtime {
    cell: RwLock<Cell>,
}

#[derive(Clone)]
struct Cell {
    rev: u64,
    gen: u64,
    enabled: bool,
    status_code: u16,
    default_action: IpAction,
    rules: Arc<Vec<Rule>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            cell: RwLock::new(Cell {
                rev: u64::MAX,
                gen: u64::MAX,
                enabled: false,
                status_code: 403,
                default_action: IpAction::Allow,
                rules: Arc::new(Vec::new()),
            }),
        }
    }

    /// 判断一个地址该怎么处理。`rev` 是配置版本，`gen` 是远程列表版本。
    pub fn check(&self, cfg: &IpFilterConfig, rev: u64, remote: &RemoteList, gen: u64, ip: IpAddr) -> Decision {
        if !cfg.enabled {
            return Decision {
                action: IpAction::Allow,
                rule: None,
                from: String::new(),
            };
        }

        // 快路径：版本没变就直接用编译结果
        {
            let c = self.cell.read().unwrap_or_else(|e| e.into_inner());
            if c.rev == rev && c.gen == gen {
                return decide(&c, ip);
            }
        }

        let mut c = self.cell.write().unwrap_or_else(|e| e.into_inner());
        if c.rev != rev || c.gen != gen {
            c.rev = rev;
            c.gen = gen;
            c.enabled = cfg.enabled;
            c.status_code = if cfg.status_code == 0 { 403 } else { cfg.status_code };
            c.default_action = cfg.default_action;
            c.rules = Arc::new(compile_rules(cfg, remote));
        }
        decide(&c, ip)
    }

    pub fn status_code(&self) -> u16 {
        let c = self.cell.read().unwrap_or_else(|e| e.into_inner());
        if c.status_code == 0 {
            403
        } else {
            c.status_code
        }
    }

    /// 管理面诊断用：这条地址命中了哪条规则
    pub fn explain(&self, cfg: &IpFilterConfig, rev: u64, remote: &RemoteList, gen: u64, ip: IpAddr) -> Decision {
        let _ = self.check(cfg, rev, remote, gen, ip);
        let c = self.cell.read().unwrap_or_else(|e| e.into_inner());
        decide(&c, ip)
    }
}

fn decide(c: &Cell, ip: IpAddr) -> Decision {
    for r in c.rules.iter() {
        if within(r.net, r.prefix, ip) {
            return Decision {
                action: r.action,
                rule: Some(format!("{}/{}", r.net, r.prefix)),
                from: r.from.clone(),
            };
        }
    }
    Decision {
        action: c.default_action,
        rule: None,
        from: String::new(),
    }
}

/// 用 hyper 的 legacy client + rustls 拉一个文本名单。
/// 只做一件事：GET 回字符串，跟随最多 3 次跳转。
pub async fn fetch_text(url: &str) -> anyhow::Result<String> {
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::client::legacy::connect::HttpConnector;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Empty<bytes::Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let mut target = url.to_string();
    for _ in 0..4 {
        let uri: http::Uri = target
            .parse()
            .map_err(|e| anyhow::anyhow!("URL 不合法: {target} ({e})"))?;
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri.clone())
            .header("user-agent", "Optical/ipfilter")
            .body(Empty::new())
            .map_err(|e| anyhow::anyhow!("构造请求失败: {e}"))?;
        let resp = client
            .request(req)
            .await
            .map_err(|e| anyhow::anyhow!("拉取失败: {e}"))?;
        let status = resp.status();
        if status.is_redirection() {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                target = if loc.starts_with("http") {
                    loc.to_string()
                } else {
                    format!(
                        "{}://{}{}",
                        uri.scheme_str().unwrap_or("https"),
                        uri.authority().map(|a| a.as_str()).unwrap_or(""),
                        loc
                    )
                };
                continue;
            }
        }
        if !status.is_success() {
            anyhow::bail!("HTTP {status}");
        }
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("读取响应失败: {e}"))?
            .to_bytes();
        // 名单都是纯文本；不是 UTF-8 说明拉错了东西（比如登录页），直接报错
        return String::from_utf8(body.to_vec())
            .map_err(|_| anyhow::anyhow!("内容不是 UTF-8 文本，可能拉到了网页而不是名单"));
    }
    anyhow::bail!("跳转次数过多")
}

/// 拉取全部远程名单。单个源失败不影响其它源。
pub async fn refresh_remote(urls: &[String], action: IpAction) -> RemoteList {
    let mut out = RemoteList::default();
    for url in urls {
        let now = crate::storage::now_ms() / 1000;
        match fetch_text(url).await {
            Ok(text) => {
                let (cidrs, bad) = parse_list(&text);
                out.lists.push(RemoteSource {
                    url: url.clone(),
                    action,
                    cidrs,
                    bad,
                    fetched_at: now,
                    error: String::new(),
                });
            }
            Err(e) => out.lists.push(RemoteSource {
                url: url.clone(),
                action,
                cidrs: Vec::new(),
                bad: Vec::new(),
                fetched_at: 0,
                error: format!("{e:#}"),
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(entries: &[(&str, IpAction)], default: IpAction) -> IpFilterConfig {
        IpFilterConfig {
            enabled: true,
            default_action: default,
            status_code: 403,
            remote: Vec::new(),
            remote_refresh_secs: 0,
            entries: entries
                .iter()
                .map(|(c, a)| IpEntry {
                    action: *a,
                    cidr: (*c).to_string(),
                    note: String::new(),
                    enabled: true,
                })
                .collect(),
        }
    }

    #[test]
    fn parses_v4_and_v6() {
        assert_eq!(parse_cidr("10.0.0.0/8").unwrap().1, 8);
        assert_eq!(parse_cidr("10.1.2.3").unwrap().1, 32);
        assert_eq!(parse_cidr("2001:db8::/32").unwrap().1, 32);
        assert_eq!(parse_cidr("::1").unwrap().1, 128);
        assert!(parse_cidr("10.0.0.0/33").is_none(), "v4 前缀超过 32 必须拒绝");
        assert!(parse_cidr("2001:db8::/129").is_none());
        assert!(parse_cidr("not-an-ip").is_none());
    }

    #[test]
    fn v4_network_contains() {
        let (net, p) = parse_cidr("192.168.1.0/24").unwrap();
        assert!(within(net, p, "192.168.1.200".parse().unwrap()));
        assert!(!within(net, p, "192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn v6_network_contains() {
        let (net, p) = parse_cidr("2001:db8::/32").unwrap();
        assert!(within(net, p, "2001:db8:1::5".parse().unwrap()));
        assert!(!within(net, p, "2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn v4_and_v6_do_not_cross_match() {
        let (net, p) = parse_cidr("0.0.0.0/0").unwrap();
        assert!(!within(net, p, "::1".parse().unwrap()), "v4 全量不该命中 v6");
    }

    #[test]
    fn first_match_wins_so_allow_can_carve_out() {
        // 先放行一个特例，再封整个网段
        let c = cfg(
            &[("10.0.0.7/32", IpAction::Allow), ("10.0.0.0/8", IpAction::Deny)],
            IpAction::Allow,
        );
        let rt = Runtime::new();
        let remote = RemoteList::default();
        let ok = rt.check(&c, 1, &remote, 1, "10.0.0.7".parse().unwrap());
        assert_eq!(ok.action, IpAction::Allow);
        let no = rt.check(&c, 1, &remote, 1, "10.0.0.8".parse().unwrap());
        assert_eq!(no.action, IpAction::Deny);
    }

    #[test]
    fn whitelist_mode_denies_unknown() {
        let c = cfg(&[("192.168.0.0/16", IpAction::Allow)], IpAction::Deny);
        let rt = Runtime::new();
        let remote = RemoteList::default();
        assert_eq!(rt.check(&c, 1, &remote, 1, "192.168.5.5".parse().unwrap()).action, IpAction::Allow);
        assert_eq!(rt.check(&c, 1, &remote, 1, "8.8.8.8".parse().unwrap()).action, IpAction::Deny);
    }

    #[test]
    fn remote_entries_come_after_local() {
        let c = cfg(&[("10.0.0.7/32", IpAction::Allow)], IpAction::Allow);
        let mut remote = RemoteList::default();
        remote.lists.push(RemoteSource {
            url: "https://example.com/list.txt".into(),
            action: IpAction::Deny,
            cidrs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        });
        let rt = Runtime::new();
        let d = rt.check(&c, 7, &remote, 1, "10.0.0.7".parse().unwrap());
        assert_eq!(d.action, IpAction::Allow, "本地 allow 要压住远程 deny");
    }

    #[test]
    fn disabled_filter_allows_everything() {
        let mut c = cfg(&[("0.0.0.0/0", IpAction::Deny)], IpAction::Deny);
        c.enabled = false;
        let rt = Runtime::new();
        let remote = RemoteList::default();
        assert_eq!(rt.check(&c, 1, &remote, 1, "1.2.3.4".parse().unwrap()).action, IpAction::Allow);
    }

    #[test]
    fn list_parsing_reports_bad_lines() {
        let text = "# 注释\n1.2.3.0/24\n\n10.0.0.0/8  # 行尾注释\nnot-an-ip\n1.1.1.1, 2.2.2.0/24\n";
        let (ok, bad) = parse_list(text);
        assert!(ok.contains(&"1.2.3.0/24".to_string()));
        assert!(ok.contains(&"10.0.0.0/8".to_string()));
        assert!(ok.contains(&"2.2.2.0/24".to_string()));
        assert!(bad.contains(&"not-an-ip".to_string()));
    }
}
