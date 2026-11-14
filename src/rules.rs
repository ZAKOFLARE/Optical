//! 自定义规则：按请求特征匹配，命中后对网关行为做细粒度改写。
//!
//! 语义（说清楚，别让人猜）：
//! 1. 规则按**列表顺序**评估，所有命中的规则**依次合并**，同一动作以最后一条为准；
//! 2. 每条规则内部的条件是 **AND**（全部满足才命中）；
//! 3. 没有匹配到就不改任何行为，保持全局配置；
//! 4. 优先级：规则产生的动作 > 路由/全局配置。
//!
//! 动作只做"真能落地"的那部分。分片回源、OCSP、下行限速需要改动数据面结构，
//! 这里不放空字段——宁可没有，也不能配了不生效。

use serde::{Deserialize, Serialize};

/// 匹配对象。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// 恒真。给"所有请求"加一条限速/改写时用它——
    /// 否则只能编个 `path 前缀 /` 之类的近似条件，读的人还得猜你为什么这么写。
    All,
    /// 域名（不含端口）
    Host,
    /// 路径前缀
    Path,
    /// 完整路径（含前导 /）
    FullPath,
    /// 查询字符串（不含 ?）
    Query,
    /// 文件后缀（不含点，如 css）
    Ext,
    /// 文件名（含后缀，如 app.js）
    Filename,
    /// 请求头
    Header,
    /// 请求协议：http / https
    Scheme,
    /// 客户端 IP（支持 CIDR）
    ClientIp,
    /// 请求方法
    Method,
    /// Cookie
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOp {
    Eq,
    Ne,
    Contains,
    NContains,
    Prefix,
    Suffix,
    /// 简易通配：* 任意串，? 单字符
    Wildcard,
    /// CIDR 网段，仅 client_ip 用
    Cidr,
    /// 不在该 CIDR 网段内，仅 client_ip 用。与 Cidr 成对——
    /// 之前只有"在网段内才命中"，想排除某段 IP 得写好几条反着拼，很别扭。
    #[serde(rename = "ncidr")]
    NCidr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MatchRule {
    pub kind: MatchKind,
    /// header / cookie 的键名，其它类型忽略
    pub name: String,
    pub op: MatchOp,
    pub value: String,
}

impl Default for MatchRule {
    fn default() -> Self {
        Self {
            kind: MatchKind::Host,
            name: String::new(),
            op: MatchOp::Eq,
            value: String::new(),
        }
    }
}

/// 命中后要改的行为。None / 未设置 = 不动。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Actions {
    /// 节点缓存 TTL（秒）；0 表示该请求不走缓存
    pub cache_ttl_secs: Option<u64>,
    /// 浏览器缓存 TTL（秒），写进 Cache-Control: max-age
    pub browser_ttl_secs: Option<u64>,
    /// 自定义 cache key 模板，支持 {method} {host} {uri} {path} {query}
    pub cache_key: Option<String>,
    /// 响应 Server 头
    pub server_name: Option<String>,
    /// 强制 https（http 请求 301 到 https）
    pub force_https: Option<bool>,
    /// 最大上传体积（字节）；超了直接 413
    pub max_upload_bytes: Option<u64>,
    /// 回源超时（毫秒）
    pub upstream_timeout_ms: Option<u64>,
    /// 回源 Host 头改写
    pub host_rewrite: Option<String>,
    /// 回源到指定源站组（引用后端组的 group 名）。规则级覆盖，高于路由选路。
    /// 源站组直接复用后端组：同一套 pick、同一套 LB 与探活，
    /// 不另造一套并行机制——两套负载均衡迟早打架。
    pub origin_group: Option<String>,
    /// 直接指定回源 URL（scheme://host[:port]），优先级最高，连源站组都盖过。
    pub upstream: Option<String>,
    /// 回源 URL 重写，支持 {path} {query} {uri}
    pub upstream_url_rewrite: Option<String>,
    /// URL 重定向：目标地址 + 状态码（301/302/307/308）
    pub redirect: Option<Redirect>,
    /// 直接返回自定义页面
    pub custom_response: Option<CustomResponse>,
    /// Token 鉴权：从 header 或 query 取令牌比对
    pub token_auth: Option<TokenAuth>,
    /// 是否允许 WebSocket 升级
    pub ws: Option<bool>,
    /// 附加响应头
    pub response_headers: Vec<(String, String)>,
    /// QPS 限速
    pub rate_limit: Option<RateLimitAction>,
    /// 规则级在途上限
    pub max_in_flight: Option<InFlightAction>,
    /// 回源**建连**超时（毫秒），与总超时分开：
    /// 建连慢通常意味着后端或网络有问题，早点失败比等满总超时更好排查。
    pub connect_timeout_ms: Option<u64>,
}

/// 限速的计数维度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKey {
    /// 按客户端 IP 分桶。默认：一个人刷爆不该连累别人。
    ClientIp,
    /// 按规则名分桶：整条规则的总额度，用来保护后端的硬上限。
    Rule,
    /// 按规则 + IP：同一规则下每个 IP 各自的额度。
    RuleIp,
}

impl Default for LimitKey {
    fn default() -> Self {
        Self::ClientIp
    }
}

/// QPS 限速（令牌桶）。`qps = 0` 视为不限制。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitAction {
    pub qps: u32,
    /// 允许的突发量，0 时取 `qps`（1 秒的额度）
    pub burst: u32,
    pub key: LimitKey,
    /// 超限时返回的状态码，默认 429
    pub status_code: u16,
}

impl Default for RateLimitAction {
    fn default() -> Self {
        Self { qps: 0, burst: 0, key: LimitKey::ClientIp, status_code: 429 }
    }
}

/// 规则级背压：命中这条规则的请求，同时在途的数量上限。
/// 和全局背压是一回事，只是作用域收窄到"被这条规则选中的请求"。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InFlightAction {
    pub limit: usize,
    pub key: LimitKey,
    pub status_code: u16,
}

impl Default for InFlightAction {
    fn default() -> Self {
        Self { limit: 0, key: LimitKey::ClientIp, status_code: 503 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Redirect {
    pub status: u16,
    pub to: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenAuth {
    /// header 名或 query 参数名
    pub name: String,
    /// 期望的令牌
    pub value: String,
    /// 从 query 取而不是 header
    pub from_query: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub name: String,
    pub enabled: bool,
    pub note: String,
    pub matches: Vec<MatchRule>,
    pub actions: Actions,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            note: String::new(),
            matches: Vec::new(),
            actions: Actions::default(),
        }
    }
}

/// 请求里参与匹配的字段。由 proxy 在入口处填好，纯数据、不做 IO。
pub struct ReqFacts<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub method: &'a str,
    pub scheme: &'a str,
    pub client_ip: &'a str,
    pub headers: &'a http::HeaderMap,
}

impl ReqFacts<'_> {
    fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    fn cookie(&self, name: &str) -> String {
        let raw = self.header("cookie");
        for part in raw.split(';') {
            let mut kv = part.splitn(2, '=');
            let k = kv.next().unwrap_or("").trim();
            if k.eq_ignore_ascii_case(name) {
                return kv.next().unwrap_or("").trim().to_string();
            }
        }
        String::new()
    }

    fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or("")
    }

    fn ext(&self) -> &str {
        let f = self.filename();
        match f.rsplit_once('.') {
            Some((_, e)) if !e.is_empty() && e.len() <= 12 => e,
            _ => "",
        }
    }
}

fn wildcard_match(pat: &str, s: &str) -> bool {
    // 经典双指针回溯，避免正则依赖
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn cidr_match(cidr: &str, ip: &str) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, b.parse::<u32>().unwrap_or(32)),
        None => (cidr, 32),
    };
    let addr: std::net::IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let base: std::net::IpAddr = match net.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match (addr, base) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            if bits == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - bits.min(32));
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            let a = u128::from(a);
            let b = u128::from(b);
            if bits == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - bits.min(128));
            (a & mask) == (b & mask)
        }
        _ => false,
    }
}

fn one_match(m: &MatchRule, f: &ReqFacts<'_>) -> bool {
    // ALL 不看 value，也不参与 op：它就是"这条规则对所有请求成立"。
    // 放在空值检查之前，否则 value 为空会被判成不匹配。
    if m.kind == MatchKind::All {
        return true;
    }
    let subject = match m.kind {
        MatchKind::All => unreachable!("上面已经处理"),
        MatchKind::Host => f.host.split(':').next().unwrap_or("").to_string(),
        MatchKind::Path | MatchKind::FullPath => f.path.to_string(),
        MatchKind::Query => f.query.to_string(),
        MatchKind::Ext => f.ext().to_string(),
        MatchKind::Filename => f.filename().to_string(),
        MatchKind::Header => f.header(&m.name),
        MatchKind::Scheme => f.scheme.to_string(),
        MatchKind::ClientIp => f.client_ip.to_string(),
        MatchKind::Method => f.method.to_string(),
        MatchKind::Cookie => f.cookie(&m.name),
    };

    if m.value.is_empty() {
        return false;
    }

    match m.op {
        MatchOp::Cidr => cidr_match(&m.value, &subject),
        MatchOp::NCidr => !cidr_match(&m.value, &subject),
        _ => {
            let (s, v) = (subject.to_lowercase(), m.value.to_lowercase());
            match m.op {
                MatchOp::Eq => s == v,
                MatchOp::Ne => s != v,
                MatchOp::Contains => s.contains(&v),
                MatchOp::NContains => !s.contains(&v),
                MatchOp::Prefix => {
                    // 路径前缀按路径段比较，/api 不该命中 /apixyz
                    let sp = subject.trim_end_matches('/');
                    let vp = m.value.trim_end_matches('/');
                    sp == vp || sp.starts_with(&format!("{vp}/"))
                }
                MatchOp::Suffix => s.ends_with(&v),
                MatchOp::Wildcard => wildcard_match(&v, &s),
                MatchOp::Cidr | MatchOp::NCidr => false,
            }
        }
    }
}

/// 所有命中规则的合并结果。
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub actions: Actions,
    /// 命中的规则名，方便在响应头/日志里定位"是谁改的"
    pub hit: Vec<String>,
}

/// 按顺序评估：命中的规则依次合并，后面的覆盖前面的。
pub fn resolve(rules: &[Rule], f: &ReqFacts<'_>) -> Resolved {
    let mut out = Resolved::default();
    for r in rules.iter().filter(|r| r.enabled) {
        if r.matches.is_empty() {
            continue; // 没有条件的规则不生效，否则一条空规则会把全站改掉
        }
        if !r.matches.iter().all(|m| one_match(m, f)) {
            continue;
        }
        out.hit.push(r.name.clone());
        merge(&mut out.actions, &r.actions);
    }
    out
}

fn merge(dst: &mut Actions, src: &Actions) {
    if src.cache_ttl_secs.is_some() {
        dst.cache_ttl_secs = src.cache_ttl_secs;
    }
    if src.rate_limit.is_some() {
        dst.rate_limit = src.rate_limit.clone();
    }
    if src.max_in_flight.is_some() {
        dst.max_in_flight = src.max_in_flight.clone();
    }
    if src.connect_timeout_ms.is_some() {
        dst.connect_timeout_ms = src.connect_timeout_ms;
    }
    if src.origin_group.is_some() {
        dst.origin_group = src.origin_group.clone();
    }
    if src.upstream.is_some() {
        dst.upstream = src.upstream.clone();
    }
    if src.browser_ttl_secs.is_some() {
        dst.browser_ttl_secs = src.browser_ttl_secs;
    }
    if src.cache_key.is_some() {
        dst.cache_key = src.cache_key.clone();
    }
    if src.server_name.is_some() {
        dst.server_name = src.server_name.clone();
    }
    if src.force_https.is_some() {
        dst.force_https = src.force_https;
    }
    if src.max_upload_bytes.is_some() {
        dst.max_upload_bytes = src.max_upload_bytes;
    }
    if src.upstream_timeout_ms.is_some() {
        dst.upstream_timeout_ms = src.upstream_timeout_ms;
    }
    if src.host_rewrite.is_some() {
        dst.host_rewrite = src.host_rewrite.clone();
    }
    if src.upstream_url_rewrite.is_some() {
        dst.upstream_url_rewrite = src.upstream_url_rewrite.clone();
    }
    if src.redirect.is_some() {
        dst.redirect = src.redirect.clone();
    }
    if src.custom_response.is_some() {
        dst.custom_response = src.custom_response.clone();
    }
    if src.token_auth.is_some() {
        dst.token_auth = src.token_auth.clone();
    }
    if src.ws.is_some() {
        dst.ws = src.ws;
    }
    if !src.response_headers.is_empty() {
        dst.response_headers.extend(src.response_headers.clone());
    }
}

/// 模板展开需要的字段。刻意不含 headers：
/// 匹配要借 parts.headers，但展开发生在后面改写请求的阶段，
/// 两者共用一个结构会让借用一直挂着，编译器直接不干。
pub struct Vars<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub method: &'a str,
}

/// 模板替换：{host} {path} {uri} {query} {method}
pub fn expand(tpl: &str, v: &Vars<'_>) -> String {
    let uri = if v.query.is_empty() {
        v.path.to_string()
    } else {
        format!("{}?{}", v.path, v.query)
    };
    tpl.replace("{host}", v.host)
        .replace("{path}", v.path)
        .replace("{uri}", &uri)
        .replace("{query}", v.query)
        .replace("{method}", v.method)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(headers: &'a http::HeaderMap) -> ReqFacts<'a> {
        ReqFacts {
            host: "www.a.com:8080",
            path: "/static/app.js",
            query: "v=2&x=1",
            method: "GET",
            scheme: "http",
            client_ip: "192.168.1.20",
            headers,
        }
    }

    fn rule(matches: Vec<MatchRule>, actions: Actions) -> Rule {
        Rule {
            name: "r".into(),
            enabled: true,
            note: String::new(),
            matches,
            actions,
        }
    }

    fn m(kind: MatchKind, op: MatchOp, value: &str) -> MatchRule {
        MatchRule {
            kind,
            name: String::new(),
            op,
            value: value.into(),
        }
    }

    #[test]
    fn path_prefix_matches_segment_not_string() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let r = rule(
            vec![m(MatchKind::Path, MatchOp::Prefix, "/static")],
            Actions::default(),
        );
        assert_eq!(resolve(&[r], &f).hit.len(), 1);

        let r2 = rule(
            vec![m(MatchKind::Path, MatchOp::Prefix, "/sta")],
            Actions::default(),
        );
        assert!(resolve(&[r2], &f).hit.is_empty(), "/sta 不该命中 /static");
    }

    #[test]
    fn all_conditions_are_anded() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let ok = rule(
            vec![
                m(MatchKind::Ext, MatchOp::Eq, "js"),
                m(MatchKind::Method, MatchOp::Eq, "get"),
            ],
            Actions::default(),
        );
        assert_eq!(resolve(&[ok], &f).hit.len(), 1);

        let bad = rule(
            vec![
                m(MatchKind::Ext, MatchOp::Eq, "js"),
                m(MatchKind::Method, MatchOp::Eq, "post"),
            ],
            Actions::default(),
        );
        assert!(resolve(&[bad], &f).hit.is_empty());
    }

    #[test]
    fn host_ignores_port_and_case() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let r = rule(
            vec![m(MatchKind::Host, MatchOp::Eq, "WWW.A.COM")],
            Actions::default(),
        );
        assert_eq!(resolve(&[r], &f).hit.len(), 1);
    }

    #[test]
    fn cidr_and_wildcard_work() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let cidr = rule(
            vec![m(MatchKind::ClientIp, MatchOp::Cidr, "192.168.1.0/24")],
            Actions::default(),
        );
        assert_eq!(resolve(&[cidr], &f).hit.len(), 1);

        let wild = rule(
            vec![m(MatchKind::Filename, MatchOp::Wildcard, "*.js")],
            Actions::default(),
        );
        assert_eq!(resolve(&[wild], &f).hit.len(), 1);
    }

    #[test]
    fn ncidr_is_negation_of_cidr() {
        let h = http::HeaderMap::new();
        let f = facts(&h); // client_ip = 192.168.1.20
        // 不在 10.0.0.0/8 网段内 → ncidr 命中
        let not_in = rule(
            vec![m(MatchKind::ClientIp, MatchOp::NCidr, "10.0.0.0/8")],
            Actions::default(),
        );
        assert_eq!(resolve(&[not_in], &f).hit.len(), 1);
        // 就在 192.168.0.0/16 网段内 → ncidr 不该命中
        let in_same = rule(
            vec![m(MatchKind::ClientIp, MatchOp::NCidr, "192.168.0.0/16")],
            Actions::default(),
        );
        assert_eq!(resolve(&[in_same], &f).hit.len(), 0);
    }

    #[test]
    fn ncidr_serde_roundtrip() {
        // 配置里写 "ncidr" 能反序列化出来，别只在内存里能用
        let r: MatchRule = serde_json::from_str(
            r#"{"kind":"client_ip","name":"","op":"ncidr","value":"10.0.0.0/8"}"#,
        )
        .unwrap();
        assert_eq!(r.op, MatchOp::NCidr);
    }

    #[test]
    fn later_rules_override_earlier_ones() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let a = rule(
            vec![m(MatchKind::Path, MatchOp::Prefix, "/static")],
            Actions {
                cache_ttl_secs: Some(60),
                ..Default::default()
            },
        );
        let b = rule(
            vec![m(MatchKind::Ext, MatchOp::Eq, "js")],
            Actions {
                cache_ttl_secs: Some(3600),
                ..Default::default()
            },
        );
        let got = resolve(&[a, b], &f);
        assert_eq!(got.hit.len(), 2);
        assert_eq!(got.actions.cache_ttl_secs, Some(3600), "后面的规则应覆盖前面的");
    }

    #[test]
    fn rule_without_conditions_matches_nothing() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        // 空条件规则如果生效，等于把全站都改了——必须是"不命中"
        assert!(resolve(&[rule(vec![], Actions::default())], &f).hit.is_empty());
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let mut r = rule(
            vec![m(MatchKind::Ext, MatchOp::Eq, "js")],
            Actions::default(),
        );
        r.enabled = false;
        assert!(resolve(&[r], &f).hit.is_empty());
    }

    #[test]
    fn header_and_cookie_matching() {
        let mut h = http::HeaderMap::new();
        h.insert("x-env", "preview".parse().unwrap());
        h.insert("cookie", "session=abc; theme=dark".parse().unwrap());
        let f = facts(&h);

        let by_header = MatchRule {
            kind: MatchKind::Header,
            name: "x-env".into(),
            op: MatchOp::Eq,
            value: "preview".into(),
        };
        assert_eq!(
            resolve(&[rule(vec![by_header], Actions::default())], &f).hit.len(),
            1
        );

        let by_cookie = MatchRule {
            kind: MatchKind::Cookie,
            name: "theme".into(),
            op: MatchOp::Eq,
            value: "dark".into(),
        };
        assert_eq!(
            resolve(&[rule(vec![by_cookie], Actions::default())], &f).hit.len(),
            1
        );
    }

    #[test]
    fn template_expansion() {
        let h = http::HeaderMap::new();
        let f = facts(&h);
        let v = Vars {
            host: f.host,
            path: f.path,
            query: f.query,
            method: f.method,
        };
        assert_eq!(expand("{method} {host} {uri}", &v), "GET www.a.com:8080 /static/app.js?v=2&x=1");
        assert_eq!(expand("cdn:{path}", &v), "cdn:/static/app.js");
    }
}
