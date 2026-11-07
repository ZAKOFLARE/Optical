//! WAF 引擎：一个请求进来，各规则族各自打分，累计超过阈值就按模式处置。
//!
//! 设计取舍：
//! - **规则族可独立开关**，每个族有自己的阈值参数，全部来自配置，热重载即生效。
//! - **评分制而不是布尔短路**：单个弱信号（比如一个 `'`）不该直接拦截，
//!   但「SQL 关键字 + 注释 + 联合查询」叠起来就必须拦。阈值在 `waf.score_threshold`。
//! - **body 检查是有条件的**：只有 Content-Length 存在且 ≤ `max_inspect_bytes` 才缓冲检查；
//!   否则跳过并计入 `skipped`（宁可不拦，也不能把流式大文件卡死在内存里）。
//! - 命中结果带 rule id，WebUI 的「规则命中率」就是拿它统计的。

use crate::config::{FrameMode, WafConfig, WafMode};
use base64::Engine;
use http::{HeaderMap, Method, StatusCode};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 单次请求里被检查的那部分信息。
pub struct RequestView<'a> {
    pub method: &'a Method,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
    #[allow(dead_code)] // 预留：将来按 IP 做信誉/黑名单
    pub client_ip: IpAddr,
    /// 仅在 body 可缓冲且未超限时存在
    pub body: Option<&'a [u8]>,
    pub content_type: &'a str,
    pub ua: &'a str,
    /// 身份标识：有 Bearer token 用它，否则用 IP（BOLA 用）
    pub identity: &'a str,
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// 规则短名，如 `sql`
    pub family: &'static str,
    /// 具体命中项，如 `sql-union-select`
    pub rule: &'static str,
    pub severity: u32,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    Monitor,
}

#[derive(Debug, Clone)]
pub struct WafResult {
    pub findings: Vec<Finding>,
    pub score: u32,
    pub verdict: Verdict,
    /// 供日志和响应头用
    pub top_rule: Option<&'static str>,
    /// body 是否真的被检查了
    pub body_inspected: bool,
}

impl WafResult {
    pub fn blocked(&self) -> bool {
        self.verdict == Verdict::Block
    }
    pub fn hit(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// BOLA 需要跨请求状态：谁在窗口内摸了多少个不同对象 ID。
#[derive(Default)]
pub struct BolaTracker {
    inner: Mutex<HashMap<String, (Instant, HashSet<String>)>>,
}

impl BolaTracker {
    pub fn observe(&self, key: &str, ids: &[String], window: Duration, max: u32) -> Option<(usize, u32)> {
        if ids.is_empty() {
            return None;
        }
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // 顺手清理过期身份，避免无限增长
        map.retain(|_, (t, _)| now.duration_since(*t) < window);
        let entry = map.entry(key.to_string()).or_insert((now, HashSet::new()));
        if now.duration_since(entry.0) >= window {
            entry.0 = now;
            entry.1.clear();
        }
        for id in ids {
            entry.1.insert(id.clone());
        }
        if entry.1.len() > max as usize {
            Some((entry.1.len(), max))
        } else {
            None
        }
    }
}

pub fn inspect(cfg: &WafConfig, bola: &BolaTracker, req: &RequestView<'_>) -> WafResult {
    let mut findings = Vec::new();
    let mut body_inspected = false;

    if !cfg.enabled {
        return WafResult {
            findings,
            score: 0,
            verdict: Verdict::Allow,
            top_rule: None,
            body_inspected: false,
        };
    }

    if cfg.dos.enabled {
        check_dos(&cfg.dos, req, &mut findings);
    }
    if cfg.traversal.enabled {
        check_traversal(&cfg.traversal, req, &mut findings);
    }
    if cfg.params.enabled {
        check_params(&cfg.params, req, &mut findings);
    }
    if cfg.cache_deception.enabled {
        check_cache_deception(&cfg.cache_deception, req, &mut findings);
    }
    if cfg.jwt.enabled {
        check_jwt(&cfg.jwt, req, &mut findings);
    }
    if cfg.ssrf.enabled {
        check_ssrf(&cfg.ssrf, req, &mut findings);
    }
    if cfg.bola.enabled {
        check_bola(&cfg.bola, bola, req, &mut findings);
    }

    // body 类规则
    if let Some(body) = req.body {
        if looks_textual(req.content_type) && !body.is_empty() {
            body_inspected = true;
            if cfg.xml.enabled && is_xml(req.content_type, body) {
                check_xml(&cfg.xml, body, &mut findings);
            }
            if cfg.sql.enabled {
                check_sql(&cfg.sql, body, "body", &mut findings);
            }
        }
    }

    // 查询串始终参与 SQL 评分（这是最常见的注入面）
    if cfg.sql.enabled {
        if let Some(q) = req.query {
            check_sql(&cfg.sql, q.as_bytes(), "query", &mut findings);
        }
    }

    let score: u32 = findings.iter().map(|f| f.severity).sum();
    let verdict = if score >= cfg.score_threshold {
        match cfg.mode {
            WafMode::Block => Verdict::Block,
            WafMode::Monitor => Verdict::Monitor,
        }
    } else {
        Verdict::Allow
    };

    let top_rule = findings
        .iter()
        .max_by_key(|f| f.severity)
        .map(|f| f.rule);

    WafResult {
        findings,
        score,
        verdict,
        top_rule,
        body_inspected,
    }
}

// ---------------- DoS / 应用层 ----------------

fn check_dos(cfg: &crate::config::DosConfig, req: &RequestView<'_>, out: &mut Vec<Finding>) {
    let header_count = req.headers.len() + req.headers.iter().count().saturating_sub(req.headers.len());
    if header_count > cfg.max_header_count {
        out.push(Finding {
            family: "dos",
            rule: "dos-header-count",
            severity: 3,
            detail: format!("header 数量 {header_count} > 上限 {}", cfg.max_header_count),
        });
    }

    let header_bytes: usize = req
        .headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
        .sum();
    if header_bytes > cfg.max_header_bytes {
        out.push(Finding {
            family: "dos",
            rule: "dos-header-bytes",
            severity: 3,
            detail: format!("header 体积 {header_bytes} > 上限 {}", cfg.max_header_bytes),
        });
    }

    let url_len = req.path.len() + req.query.map(|q| q.len() + 1).unwrap_or(0);
    if url_len > cfg.max_url_len {
        out.push(Finding {
            family: "dos",
            rule: "dos-url-len",
            severity: 2,
            detail: format!("URL 长度 {url_len} > 上限 {}", cfg.max_url_len),
        });
    }

    if cfg.max_body_bytes > 0 {
        if let Some(cl) = req
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
        {
            if cl > cfg.max_body_bytes {
                out.push(Finding {
                    family: "dos",
                    rule: "dos-body-size",
                    severity: 5,
                    detail: format!("Content-Length {cl} > 上限 {}", cfg.max_body_bytes),
                });
            }
        }
    }

    // cookie 体积 / 数量 / 压缩比
    if let Some(raw) = req.headers.get(http::header::COOKIE).and_then(|v| v.to_str().ok()) {
        let raw_len = raw.len();
        if raw_len > cfg.max_cookie_bytes {
            out.push(Finding {
                family: "dos",
                rule: "dos-cookie-bytes",
                severity: 3,
                detail: format!("Cookie 头 {raw_len}B > 上限 {}B", cfg.max_cookie_bytes),
            });
        }
        let pairs = parse_cookies(raw);
        if pairs.len() > cfg.max_cookie_count {
            out.push(Finding {
                family: "dos",
                rule: "dos-cookie-count",
                severity: 3,
                detail: format!("Cookie 个数 {} > 上限 {}", pairs.len(), cfg.max_cookie_count),
            });
        }
        for (name, value) in &pairs {
            if value.len() > cfg.max_cookie_value_bytes {
                out.push(Finding {
                    family: "dos",
                    rule: "dos-cookie-value",
                    severity: 2,
                    detail: format!("Cookie {name} 体积 {}B 超限", value.len()),
                });
            }
            if let Some((raw_size, expanded, ratio)) = cookie_compression(value) {
                if ratio < cfg.cookie_compression_ratio as f64 {
                    out.push(Finding {
                        family: "dos",
                        rule: "dos-cookie-compression",
                        severity: 5,
                        detail: format!(
                            "Cookie {name} 压缩比异常：{raw_size}B → {expanded}B（比值 {ratio:.1} < {}）",
                            cfg.cookie_compression_ratio
                        ),
                    });
                }
            }
        }
    }

    // 异常应用层：空 UA + 非法方法组合、可疑 method
    if req.ua.is_empty() {
        out.push(Finding {
            family: "dos",
            rule: "dos-empty-ua",
            severity: 1,
            detail: "缺少 User-Agent".into(),
        });
    }
    let m = req.method.as_str();
    if !matches!(m, "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH") {
        out.push(Finding {
            family: "dos",
            rule: "dos-method",
            severity: 3,
            detail: format!("非常规方法 {m}"),
        });
    }
    // header 名不合规（HTTP/1.1 走私/混淆的常见特征）
    for (k, _) in req.headers.iter() {
        let name = k.as_str();
        if name.contains(' ') || name.contains('\t') || name != name.to_ascii_lowercase() {
            out.push(Finding {
                family: "dos",
                rule: "dos-header-malformed",
                severity: 3,
                detail: format!("异常 header 名: {name}"),
            });
            break;
        }
    }
}

/// 识别 base64(gzip/zlib) 的 cookie 并试解压，返回 (原始字节, 解压后字节, 压缩比)。
/// 解压上限 64 KiB，超出即认为命中炸弹，避免把网关自己撑爆。
fn cookie_compression(value: &str) -> Option<(usize, usize, f64)> {
    const LIMIT: usize = 64 * 1024;
    let v = value.trim_matches('"');
    if v.len() < 24 {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(v)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v))
        .ok()?;
    let is_gzip = raw.len() > 2 && raw[0] == 0x1f && raw[1] == 0x8b;
    let is_zlib = raw.len() > 2 && raw[0] == 0x78;
    if !is_gzip && !is_zlib {
        return None;
    }
    use std::io::Read;
    let mut out = Vec::with_capacity(1024);
    let reader: Box<dyn Read> = if is_gzip {
        Box::new(flate2::read::GzDecoder::new(&raw[..]))
    } else {
        Box::new(flate2::read::ZlibDecoder::new(&raw[..]))
    };
    let n = reader.take(LIMIT as u64 + 1).read_to_end(&mut out).ok()?;
    if n == 0 {
        return None;
    }
    let ratio = n as f64 / raw.len() as f64;
    Some((raw.len(), n, ratio))
}

// ---------------- XML ----------------

fn is_xml(content_type: &str, body: &[u8]) -> bool {
    content_type.contains("xml")
        || body.starts_with(b"<?xml")
        || body.starts_with(&[0xEF, 0xBB, 0xBF]) // BOM
}

fn check_xml(cfg: &crate::config::XmlConfig, body: &[u8], out: &mut Vec<Finding>) {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();

    if cfg.block_dtd && lower.contains("<!doctype") {
        out.push(Finding {
            family: "xml",
            rule: "xml-doctype",
            severity: 4,
            detail: "出现 DOCTYPE 声明（XXE 前置条件）".into(),
        });
    }
    if cfg.block_external_entity
        && (lower.contains("<!entity") && (lower.contains("system") || lower.contains("public")))
    {
        out.push(Finding {
            family: "xml",
            rule: "xml-external-entity",
            severity: 5,
            detail: "外部实体声明（XXE）".into(),
        });
    }
    if cfg.block_xinclude && lower.contains("<xi:include") {
        out.push(Finding {
            family: "xml",
            rule: "xml-xinclude",
            severity: 5,
            detail: "XInclude 指令可读取任意文件".into(),
        });
    }

    // 深度：连续开标签的最大嵌套
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    for ch in text.chars() {
        match ch {
            '<' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            '>' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    if max_depth > cfg.max_depth {
        out.push(Finding {
            family: "xml",
            rule: "xml-depth",
            severity: 3,
            detail: format!("嵌套深度 {max_depth} > 上限 {}", cfg.max_depth),
        });
    }

    // billion laughs：递归实体引用
    let entity_refs = text.matches("&").count();
    if entity_refs > cfg.max_entity_refs {
        out.push(Finding {
            family: "xml",
            rule: "xml-entity-bomb",
            severity: 4,
            detail: format!("实体引用 {entity_refs} 次 > 上限 {}", cfg.max_entity_refs),
        });
    }
}

// ---------------- JWT ----------------

fn check_jwt(cfg: &crate::config::JwtConfig, req: &RequestView<'_>, out: &mut Vec<Finding>) {
    let Some(hv) = req.headers.get(http::header::AUTHORIZATION) else {
        return;
    };
    let Ok(raw) = hv.to_str() else { return };
    let Some(token) = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")) else {
        return;
    };
    let token = token.trim();
    if token.len() > cfg.max_token_bytes {
        out.push(Finding {
            family: "jwt",
            rule: "jwt-oversize",
            severity: 3,
            detail: format!("token {}B 超过上限 {}B", token.len(), cfg.max_token_bytes),
        });
        return;
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return;
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    if let Ok(hdr_raw) = b64.decode(parts[0]) {
        if let Ok(hdr) = serde_json::from_slice::<serde_json::Value>(&hdr_raw) {
            let alg = hdr.get("alg").and_then(|v| v.as_str()).unwrap_or("");
            if cfg.reject_alg_none && alg.eq_ignore_ascii_case("none") {
                out.push(Finding {
                    family: "jwt",
                    rule: "jwt-alg-none",
                    severity: 5,
                    detail: "alg = none，签名可被绕过".into(),
                });
            } else if !cfg.allowed_algs.is_empty()
                && !cfg.allowed_algs.iter().any(|a| a.eq_ignore_ascii_case(alg))
            {
                out.push(Finding {
                    family: "jwt",
                    rule: "jwt-alg-not-allowed",
                    severity: 4,
                    detail: format!("alg = {alg} 不在白名单"),
                });
            }
            if cfg.reject_kid_injection {
                if let Some(kid) = hdr.get("kid").and_then(|v| v.as_str()) {
                    let k = kid.to_ascii_lowercase();
                    if k.contains("..") || k.contains('/') || k.contains('\\') || k.contains('\'')
                        || k.contains("\"") || k.contains("http")
                    {
                        out.push(Finding {
                            family: "jwt",
                            rule: "jwt-kid-injection",
                            severity: 5,
                            detail: format!("kid 含路径/URL 特征: {kid}"),
                        });
                    }
                }
            }
        }
    }

    if let Ok(payload_raw) = b64.decode(parts[1]) {
        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&payload_raw) {
            if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                if exp + cfg.clock_skew_secs as i64 <= now {
                    out.push(Finding {
                        family: "jwt",
                        rule: "jwt-expired",
                        severity: 2,
                        detail: format!("token 已过期（exp={exp}, now={now}）"),
                    });
                }
            }
        }
    }
}

// ---------------- SQL ----------------

const SQL_PATTERNS: &[(&str, u32, &str)] = &[
    ("union select", 4, "sql-union-select"),
    ("union all select", 4, "sql-union-select"),
    ("' or '1'='1", 5, "sql-tautology"),
    ("' or 1=1", 5, "sql-tautology"),
    ("\" or \"1\"=\"1", 5, "sql-tautology"),
    (" or 1=1", 3, "sql-tautology"),
    ("information_schema", 4, "sql-schema-probe"),
    ("xp_cmdshell", 5, "sql-xp-cmdshell"),
    ("sleep(", 4, "sql-time-blind"),
    ("benchmark(", 4, "sql-time-blind"),
    ("waitfor delay", 4, "sql-time-blind"),
    ("extractvalue(", 3, "sql-error-blind"),
    ("updatexml(", 3, "sql-error-blind"),
    ("into outfile", 4, "sql-file-write"),
    ("load_file(", 4, "sql-file-read"),
    ("; drop table", 5, "sql-ddl"),
    ("--", 1, "sql-comment"),
    ("/*", 1, "sql-comment"),
];

fn check_sql(cfg: &crate::config::SqlConfig, raw: &[u8], where_: &str, out: &mut Vec<Finding>) {
    let text = String::from_utf8_lossy(raw);
    let decoded = percent_decode(&text).to_ascii_lowercase();
    let mut score = 0u32;
    let mut rules: Vec<&'static str> = Vec::new();
    for (pat, sev, id) in SQL_PATTERNS {
        if decoded.contains(pat) {
            // 注释类只在已经有其他信号时才算分，避免误报
            if (*pat == "--" || *pat == "/*") && rules.is_empty() {
                continue;
            }
            score += sev;
            rules.push(id);
        }
    }
    if score >= cfg.threshold && !rules.is_empty() {
        out.push(Finding {
            family: "sql",
            rule: rules[0],
            severity: score.min(5),
            detail: format!("{where_} 命中 SQL 特征: {}", rules.join(",")),
        });
    }
}

// ---------------- SSRF ----------------

fn check_ssrf(cfg: &crate::config::SsrfConfig, req: &RequestView<'_>, out: &mut Vec<Finding>) {
    if cfg.allow_private {
        return;
    }
    let mut candidates: Vec<(String, String)> = Vec::new();
    if let Some(q) = req.query {
        candidates.extend(parse_pairs(q));
    }
    if let Some(body) = req.body {
        if req.content_type.contains("form-urlencoded") {
            candidates.extend(parse_pairs(&String::from_utf8_lossy(body)));
        } else if req.content_type.contains("json") {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
                collect_json_strings(&v, &mut candidates);
            }
        }
    }

    for (k, v) in candidates {
        let key_l = k.to_ascii_lowercase();
        if !cfg.param_names.iter().any(|n| n.eq_ignore_ascii_case(&key_l)) {
            continue;
        }
        let target = percent_decode(&v).to_ascii_lowercase();
        let bad_scheme = ["file://", "gopher://", "dict://", "ftp://", "ldap://"]
            .iter()
            .find(|s| target.starts_with(*s));
        let host = extract_host(&target);
        let bad_host = host.as_deref().map(is_internal_host).unwrap_or(false);
        if let Some(s) = bad_scheme {
            out.push(Finding {
                family: "ssrf",
                rule: "ssrf-scheme",
                severity: 5,
                detail: format!("参数 {k} 使用危险协议 {s}"),
            });
        } else if bad_host {
            out.push(Finding {
                family: "ssrf",
                rule: "ssrf-internal",
                severity: 5,
                detail: format!("参数 {k} 指向内网/元数据地址: {v}"),
            });
        }
    }
}

fn extract_host(v: &str) -> Option<String> {
    let rest = match v.find("://") {
        Some(i) => &v[i + 3..],
        None => v.strip_prefix("//").unwrap_or(v),
    };
    let host_part = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_part.split('@').next_back().unwrap_or(host_part);
    let host = host.split(':').next().unwrap_or(host).trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn is_internal_host(host: &str) -> bool {
    if matches!(host, "localhost" | "0.0.0.0" | "[::]" | "::" | "::1" | "[::1]") {
        return true;
    }
    if host.ends_with(".internal") || host.ends_with(".local") || host == "169.254.169.254" {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast()
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
    }
    false
}

fn collect_json_strings(v: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if let serde_json::Value::String(s) = val {
                    out.push((k.clone(), s.clone()));
                } else {
                    collect_json_strings(val, out);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for item in a {
                collect_json_strings(item, out);
            }
        }
        _ => {}
    }
}

// ---------------- BOLA ----------------

fn check_bola(
    cfg: &crate::config::BolaConfig,
    tracker: &BolaTracker,
    req: &RequestView<'_>,
    out: &mut Vec<Finding>,
) {
    let ids = extract_object_ids(req.path, req.query);
    if let Some((seen, max)) = tracker.observe(
        req.identity,
        &ids,
        Duration::from_secs(cfg.window_secs.max(1)),
        cfg.max_distinct_ids,
    ) {
        out.push(Finding {
            family: "bola",
            rule: "bola-id-enumeration",
            severity: 4,
            detail: format!(
                "{}s 内同一身份访问了 {seen} 个不同对象 ID（上限 {max}）",
                cfg.window_secs
            ),
        });
    }
}

fn extract_object_ids(path: &str, query: Option<&str>) -> Vec<String> {
    let mut ids = Vec::new();
    for seg in path.split('/') {
        if !seg.is_empty() && seg.len() <= 12 && seg.chars().all(|c| c.is_ascii_digit()) {
            ids.push(format!("p:{seg}"));
        }
    }
    if let Some(q) = query {
        for (k, v) in parse_pairs(q) {
            let kl = k.to_ascii_lowercase();
            if (kl == "id" || kl.ends_with("_id") || kl == "uuid") && !v.is_empty() {
                ids.push(format!("q:{k}={v}"));
            }
        }
    }
    ids
}

// ---------------- 路径穿越 / 开放重定向 ----------------

fn check_traversal(cfg: &crate::config::TraversalConfig, req: &RequestView<'_>, out: &mut Vec<Finding>) {
    let path_once = percent_decode(req.path).to_ascii_lowercase();
    let path_twice = percent_decode(&path_once).to_ascii_lowercase();

    if path_once.contains("../") || path_once.contains("..\\") {
        out.push(Finding {
            family: "traversal",
            rule: "traversal-dotdot",
            severity: 5,
            detail: format!("路径含穿越序列: {}", req.path),
        });
    } else if cfg.block_encoded
        && (path_twice.contains("../") || path_once.contains("%2e%2e") || path_once.contains("%252e"))
    {
        out.push(Finding {
            family: "traversal",
            rule: "traversal-encoded",
            severity: 5,
            detail: "路径含编码后的穿越序列（%2e%2e / %252e）".into(),
        });
    }
    if path_once.contains("/etc/passwd") || path_once.contains("\\windows\\system32") {
        out.push(Finding {
            family: "traversal",
            rule: "traversal-sensitive-file",
            severity: 5,
            detail: "路径指向敏感系统文件".into(),
        });
    }

    if cfg.block_open_redirect {
        if let Some(q) = req.query {
            for (k, v) in parse_pairs(q) {
                if !cfg.redirect_params.iter().any(|p| p.eq_ignore_ascii_case(&k)) {
                    continue;
                }
                let target = percent_decode(&v);
                let t = target.trim();
                let external = t.starts_with("http://")
                    || t.starts_with("https://")
                    || t.starts_with("//")
                    || t.starts_with("\\\\");
                if external {
                    out.push(Finding {
                        family: "traversal",
                        rule: "open-redirect",
                        severity: 5,
                        detail: format!("参数 {k} 指向外部地址: {t}"),
                    });
                }
            }
        }
    }
}

// ---------------- 缓存欺骗 ----------------

fn check_cache_deception(
    cfg: &crate::config::CacheDeceptionConfig,
    req: &RequestView<'_>,
    out: &mut Vec<Finding>,
) {
    let path = req.path.to_ascii_lowercase();
    let has_static_ext = cfg.static_exts.iter().any(|e| path.ends_with(e));
    if has_static_ext {
        // /user/1/profile.css —— 前段明显是动态路由，却被静态扩展名"污染"
        let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        let suspicious = segments.len() >= 3
            && segments
                .iter()
                .any(|s| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty());
        if suspicious {
            out.push(Finding {
                family: "cache_deception",
                rule: "cache-deception-ext",
                severity: 4,
                detail: format!("动态路径带静态扩展名: {}", req.path),
            });
        }
    }
    let seg_count = req.path.split('/').filter(|s| !s.is_empty()).count();
    if seg_count > cfg.max_path_segments {
        out.push(Finding {
            family: "cache_deception",
            rule: "cache-deception-segments",
            severity: 2,
            detail: format!("路径段 {seg_count} > 上限 {}", cfg.max_path_segments),
        });
    }
    if let Some(q) = req.query {
        if has_static_ext && (q.contains("..") || q.contains("%2e")) {
            out.push(Finding {
                family: "cache_deception",
                rule: "cache-deception-query",
                severity: 4,
                detail: "静态资源请求带穿越型查询串".into(),
            });
        }
    }
}

// ---------------- 参数污染 ----------------

fn check_params(cfg: &crate::config::ParamsConfig, req: &RequestView<'_>, out: &mut Vec<Finding>) {
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(q) = req.query {
        pairs.extend(parse_pairs(q));
    }
    if let Some(body) = req.body {
        if req.content_type.contains("form-urlencoded") {
            pairs.extend(parse_pairs(&String::from_utf8_lossy(body)));
        }
    }
    if pairs.is_empty() {
        return;
    }
    if pairs.len() > cfg.max_params {
        out.push(Finding {
            family: "params",
            rule: "param-count",
            severity: 2,
            detail: format!("参数总数 {} > 上限 {}", pairs.len(), cfg.max_params),
        });
    }

    let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
    for (k, v) in &pairs {
        seen.entry(k.clone()).or_default().insert(v.clone());
    }
    for (k, vals) in seen {
        if vals.len() > cfg.max_duplicates {
            out.push(Finding {
                family: "params",
                rule: "param-pollution",
                severity: 4,
                detail: format!("参数 {k} 出现 {} 个不同值（HPP 污染）", vals.len()),
            });
        }
    }
}

// ---------------- 帧限制（响应阶段） ----------------

/// 按配置给响应补上防点击劫持的头；返回是否写入了头。
pub fn apply_frame_policy(cfg: &crate::config::FrameConfig, headers: &mut HeaderMap) -> bool {
    if !cfg.enabled {
        return false;
    }
    match cfg.mode {
        FrameMode::Deny => {
            headers.insert(
                http::header::X_FRAME_OPTIONS,
                http::HeaderValue::from_static("DENY"),
            );
            headers.insert(
                http::header::CONTENT_SECURITY_POLICY,
                http::HeaderValue::from_static("frame-ancestors 'none'"),
            );
        }
        FrameMode::Sameorigin => {
            headers.insert(
                http::header::X_FRAME_OPTIONS,
                http::HeaderValue::from_static("SAMEORIGIN"),
            );
            headers.insert(
                http::header::CONTENT_SECURITY_POLICY,
                http::HeaderValue::from_static("frame-ancestors 'self'"),
            );
        }
        FrameMode::AllowFrom => {
            let list = cfg.allow_from.join(" ");
            if let Ok(v) = http::HeaderValue::from_str(&format!("frame-ancestors {list}")) {
                headers.insert(http::header::CONTENT_SECURITY_POLICY, v);
            }
        }
    }
    true
}

// ---------------- 小工具 ----------------

fn looks_textual(content_type: &str) -> bool {
    content_type.contains("json")
        || content_type.contains("xml")
        || content_type.contains("text/")
        || content_type.contains("form-urlencoded")
        || content_type.is_empty()
}

pub fn parse_cookies(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|p| {
            let p = p.trim();
            if p.is_empty() {
                return None;
            }
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

pub fn parse_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|s| !s.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push(h * 16 + l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// WAF 拦截时的响应状态码：SQL/XML/SSRF 这类直接 403，超限类 413。
pub fn block_status(top_rule: Option<&str>) -> StatusCode {
    match top_rule {
        Some(r) if r.starts_with("dos-body") => StatusCode::PAYLOAD_TOO_LARGE,
        Some(r) if r.starts_with("dos-") => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn view<'a>(
        method: &'a Method,
        path: &'a str,
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        body: Option<&'a [u8]>,
    ) -> RequestView<'a> {
        RequestView {
            method,
            path,
            query,
            headers,
            client_ip: "203.0.113.9".parse().unwrap(),
            body,
            content_type: "",
            ua: "curl/8",
            identity: "ip:203.0.113.9",
        }
    }

    fn cfg() -> WafConfig {
        WafConfig::default()
    }

    #[test]
    fn clean_request_passes() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/api/v1/items", Some("page=1"), &h, None));
        assert!(!r.hit());
        assert_eq!(r.verdict, Verdict::Allow);
    }

    #[test]
    fn sql_injection_blocked() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(
            &cfg(),
            &BolaTracker::default(),
            &view(&m, "/search", Some("q=%27%20or%201%3D1%20union%20select%20password"), &h, None),
        );
        assert!(r.blocked(), "findings={:?}", r.findings);
        assert!(r.findings.iter().any(|f| f.family == "sql"));
    }

    #[test]
    fn traversal_blocked() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/static/%2e%2e/%2e%2e/etc/passwd", None, &h, None));
        assert!(r.blocked(), "findings={:?}", r.findings);
        assert!(r.findings.iter().any(|f| f.family == "traversal"));
    }

    #[test]
    fn open_redirect_flagged() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/login", Some("next=https%3A%2F%2Fevil.example"), &h, None));
        assert!(r.findings.iter().any(|f| f.rule == "open-redirect"));
    }

    #[test]
    fn ssrf_metadata_address_blocked() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(
            &cfg(),
            &BolaTracker::default(),
            &view(&m, "/fetch", Some("url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data"), &h, None),
        );
        assert!(r.blocked(), "findings={:?}", r.findings);
        assert!(r.findings.iter().any(|f| f.family == "ssrf"));
    }

    #[test]
    fn jwt_alg_none_blocked() {
        let mut h = HeaderMap::new();
        // {"alg":"none","typ":"JWT"} . {"sub":"admin"} . ""
        h.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."),
        );
        let m = Method::GET;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/me", None, &h, None));
        assert!(r.findings.iter().any(|f| f.rule == "jwt-alg-none"), "findings={:?}", r.findings);
    }

    #[test]
    fn xml_xxe_blocked() {
        let h = HeaderMap::new();
        let m = Method::POST;
        let body = br#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
        let mut v = view(&m, "/api/xml", None, &h, Some(body));
        v.content_type = "application/xml";
        let r = inspect(&cfg(), &BolaTracker::default(), &v);
        assert!(r.body_inspected);
        assert!(r.blocked(), "findings={:?}", r.findings);
    }

    #[test]
    fn hpp_duplicate_params_flagged() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/pay", Some("amount=1&amount=9999"), &h, None));
        assert!(r.findings.iter().any(|f| f.rule == "param-pollution"), "findings={:?}", r.findings);
    }

    #[test]
    fn cache_deception_flagged() {
        let h = HeaderMap::new();
        let m = Method::GET;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/user/42/profile.css", None, &h, None));
        assert!(r.findings.iter().any(|f| f.family == "cache_deception"), "findings={:?}", r.findings);
    }

    #[test]
    fn bola_tracks_identity_window() {
        let cfg = cfg();
        let t = BolaTracker::default();
        let h = HeaderMap::new();
        let m = Method::GET;
        let mut last = None;
        for i in 0..40 {
            let path = format!("/api/order/{i}");
            let r = inspect(&cfg, &t, &view(&m, &path, None, &h, None));
            last = Some(r);
        }
        let r = last.unwrap();
        assert!(r.findings.iter().any(|f| f.family == "bola"), "findings={:?}", r.findings);
    }

    #[test]
    fn dos_oversize_body_blocked() {
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("99999999"));
        let m = Method::POST;
        let r = inspect(&cfg(), &BolaTracker::default(), &view(&m, "/upload", None, &h, None));
        assert!(r.findings.iter().any(|f| f.rule == "dos-body-size"));
        assert_eq!(block_status(r.top_rule), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn monitor_mode_does_not_block() {
        let mut c = cfg();
        c.mode = WafMode::Monitor;
        let h = HeaderMap::new();
        let m = Method::GET;
        // 评分 9（' or 1=1 给 5，union select 给 4）足以越过阈值
        let r = inspect(
            &c,
            &BolaTracker::default(),
            &view(&m, "/search", Some("q=%27%20or%201%3D1%20union%20select%201"), &h, None),
        );
        assert!(r.hit());
        assert_eq!(r.verdict, Verdict::Monitor);
        assert!(!r.blocked());
    }

    #[test]
    fn frame_policy_headers() {
        let mut h = HeaderMap::new();
        assert!(apply_frame_policy(&crate::config::FrameConfig::default(), &mut h));
        assert_eq!(h[http::header::X_FRAME_OPTIONS], "DENY");
    }

    #[test]
    fn percent_decode_works() {
        assert_eq!(percent_decode("a%2e%2e%2fb+c"), "a../b c");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
