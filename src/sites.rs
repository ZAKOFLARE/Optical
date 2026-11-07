//! 静态站点：网关自己也能托管站点，而不是只能把请求转给别人。
//!
//! 定位很明确——"像 nginx 那样管项目"的最小闭环：
//! 绑定域名 → 指定根目录 → 直接吐文件，带 ETag / 304 / SPA 回退 / 缓存策略。
//! 动态请求还是交给 `routes` 转发，两者按 host 分流，互不抢占。
//!
//! 安全底线：路径百分号解码后再逐段校验，`..` 一律拒绝；
//! 落地前再 canonicalize 一次确认没跑出根目录（软链接打穿也算）。

use crate::proxy::ProxyBody;
use http::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct SiteConfig {
    /// 站点名，只用于展示；留空时按域名兜底
    pub name: String,
    pub enabled: bool,
    /// 绑定的域名；`*` 表示兜底。可以写多个，匹配时忽略端口与大小写
    pub hosts: Vec<String>,
    /// 站点根目录；相对路径按配置文件所在目录解析
    pub root: String,
    /// 目录默认文档，按顺序找
    pub index: Vec<String>,
    /// 单页应用：找不到的路径（无扩展名、且接受 HTML）回退到首页
    pub spa: bool,
    /// 浏览器缓存秒数；0 表示 no-cache
    pub cache_secs: u64,
    /// 带指纹的静态资源：在 cache_secs 基础上加 immutable
    pub immutable: bool,
    /// 额外响应头
    pub headers: Vec<(String, String)>,
}

impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            hosts: vec!["*".to_string()],
            root: String::new(),
            index: vec!["index.html".to_string()],
            spa: false,
            cache_secs: 0,
            immutable: false,
            headers: Vec::new(),
        }
    }
}

impl SiteConfig {
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            self.hosts.first().map(String::as_str).unwrap_or("unnamed")
        } else {
            &self.name
        }
    }

    fn matches_host(&self, host: &str) -> bool {
        let h = strip_port(host).to_ascii_lowercase();
        self.hosts.iter().any(|p| {
            let p = strip_port(p).to_ascii_lowercase();
            p == "*" || p == h
        })
    }
}

fn strip_port(host: &str) -> &str {
    // [::1]:8080 这种要先处理方括号，否则 rfind(':') 会把 IPv6 地址剁碎
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

/// 命中哪个站点。精确域名优先于 `*`，避免兜底站点抢走真实域名的请求。
pub fn pick<'a>(sites: &'a [SiteConfig], host: &str) -> Option<&'a SiteConfig> {
    let h = strip_port(host).to_ascii_lowercase();
    let mut wildcard = None;
    for s in sites.iter().filter(|s| s.enabled) {
        for p in &s.hosts {
            let p = strip_port(p).to_ascii_lowercase();
            if p == h && p != "*" {
                return Some(s);
            }
            if p == "*" {
                wildcard = Some(s);
            }
        }
    }
    wildcard
}

/// 百分号解码。只用于路径，遇到非 UTF-8 直接判非法（宁可 404 也不要乱猜）。
fn decode_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let s = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// 把 URL 路径变成安全的相对路径；含 `..`、绝对段、NUL 的直接拒绝。
fn safe_rel(path: &str) -> Option<PathBuf> {
    let decoded = decode_path(path)?;
    if decoded.contains('\0') {
        return None;
    }
    let mut rel = PathBuf::new();
    for comp in Path::new(decoded.trim_start_matches('/')).components() {
        match comp {
            Component::Normal(seg) => rel.push(seg),
            Component::CurDir => {}
            // ParentDir / RootDir / Prefix 都是越界信号
            _ => return None,
        }
    }
    Some(rel)
}

fn mime_of(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

/// 文件元信息 → (ETag, Last-Modified)
fn validators(meta: &std::fs::Metadata) -> (String, Option<http::HeaderValue>) {
    use std::time::UNIX_EPOCH;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .unwrap_or_default();
    let etag = format!("\"{:x}-{:x}\"", mtime.as_nanos(), meta.len());
    let lm = httpdate(mtime.as_secs());
    (etag, lm.and_then(|s| HeaderValue::from_str(&s).ok()))
}

/// RFC 7231 IMF-fixdate（只算 UTC，不引 chrono）
fn httpdate(secs: u64) -> Option<String> {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // 1970-01-01 是周四，DAYS 从周四开始排
    let wd = DAYS[(days % 7) as usize];
    // 民用历法转换（Howard Hinnant 的 days_from_civil 反函数）
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mo <= 2 { y + 1 } else { y };
    Some(format!(
        "{wd}, {d:02} {} {year} {h:02}:{m:02}:{s:02} GMT",
        MONTHS[(mo - 1) as usize]
    ))
}

fn build(
    status: StatusCode,
    body: Vec<u8>,
    mime: &str,
    etag: Option<String>,
    lm: Option<HeaderValue>,
    site: &SiteConfig,
) -> Response<ProxyBody> {
    let len = body.len();
    let mut b = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, mime)
        .header("x-content-type-options", "nosniff");
    if let Some(e) = etag {
        b = b.header(ETAG, e);
    }
    if let Some(v) = lm {
        b = b.header(LAST_MODIFIED, v);
    }
    let cc = if site.cache_secs == 0 {
        "no-cache".to_string()
    } else if site.immutable {
        format!("public, max-age={}, immutable", site.cache_secs)
    } else {
        format!("public, max-age={}", site.cache_secs)
    };
    b = b.header(CACHE_CONTROL, cc);
    for (k, v) in &site.headers {
        if let (Ok(n), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            b = b.header(n, val);
        }
    }
    let body = if status == StatusCode::NOT_MODIFIED {
        Vec::new()
    } else {
        body
    };
    b.header(http::header::CONTENT_LENGTH, len.to_string())
        .body(
            Full::new(bytes::Bytes::from(body))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(bytes::Bytes::new()).map_err(|n| match n {}).boxed())
                .expect("空响应不可能构造失败")
        })
}

/// 某个站点命中的文件；目录会往下找 index。
/// 返回 None 表示"没有这个文件"，交给上层决定 404 还是 SPA 回退。
async fn resolve_file(root: &Path, rel: &Path, site: &SiteConfig) -> Option<(PathBuf, bool)> {
    let mut full = root.join(rel);
    if full.is_dir() {
        for name in &site.index {
            let cand = full.join(name);
            if cand.is_file() {
                return Some((cand, false));
            }
        }
        return None;
    }
    if full.is_file() {
        // 目录请求没有尾斜杠时补一个，否则相对链接会挂
        return Some((full, false));
    }
    // 大小写在这里不做兼容：Linux 上"看起来有、其实没有"比 404 更难查
    full = full.to_path_buf();
    let _ = &full;
    None
}

/// 在某个站点里找文件。`None` = 没有这个文件（host 是否归属由 `pick` 决定）。
pub async fn serve_site(
    site: &SiteConfig,
    path: &str,
    method: &Method,
    base_dir: &Path,
) -> Option<Response<ProxyBody>> {
    if method != Method::GET && method != Method::HEAD {
        return Some(
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(http::header::ALLOW, "GET, HEAD")
                .body(Full::new(bytes::Bytes::new()).map_err(|n| match n {}).boxed())
                .ok()?,
        );
    }

    let root = crate::config::resolve_one(&site.root, base_dir);
    let rel = safe_rel(path)?;
    let found = resolve_file(&root, &rel, site).await;

    let mut resolved = found;
    if resolved.is_none() && site.spa && !path.contains('.') {
        // SPA 路由：没有扩展名就当它是前端路由，回首页
        for name in &site.index {
            let cand = root.join(name);
            if cand.is_file() {
                resolved = Some((cand, false));
                break;
            }
        }
    }

    let Some((file, _)) = resolved else {
        return None;
    };

    // 软链接穿出根目录：canonicalize 后的前缀必须还是根目录
    let canon_root = tokio::fs::canonicalize(&root).await.ok();
    let canon = tokio::fs::canonicalize(&file).await.ok()?;
    if let Some(cr) = canon_root {
        if !canon.starts_with(&cr) {
            return None;
        }
    }

    let meta = tokio::fs::metadata(&canon).await.ok()?;
    let (etag, lm) = validators(&meta);
    let mime = mime_of(&canon);

    let body = if method == Method::HEAD {
        Vec::new()
    } else {
        tokio::fs::read(&canon).await.ok()?
    };
    let mut resp = build(StatusCode::OK, body, mime, Some(etag), lm, site);
    if method == Method::HEAD {
        resp.headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_str(&meta.len().to_string()).ok()?);
    }
    Some(resp)
}

/// 命中站点但没文件 → 该站点自己的 404（不要再往上游转，否则掩盖配置错误）
pub fn not_found() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(
            Full::new(bytes::Bytes::from_static(b"404 site file not found"))
                .map_err(|n| match n {})
                .boxed(),
        )
        .expect("404 响应构造失败")
}

/// 条件请求：If-None-Match / If-Modified-Since 命中就 304。
pub fn is_not_modified(req_etag: Option<&str>, resp: &Response<ProxyBody>) -> bool {
    let Some(tag) = req_etag else { return false };
    resp.headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|etag| etag == tag || tag.trim() == "*")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(hosts: &[&str]) -> SiteConfig {
        SiteConfig {
            name: "t".into(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            root: "public".into(),
            ..Default::default()
        }
    }

    #[test]
    fn exact_host_beats_wildcard() {
        let exact = site(&["a.example.com"]);
        let wild = site(&["*"]);
        let sites = vec![wild.clone(), exact.clone()];
        assert_eq!(pick(&sites, "a.example.com").unwrap().hosts[0], "a.example.com");
        assert_eq!(pick(&sites, "b.example.com").unwrap().hosts[0], "*");
    }

    #[test]
    fn host_match_ignores_port_and_case() {
        let s = site(&["Example.COM"]);
        assert!(pick(&[s], "example.com:8080").is_some());
        assert!(pick(&[site(&["[::1]"])], "[::1]:443").is_some());
    }

    #[test]
    fn traversal_is_rejected() {
        for p in ["/../etc/passwd", "/a/../../b", "/%2e%2e/secret", "/a/%2E%2E/b"] {
            assert!(safe_rel(p).is_none(), "{p} 应该被拒绝");
        }
        assert!(safe_rel("/a/b.txt").is_some());
        assert_eq!(safe_rel("/a//b").unwrap(), PathBuf::from("a/b"));
    }

    #[test]
    fn decoded_path_is_used_not_raw() {
        // %20 要解码成空格，%2F 变成分隔符；只看原始串会漏掉编码过的越界
        assert_eq!(safe_rel("/a%20b").unwrap(), PathBuf::from("a b"));
        assert!(safe_rel("/%2f..%2fetc").is_none());
    }

    #[test]
    fn mime_by_extension() {
        assert!(mime_of(Path::new("a.html")).starts_with("text/html"));
        assert_eq!(mime_of(Path::new("x.unknown")), "application/octet-stream");
    }

    #[test]
    fn httpdate_formats_known_instant() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(
            httpdate(1_704_067_200).unwrap(),
            "Mon, 01 Jan 2024 00:00:00 GMT"
        );
    }
}
