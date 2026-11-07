//! 路由决策。
//!
//! 匹配规则（确定性、可预测，便于排查）：
//! 1. 按配置里的顺序逐条尝试，**先命中先用**；
//! 2. host 支持 `*` / `*.example.com` / 精确匹配（忽略大小写与端口）；
//! 3. path_prefix 为前缀匹配，`/` 表示全部；
//! 4. 全不命中则走 `server.default_upstream`。
//!
//! [扩展点 E2] `UpstreamSelector`：默认实现是 `SingleUpstream`（直取 route.upstream）。
//! 后续要做加权轮询/一致性哈希/健康检查摘除，只需新增实现并在 `Router` 里换掉即可，
//! 决策结果结构（`Decision`）不用动。

use crate::config::{Config, RouteConfig};
use http::Method;

/// 一次请求的可匹配信息。
pub struct RequestInfo<'a> {
    /// 当前匹配策略不看 method，但加权/灰度类选择器会用到，故保留在契约里
    #[allow(dead_code)]
    pub method: &'a Method,
    pub host: Option<&'a str>,
    pub path: &'a str,
}

/// 最终转发参数（已解析为本请求的确定值）。
#[derive(Debug, Clone)]
pub struct Decision {
    /// 命中的路由名；None 表示走默认上游
    pub route_name: Option<String>,
    pub upstream: String,
    pub strip_prefix: bool,
    pub path_prefix: String,
    pub rewrite_host: bool,
    pub timeout_ms: u64,
}

/// [扩展点 E2] 上游选择策略。
pub trait UpstreamSelector: Send + Sync {
    fn select(&self, route: &RouteConfig, req: &RequestInfo<'_>) -> String;
}

/// 默认策略：一条路由对应一个固定上游。
pub struct SingleUpstream;

impl UpstreamSelector for SingleUpstream {
    fn select(&self, route: &RouteConfig, _req: &RequestInfo<'_>) -> String {
        route.upstream.clone()
    }
}

pub fn resolve(cfg: &Config, req: &RequestInfo<'_>, selector: &dyn UpstreamSelector) -> Decision {
    let fallback_timeout = cfg.server.request_timeout_ms;

    for route in &cfg.routes {
        if !host_matches(&route.host, req.host) {
            continue;
        }
        if !path_matches(&route.path_prefix, req.path) {
            continue;
        }
        return Decision {
            route_name: Some(route.name.clone()),
            upstream: selector.select(route, req),
            strip_prefix: route.strip_prefix,
            path_prefix: route.path_prefix.clone(),
            rewrite_host: route.rewrite_host,
            timeout_ms: route.timeout_ms.unwrap_or(fallback_timeout),
        };
    }

    Decision {
        route_name: None,
        upstream: cfg.server.default_upstream.clone(),
        strip_prefix: false,
        path_prefix: String::new(),
        rewrite_host: true,
        timeout_ms: fallback_timeout,
    }
}

pub fn host_matches(pattern: &str, host: Option<&str>) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let Some(host) = host else {
        return false;
    };
    let host = normalize_host(host);
    let pattern = pattern.to_ascii_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // *.example.com 命中 a.example.com、a.b.example.com，不命中 example.com 本身
        return host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    host == pattern
}

/// 去掉端口、转小写。
pub fn normalize_host(raw: &str) -> String {
    let raw = raw.trim().to_ascii_lowercase();
    // IPv6 形如 [::1]:8080
    if raw.starts_with('[') {
        if let Some(end) = raw.find(']') {
            return raw[..=end].to_string();
        }
        return raw;
    }
    match raw.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => raw,
    }
}

pub fn path_matches(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    // /api 命中 /api、/api/x，不命中 /apix
    matches!(path.as_bytes().get(prefix.len()), None | Some(b'/') | Some(b'?'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteConfig;

    fn cfg_with_default(up: &str) -> Config {
        let mut c = Config::default();
        c.server.default_upstream = up.to_string();
        c
    }

    #[test]
    fn host_patterns() {
        assert!(host_matches("*", Some("a.b.c")));
        assert!(host_matches("*", None));
        assert!(host_matches("api.local", Some("API.local:8080")));
        assert!(!host_matches("api.local", Some("x.local")));
        assert!(host_matches("*.example.com", Some("a.example.com")));
        assert!(host_matches("*.example.com", Some("a.b.example.com")));
        assert!(!host_matches("*.example.com", Some("example.com")));
    }

    #[test]
    fn prefix_boundaries() {
        assert!(path_matches("/", "/anything"));
        assert!(path_matches("/api", "/api"));
        assert!(path_matches("/api", "/api/v1"));
        assert!(!path_matches("/api", "/apix"));
    }

    #[test]
    fn first_match_wins_and_fallback() {
        let mut cfg = cfg_with_default("http://fallback:1");
        cfg.routes
            .push(RouteConfig::new("api", "*", "/api", "http://api:2"));
        let sel = SingleUpstream;

        let d = resolve(
            &cfg,
            &RequestInfo {
                method: &Method::GET,
                host: Some("x"),
                path: "/api/v1",
            },
            &sel,
        );
        assert_eq!(d.route_name.as_deref(), Some("api"));
        assert_eq!(d.upstream, "http://api:2");

        let d = resolve(
            &cfg,
            &RequestInfo {
                method: &Method::GET,
                host: Some("x"),
                path: "/other",
            },
            &sel,
        );
        assert!(d.route_name.is_none());
        assert_eq!(d.upstream, "http://fallback:1");
    }

    #[test]
    fn route_timeout_overrides_server() {
        let mut cfg = cfg_with_default("http://fallback:1");
        let mut r = RouteConfig::new("slow", "*", "/slow", "http://slow:3");
        r.timeout_ms = Some(1234);
        cfg.routes.push(r);
        let d = resolve(
            &cfg,
            &RequestInfo {
                method: &Method::GET,
                host: None,
                path: "/slow/x",
            },
            &SingleUpstream,
        );
        assert_eq!(d.timeout_ms, 1234);
    }
}
