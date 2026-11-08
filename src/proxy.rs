//! 转发核心。
//!
//! 一条请求的处理链（顺序不能乱）：
//!   accept 限流 → DoS 体积闸门 → WAF（含 body 检查）→ 缓存命中 → 路由/后端选择
//!   → 请求头改写 → 上游转发（h1 / h2 / WS 隧道）→ 响应头改写 + 帧策略 → 计量 → 缓存写入
//!
//! 几个原则：
//! - 请求体**默认流式透传**；只有 Content-Length 已知且 ≤ max_inspect_bytes 时才缓冲给 WAF 看。
//! - 缓存只在「GET/HEAD + 可缓存扩展名 + 响应体足够小」时生效，且必带 `x-optical-cache` 标记。
//! - h2 入站就用 h2 出站（gRPC 依赖它保 trailers），h1 入站走 h1，不做版本篡改。

use crate::cache::is_cacheable_path;
use crate::config::{Config, HeaderAction, HeaderPhase, HeaderRule, RouteConfig};
use crate::route::{resolve, Decision, RequestInfo, SingleUpstream};
use crate::state::AppState;
use crate::waf::{self, RequestView};
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, CONNECTION, CONTENT_TYPE, HOST, SERVER};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;
pub type HttpClient = Client<HttpConnector, ProxyBody>;

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Clone)]
pub struct Clients {
    h1: HttpClient,
    h2: HttpClient,
}

impl Clients {
    pub fn new() -> Self {
        Self {
            h1: build_client(false),
            h2: build_client(true),
        }
    }
}

impl Default for Clients {
    fn default() -> Self {
        Self::new()
    }
}

fn build_client(http2_only: bool) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    connector.set_keepalive(Some(Duration::from_secs(30)));
    let mut b = Client::builder(TokioExecutor::new());
    b.pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(32);
    if http2_only {
        b.http2_only(true);
    }
    b.build(connector)
}

/// 网关面 accept 循环。
pub async fn serve(state: Arc<AppState>, listener: TcpListener) -> anyhow::Result<()> {
    serve_with_scheme(state, listener, "http").await
}

pub async fn serve_with_scheme(
    state: Arc<AppState>,
    listener: TcpListener,
    scheme: &'static str,
) -> anyhow::Result<()> {
    let clients = Clients::new();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept 失败");
                continue;
            }
        };

        // DoS：单 IP 并发 + 新建速率双闸门，超限直接关连接（不回响应，省带宽）
        let (max_active, max_per_sec) = state.config_for_limits();
        let Some(guard) = state.try_acquire_conn(peer.ip(), max_active, max_per_sec) else {
            tracing::warn!(%peer, "单 IP 连接数/速率超限，拒绝");
            drop(stream);
            continue;
        };

        let io = TokioIo::new(stream);
        let state = state.clone();
        let clients = clients.clone();

        tokio::spawn(async move {
            let builder = auto::Builder::new(TokioExecutor::new());
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                let clients = clients.clone();
                async move { Ok::<_, Infallible>(handle(req, state, clients, peer, scheme).await) }
            });
            if let Err(err) = builder.serve_connection_with_upgrades(io, svc).await {
                tracing::debug!(%peer, error = %err, "连接结束");
            }
            drop(guard);
        });
    }
}

/// 单请求处理。
pub async fn handle(
    mut req: Request<Incoming>,
    state: Arc<AppState>,
    clients: Clients,
    peer: std::net::SocketAddr,
    scheme: &str,
) -> Response<ProxyBody> {
    let started = Instant::now();
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    let cfg = state.snapshot().await;

    let client_ip = peer.ip();
    let ip_str = client_ip.to_string();

    // WS 必须在消费 request 之前把 upgrade future 取出来，hyper 只允许这一次
    let ws_upgrade = if is_websocket_upgrade(req.headers()) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let (mut parts, incoming) = req.into_parts();
    let original_host = parts
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_owned);
    let ua = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // ---- IP 黑白名单：数据面最前面的闸 ----
    // 放在这里是为了"被拒的请求什么都不发生"：不进 WAF、不选路、不占后端连接，
    // 但要留一条审计——谁被挡了、被哪条规则挡的，事后必须能查。
    // 管理面不走这条路径，所以再狠的规则也不会把人锁在控制台外面。
    if cfg.ip_filter.enabled {
        let decision = state.ip_check(&cfg, client_ip);
        if decision.action == crate::ipfilter::IpAction::Deny {
            state.metrics.ip_blocks.fetch_add(1, Ordering::Relaxed);
            let detail = match &decision.rule {
                Some(rule) => format!(
                    "命中 {rule}{}",
                    if decision.from.is_empty() {
                        String::new()
                    } else {
                        format!("（来自 {}）", decision.from)
                    }
                ),
                None => "名单未命中，按默认策略拒绝".to_string(),
            };
            state.audit.push(
                &cfg.storage,
                crate::storage::AuditEntry {
                    ts_ms: crate::storage::now_ms(),
                    kind: "ip.block".into(),
                    detail,
                    identity: ip_str.clone(),
                    path: path.clone(),
                    rule: decision.rule.clone().unwrap_or_else(|| "ip-filter".into()),
                },
            );
            let status = http::StatusCode::from_u16(state.ip_filter.status_code())
                .unwrap_or(http::StatusCode::FORBIDDEN);
            return error_response(
                &state,
                &cfg,
                status,
                &format!("来源地址 {ip_str} 被访问控制规则拒绝"),
                decision.rule.as_deref(),
            );
        }
    }

    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let content_length = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    // 入向带宽 = 请求头字节（近似）+ 请求体字节；只算 Content-Length 会让 GET 永远是 0
    let header_bytes: usize = parts
        .headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
        .sum();
    let request_line_bytes = parts.uri.path().len() + parts.uri.query().map(|q| q.len() + 1).unwrap_or(0) + 16;
    state.metrics.bytes_in.fetch_add(
        (content_length + header_bytes + request_line_bytes) as u64,
        Ordering::Relaxed,
    );

    let is_ws = ws_upgrade.is_some();
    let is_grpc = content_type.starts_with("application/grpc");

    // ---- 自定义规则：评估一次，后面各个阶段按需取动作 ----
    // 事实结构借了 parts.headers，所以必须在一个独立作用域里用完即弃，
    // 否则后面改写请求头时借用检查直接拦下来。
    let host_str = original_host.clone().unwrap_or_default();
    let method_str = parts.method.as_str().to_string();
    let query_str = query.clone().unwrap_or_default();
    let rule_hit = {
        let facts = crate::rules::ReqFacts {
            host: &host_str,
            path: &path,
            query: &query_str,
            method: &method_str,
            scheme,
            client_ip: &ip_str,
            headers: &parts.headers,
        };
        crate::rules::resolve(&cfg.rules, &facts)
    };
    // 命中的自定义规则要计进分析里那份「规则」维度。
    // 不计的话，这一栏永远只有内置的 dos-body-size —— 用户自己写的规则
    // 明明在改行为，却在流量分析里一条都看不到。
    state.record_rule_hits(&rule_hit.hit);
    let vars = crate::rules::Vars {
        host: &host_str,
        path: &path,
        query: &query_str,
        method: &method_str,
    };
    let act = &rule_hit.actions;

    // ---- DoS 体积闸门（读 body 之前就拦）----
    if cfg.waf.enabled && cfg.waf.dos.enabled && cfg.waf.dos.max_body_bytes > 0
        && content_length > cfg.waf.dos.max_body_bytes
    {
        state.metrics.waf_blocks.fetch_add(1, Ordering::Relaxed);
        state.record_rule_hit("dos-body-size");
        state.record_profile(&ua, &ip_str, 413);
        state.audit.push(
            &cfg.storage,
            crate::storage::AuditEntry {
                ts_ms: crate::storage::now_ms(),
                kind: "waf.block".into(),
                detail: format!("Content-Length {content_length} 超过上限 {}", cfg.waf.dos.max_body_bytes),
                identity: ip_str.clone(),
                path: path.clone(),
                rule: "dos-body-size".into(),
            },
        );
        return error_response(&state, &cfg, StatusCode::PAYLOAD_TOO_LARGE, "请求体过大，已被 Optical 拦截", Some("dos-body-size"));
    }

    // ---- body 检查窗口 ----
    let inspect_limit = cfg.server.max_inspect_bytes;
    let can_buffer = content_length > 0 && content_length <= inspect_limit && !is_ws;
    let (body_bytes, forward_body): (Option<Bytes>, ProxyBody) = if can_buffer {
        match http_body_util::Limited::new(incoming, inspect_limit).collect().await {
            Ok(c) => {
                let b = c.to_bytes();
                let body = Full::new(b.clone()).map_err(|never| match never {}).boxed();
                (Some(b), body)
            }
            Err(_) => {
                state.metrics.errors.fetch_add(1, Ordering::Relaxed);
                return error_response(&state, &cfg, StatusCode::BAD_REQUEST, "请求体读取失败", None);
            }
        }
    } else {
        if content_length > inspect_limit && inspect_limit != 0 {
            state.metrics.waf_skipped.fetch_add(1, Ordering::Relaxed);
        }
        (None, incoming.boxed())
    };

    // ---- WAF ----
    if cfg.waf.enabled {
        let identity = jwt_identity(&parts.headers).unwrap_or_else(|| ip_str.clone());
        let view = RequestView {
            method: &parts.method,
            path: &path,
            query: query.as_deref(),
            headers: &parts.headers,
            client_ip,
            body: body_bytes.as_deref(),
            content_type: &content_type,
            ua: &ua,
            identity: &identity,
        };
        let result = waf::inspect(&cfg.waf, &state.bola, &view);

        if result.hit() {
            state.metrics.waf_hits.fetch_add(1, Ordering::Relaxed);
            state.record_findings(&result.findings);
            tracing::trace!(path = %path, body = result.body_inspected, "WAF 检查完成");
        }
        if result.blocked() {
            state.metrics.waf_blocks.fetch_add(1, Ordering::Relaxed);
            let detail = result
                .findings
                .iter()
                .map(|f| format!("{}:{}", f.rule, f.detail))
                .collect::<Vec<_>>()
                .join("; ");
            state.audit.push(
                &cfg.storage,
                crate::storage::AuditEntry {
                    ts_ms: crate::storage::now_ms(),
                    kind: "waf.block".into(),
                    detail,
                    identity: ip_str.clone(),
                    path: path.clone(),
                    rule: result.top_rule.unwrap_or("waf").into(),
                },
            );
            state.record_profile(&ua, &ip_str, 403);
            return error_response(
                &state,
                &cfg,
                waf::block_status(result.top_rule),
                &format!(
                    "请求被 WAF 拦截（{}，评分 {}）",
                    result.top_rule.unwrap_or("unknown"),
                    result.score
                ),
                result.top_rule,
            );
        }
        if result.verdict == waf::Verdict::Monitor && result.hit() {
            tracing::info!(path = %path, score = result.score, "WAF 监控模式命中（未拦截）");
        }
    }

    // ---- 规则里的"短路"动作：在选路之前就该给结论 ----
    // 放在 WAF 之后是故意的：安全策略先过，规则不能用来绕开 WAF。
    if let Some(tk) = &act.token_auth {
        if !tk.name.is_empty() {
            let got = if tk.from_query {
                query
                    .as_deref()
                    .unwrap_or("")
                    .split('&')
                    .find_map(|kv| {
                        let mut p = kv.splitn(2, '=');
                        (p.next().unwrap_or("") == tk.name).then(|| p.next().unwrap_or("").to_string())
                    })
                    .unwrap_or_default()
            } else {
                parts
                    .headers
                    .get(tk.name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string()
            };
            if got != tk.value {
                state.record_profile(&ua, &ip_str, 401);
                return error_response(&state, &cfg, StatusCode::UNAUTHORIZED, "缺少或错误的访问令牌", Some("rule-token"));
            }
        }
    }

    if act.force_https == Some(true) && scheme == "http" {
        let host = original_host.as_deref().unwrap_or("");
        let uri = match &query {
            Some(q) => format!("{}?{q}", path),
            None => path.clone(),
        };
        state.record_profile(&ua, &ip_str, 301);
        return redirect_response(&state, &cfg, 301, &format!("https://{host}{uri}"));
    }

    if let Some(r) = &act.redirect {
        if !r.to.is_empty() {
            let target = crate::rules::expand(&r.to, &vars);
            state.record_profile(&ua, &ip_str, r.status);
            return redirect_response(&state, &cfg, r.status.max(300), &target);
        }
    }

    if let Some(c) = &act.custom_response {
        state.record_profile(&ua, &ip_str, c.status);
        let ct = if c.content_type.is_empty() {
            "text/html; charset=utf-8".to_string()
        } else {
            c.content_type.clone()
        };
        let mut resp = Response::builder()
            .status(StatusCode::from_u16(c.status).unwrap_or(StatusCode::OK))
            .header(CONTENT_TYPE, ct)
            .header(http::header::CACHE_CONTROL, "no-store")
            .body(
                Full::new(Bytes::from(c.body.clone()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap_or_else(|_| {
                error_response(&state, &cfg, StatusCode::INTERNAL_SERVER_ERROR, "自定义响应构造失败", None)
            });
        apply_rule_headers(&mut resp, &rule_hit);
        return resp;
    }

    if let Some(limit) = act.max_upload_bytes {
        if content_length as u64 > limit {
            state.record_profile(&ua, &ip_str, 413);
            return error_response(
                &state,
                &cfg,
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("请求体超过规则限制（{limit} 字节）"),
                Some("rule-max-upload"),
            );
        }
    }

    if is_ws && act.ws == Some(false) {
        state.record_profile(&ua, &ip_str, 403);
        return error_response(&state, &cfg, StatusCode::FORBIDDEN, "该路径不允许 WebSocket 升级", Some("rule-ws"));
    }

    // ---- 动态项目：CORS 预检在选路之前就给结论 ----
    // 预检请求不带凭据也不该进 WAF 打分，浏览器只看 OPTIONS 的响应头。
    let cors_app = if cfg.apps.is_empty() {
        None
    } else {
        crate::apps::pick(&cfg.apps, &host_str, &path)
    };
    let origin = parts
        .headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if let Some(app) = cors_app {
        if app.cors.enabled && parts.method == Method::OPTIONS && !origin.is_empty() {
            state.record_hit(
                &ua,
                &ip_str,
                204,
                crate::stats::ReqDims {
                    route: &format!("app:{}", app.name),
                    backend: "",
                    host: &host_str,
                },
                0,
            );
            return cors_preflight(&app.cors, &origin, &parts.headers);
        }
    }

    // ---- 全局 HTTP → HTTPS ----
    // 放在规则之后、选路之前：规则里的 force_https 可以按路径精细化，
    // 这里是"整个网关都别用明文"的粗开关，两者不冲突。
    if cfg.tls.enabled && cfg.tls.http_redirect && scheme == "http" {
        let host = original_host.as_deref().unwrap_or("");
        let uri = match &query {
            Some(q) => format!("{}?{q}", path),
            None => path.clone(),
        };
        state.record_profile(&ua, &ip_str, 301);
        return redirect_response(&state, &cfg, 301, &format!("https://{host}{uri}"));
    }

    // ---- 静态站点 ----
    // host 命中站点就由网关自己吐文件，不再往下转发；
    // 没命中（或没这个文件）才继续走 routes，两条路互不干扰。
    if !cfg.sites.is_empty() && !is_ws {
        if let Some(site) = crate::sites::pick(&cfg.sites, &host_str) {
            let site_name = site.display_name().to_string();
            match crate::sites::serve_site(site, &path, &parts.method, state.base_dir()).await {
                Some(mut resp) => {
                    // 条件请求：ETag 命中直接 304，别再读一遍盘
                    let inm = parts
                        .headers
                        .get(http::header::IF_NONE_MATCH)
                        .and_then(|v| v.to_str().ok());
                    if crate::sites::is_not_modified(inm, &resp) {
                        let keep: Vec<(http::HeaderName, http::HeaderValue)> = resp
                            .headers()
                            .iter()
                            .filter(|(k, _)| {
                                *k == http::header::ETAG
                                    || *k == http::header::CACHE_CONTROL
                                    || *k == http::header::LAST_MODIFIED
                            })
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        let mut not_modified = Response::builder()
                            .status(StatusCode::NOT_MODIFIED)
                            .body(
                                Full::new(Bytes::new())
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
                            .unwrap_or_else(|_| {
                                Response::new(
                                    Full::new(Bytes::new())
                                        .map_err(|never| match never {})
                                        .boxed(),
                                )
                            });
                        for (k, v) in keep {
                            not_modified.headers_mut().insert(k, v);
                        }
                        resp = not_modified;
                    }
                    state.record_hit(
                        &ua,
                        &ip_str,
                        resp.status().as_u16(),
                        crate::stats::ReqDims {
                            route: &format!("site:{site_name}"),
                            backend: "",
                            host: &host_str,
                        },
                        0,
                    );
                    return resp;
                }
                None => {
                    // 没这个文件就继续往下走（等价 nginx 的 try_files $uri @backend）。
                    // 同一域名常常既要发静态文件、又要挂 /api 或动态项目：
                    // 这里若直接 404，应用就永远轮不到，只能把站点和应用拆去不同域名。
                }
            }
        }
    }

    // ---- 路由 ----
    let info = RequestInfo {
        method: &parts.method,
        host: original_host.as_deref(),
        path: &path,
    };
    let mut decision = resolve(&cfg, &info, &SingleUpstream);
    let route: Option<RouteConfig> = decision
        .route_name
        .as_deref()
        .and_then(|n| cfg.routes.iter().find(|r| r.name == n))
        .cloned();

    // 选路：单后端 / 分组，策略优先级 路由 > 分组 > 全局。
    // 不管哪种，pick 都只在目标范围内挑，绝不跨组。
    let mut backend_name: Option<String> = None;
    let mut lb_used: Option<&'static str> = None;
    if let Some(r) = &route {
        if let Some(target) = cfg.route_target(r) {
            let strategy = cfg.resolve_lb(Some(r), if target.is_group() { Some(target.name()) } else { None });
            if let Some(p) = state.backends.pick(&cfg, target, strategy, Some(client_ip)) {
                decision.upstream = p.backend.url.clone();
                if p.backend.timeout_ms > 0 {
                    decision.timeout_ms = p.backend.timeout_ms;
                }
                backend_name = Some(p.backend.name.clone());
                lb_used = Some(p.strategy.label());
                if p.degraded {
                    tracing::warn!(route = %r.name, backend = %p.backend.name, "分组内无健康成员，降级转发");
                }
            } else {
                tracing::warn!(route = %r.name, target = target.name(), "目标没有可用后端，回退默认上游");
            }
        }
    }

    // ---- 缓存查找 ----
    let enc = parts
        .headers
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    // 规则可以自定义 cache key（比如按客户端分组、忽略某个查询参数）
    let cache_key = match &act.cache_key {
        Some(tpl) if !tpl.is_empty() => {
            format!("rule:{}#{enc}", crate::rules::expand(tpl, &vars))
        }
        _ => format!(
            "{}#{}",
            crate::cache::ResponseCache::key(&parts.method, original_host.as_deref(), &path, query.as_deref()),
            enc
        ),
    };
    let cache_ok = act.cache_ttl_secs != Some(0)
        && (parts.method == Method::GET || parts.method == Method::HEAD)
        && cfg.cache_allowed(route.as_ref())
        && is_cacheable_path(&path, &cfg.cache.cacheable_exts);

    if cache_ok {
        if let Some((status, headers, body)) = state.cache.lookup(&cache_key) {
            state.metrics.cache_hit.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .bytes_out
                .fetch_add(body.len() as u64, Ordering::Relaxed);
            let mut hm = headers;
            hm.insert(HeaderName::from_static("x-optical-cache"), HeaderValue::from_static("HIT"));
            if let Ok(v) = HeaderValue::from_str(decision.route_name.as_deref().unwrap_or("default")) {
                hm.insert(HeaderName::from_static("x-optical-route"), v);
            }
            state.record_hit(
                &ua,
                &ip_str,
                status.as_u16(),
                crate::stats::ReqDims {
                    route: decision.route_name.as_deref().unwrap_or(""),
                    backend: "",
                    host: original_host.as_deref().unwrap_or(""),
                },
                0,
            );
            let mut hit_resp = Response::builder()
                .status(status)
                .body(Full::new(body).map_err(|never| match never {}).boxed())
                .map(|mut r| {
                    *r.headers_mut() = hm;
                    r
                })
                .unwrap_or_else(|_| error_response(&state, &cfg, StatusCode::INTERNAL_SERVER_ERROR, "缓存响应构造失败", None));
            // 缓存命中也要带 CORS：否则预检过了、真实响应却没有 Allow-Origin，前端照旧报错
            if let Some(app) = cors_app {
                apply_cors(&app.cors, &origin, hit_resp.headers_mut());
            }
            return hit_resp;
        }
        state.metrics.cache_miss.fetch_add(1, Ordering::Relaxed);
    }

    // 动态项目：进程没在跑时给 503，而不是让它去 connect 一个没人监听的端口。
    // 502 会被当成"网关坏了"，503 + 明确文案才说明是"应用停了"。
    if let Some(rn) = decision.route_name.as_deref() {
        if let Some(app_name) = rn.strip_prefix("app:") {
            if !crate::apps::is_running(&state.apps, app_name).await {
                state.record_hit(
                    &ua,
                    &ip_str,
                    503,
                    crate::stats::ReqDims {
                        route: rn,
                        backend: "",
                        host: original_host.as_deref().unwrap_or(""),
                    },
                    0,
                );
                return error_response(
                    &state,
                    &cfg,
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("项目 {app_name} 未启动，请在控制台「应用」页启动"),
                    Some("app-stopped"),
                );
            }
        }
    }

    if parts.method == Method::CONNECT {
        return error_response(&state, &cfg, StatusCode::METHOD_NOT_ALLOWED, "不支持 CONNECT 隧道", None);
    }

    // ---- 上游 URI ----
    let Ok(base) = decision.upstream.parse::<Uri>() else {
        return fail(&state, &cfg, &ua, &ip_str, StatusCode::BAD_GATEWAY, "上游地址解析失败");
    };
    let up_scheme = base.scheme_str().unwrap_or("http").to_string();
    let authority = match base.authority() {
        Some(a) => a.as_str().to_string(),
        None => return fail(&state, &cfg, &ua, &ip_str, StatusCode::BAD_GATEWAY, "上游缺少 host"),
    };

    let mut new_path = path.clone();
    if decision.strip_prefix
        && !decision.path_prefix.is_empty()
        && decision.path_prefix != "/"
        && new_path.starts_with(&decision.path_prefix)
    {
        new_path = new_path[decision.path_prefix.len()..].to_string();
        if new_path.is_empty() {
            new_path = "/".to_string();
        } else if !new_path.starts_with('/') {
            new_path = format!("/{new_path}");
        }
    }
    let base_path = base.path().trim_end_matches('/');
    let joined = format!("{base_path}{new_path}");
    // 规则里的回源 URL 重写优先级最高，直接替换整段 path?query
    let path_and_query = match &act.upstream_url_rewrite {
        Some(tpl) if !tpl.is_empty() => {
            let mut p = crate::rules::expand(tpl, &vars);
            if !p.starts_with('/') {
                p = format!("/{p}");
            }
            p
        }
        _ => match &query {
            Some(q) => format!("{joined}?{q}"),
            None => joined,
        },
    };

    // ---- WebSocket ----
    if let Some(on_up) = ws_upgrade {
        let meta = TunnelMeta {
            authority: &authority,
            path_and_query: &path_and_query,
            ua: &ua,
            ip: &ip_str,
        };
        return websocket_tunnel(parts, on_up, state.clone(), &cfg, meta).await;
    }

    let uri = match Uri::builder()
        .scheme(up_scheme.as_str())
        .authority(authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()
    {
        Ok(u) => u,
        Err(e) => {
            return fail(&state, &cfg, &ua, &ip_str, StatusCode::BAD_GATEWAY, format!("构造上游 URI 失败: {e}"))
        }
    };

    // ---- 请求头 ----
    strip_hop_by_hop(&mut parts.headers, is_grpc);
    apply_header_rules(&cfg, HeaderPhase::Request, &mut parts.headers, &path, original_host.as_deref(), 0);
    if decision.rewrite_host {
        if let Ok(v) = HeaderValue::from_str(&authority) {
            parts.headers.insert(HOST, v);
        }
    }
    // 规则里的 host 头改写盖过上面的默认行为（支持 {host} 模板）
    if let Some(h) = &act.host_rewrite {
        if !h.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&crate::rules::expand(h, &vars)) {
                parts.headers.insert(HOST, v);
            }
        }
    }
    append_forwarded(&mut parts.headers, &peer, original_host.as_deref(), scheme);

    let is_h2 = parts.version == Version::HTTP_2;
    parts.uri = uri;
    parts.version = if is_h2 { Version::HTTP_2 } else { Version::HTTP_11 };
    let upstream_req = Request::from_parts(parts, forward_body);

    let client = if is_h2 { clients.h2 } else { clients.h1 };
    let timeout_ms = act.upstream_timeout_ms.unwrap_or(decision.timeout_ms);
    let timeout = Duration::from_millis(timeout_ms);
    let resp = match tokio::time::timeout(timeout, client.request(upstream_req)).await {
        Err(_) => {
            return fail(&state, &cfg, &ua, &ip_str, StatusCode::GATEWAY_TIMEOUT, format!("上游超时（{} ms）", timeout_ms))
        }
        Ok(Err(e)) => {
            return fail(&state, &cfg, &ua, &ip_str, StatusCode::BAD_GATEWAY, format!("连接上游失败: {e}"))
        }
        Ok(Ok(r)) => r,
    };

    let elapsed = started.elapsed();
    state.record_upstream(elapsed);

    let (mut rparts, rbody) = resp.into_parts();
    let status = rparts.status;
    strip_hop_by_hop(&mut rparts.headers, is_grpc);
    apply_server_header(&cfg, &mut rparts.headers);

    // ---- 帧限制 ----
    if cfg.waf.enabled {
        // 帧策略只打响应头，不参与"规则命中"统计，否则它会永远霸占 Top 榜
        waf::apply_frame_policy(&cfg.waf.frame, &mut rparts.headers);
    }

    // ---- 响应头改写 ----
    apply_header_rules(&cfg, HeaderPhase::Response, &mut rparts.headers, &path, original_host.as_deref(), status.as_u16());
    // 动态项目的 CORS 头（静态站点/纯 API 也可以开，只要是 app 路由）
    if let Some(app) = cors_app {
        apply_cors(&app.cors, &origin, &mut rparts.headers);
    }
    // 规则动作盖在全局配置之上
    if let Some(name) = &act.server_name {
        if let Ok(v) = HeaderValue::from_str(name) {
            rparts.headers.insert(SERVER, v);
        }
    }
    if let Some(secs) = act.browser_ttl_secs {
        if let Ok(v) = HeaderValue::from_str(&format!("public, max-age={secs}")) {
            rparts.headers.insert(http::header::CACHE_CONTROL, v);
        }
    }
    for (k, v) in act.response_headers.iter() {
        if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
            rparts.headers.insert(name, val);
        }
    }
    if !rule_hit.hit.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&rule_hit.hit.join(",")) {
            rparts.headers.insert(HeaderName::from_static("x-optical-rule"), v);
        }
    }
    insert_debug_headers(
        &mut rparts.headers,
        &decision,
        &authority,
        elapsed,
        backend_name.as_deref(),
        lb_used,
    );

    // ---- 缓存写入（只对小响应）----
    let body_len = rparts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let want_cache = cache_ok
        && cfg.cache.cacheable_status.contains(&status.as_u16())
        && body_len > 0
        && body_len <= cfg.cache.max_bytes / 4;

    let body: ProxyBody = if want_cache {
        match rbody.collect().await {
            Ok(c) => {
                let bytes = c.to_bytes();
                let mut stored = rparts.headers.clone();
                stored.remove(http::header::TRANSFER_ENCODING);
                stored.remove(HeaderName::from_static("x-optical-cache"));
                state.cache.store(
                    cache_key,
                    status,
                    stored,
                    bytes.clone(),
                    crate::cache::CachePolicy {
                        ttl: Duration::from_secs(
                            act.cache_ttl_secs.unwrap_or(cfg.cache.ttl_secs).max(1),
                        ),
                        max_bytes: cfg.cache.max_bytes,
                        max_entries: cfg.cache.max_entries,
                    },
                );
                rparts
                    .headers
                    .insert(HeaderName::from_static("x-optical-cache"), HeaderValue::from_static("MISS"));
                state
                    .metrics
                    .bytes_out
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                Full::new(bytes).map_err(|never| match never {}).boxed()
            }
            Err(e) => {
                state.metrics.errors.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(error = %e, "缓存收集失败");
                return error_response(&state, &cfg, StatusCode::BAD_GATEWAY, "上游响应读取失败", None);
            }
        }
    } else {
        rparts
            .headers
            .insert(HeaderName::from_static("x-optical-cache"), HeaderValue::from_static("BYPASS"));
        CountingBody {
            inner: rbody,
            state: state.clone(),
        }
        .boxed()
    };

    // 概览排行榜靠这份维度做"按路由/后端/域名"细分，缺失就没法拆
    state.record_hit(
        &ua,
        &ip_str,
        status.as_u16(),
        crate::stats::ReqDims {
            route: decision.route_name.as_deref().unwrap_or(""),
            backend: backend_name.as_deref().unwrap_or(""),
            host: original_host.as_deref().unwrap_or(""),
        },
        elapsed.as_micros() as u64,
    );

    tracing::debug!(
        peer = %peer,
        route = decision.route_name.as_deref().unwrap_or("default"),
        upstream = %authority,
        %path,
        status = status.as_u16(),
        ms = elapsed.as_millis() as u64,
        "proxied"
    );

    Response::from_parts(rparts, body)
}

/// 流式转发时边转发边计字节，不缓冲。
pub struct CountingBody {
    inner: Incoming,
    state: Arc<AppState>,
}

impl HttpBody for CountingBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(d) = frame.data_ref() {
                    this.state
                        .metrics
                        .bytes_out
                        .fetch_add(d.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// WS 隧道需要的请求上下文（打包传，避免参数列表失控）。
struct TunnelMeta<'a> {
    authority: &'a str,
    path_and_query: &'a str,
    ua: &'a str,
    ip: &'a str,
}

/// WebSocket：手工 http1 握手保留升级头，拿到 101 后双向拷贝。
async fn websocket_tunnel(
    parts: http::request::Parts,
    client_upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    cfg: &Config,
    meta: TunnelMeta<'_>,
) -> Response<ProxyBody> {
    let TunnelMeta { authority, path_and_query, ua, ip } = meta;
    let uri = match Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
    {
        Ok(u) => u,
        Err(e) => return error_response(&state, cfg, StatusCode::BAD_GATEWAY, &format!("WS 上游 URI 非法: {e}"), None),
    };

    let tcp = match TcpStream::connect(authority).await {
        Ok(t) => t,
        Err(e) => {
            return error_response(&state, cfg, StatusCode::BAD_GATEWAY, &format!("WS 连接上游失败: {e}"), Some("ws-connect"))
        }
    };
    let _ = tcp.set_nodelay(true);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await {
        Ok(v) => v,
        Err(e) => {
            return error_response(&state, cfg, StatusCode::BAD_GATEWAY, &format!("WS 握手失败: {e}"), Some("ws-handshake"))
        }
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let mut up_req = Request::builder().method(Method::GET).uri(uri);
    {
        let hm = up_req.headers_mut().expect("builder");
        *hm = parts.headers.clone();
        hm.insert(
            HOST,
            HeaderValue::from_str(authority).unwrap_or(HeaderValue::from_static("localhost")),
        );
    }
    let up_req = match up_req.body(Full::new(Bytes::new())) {
        Ok(r) => r,
        Err(e) => return error_response(&state, cfg, StatusCode::BAD_REQUEST, &format!("WS 请求构造失败: {e}"), None),
    };

    let resp = match tokio::time::timeout(Duration::from_secs(10), sender.send_request(up_req)).await {
        Err(_) => return error_response(&state, cfg, StatusCode::GATEWAY_TIMEOUT, "WS 上游握手超时", Some("ws-timeout")),
        Ok(Err(e)) => {
            return error_response(&state, cfg, StatusCode::BAD_GATEWAY, &format!("WS 上游错误: {e}"), Some("ws-upstream"))
        }
        Ok(Ok(r)) => r,
    };

    let status = resp.status();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        state.metrics.errors.fetch_add(1, Ordering::Relaxed);
        state.record_profile(ua, ip, status.as_u16());
        let headers = resp.headers().clone();
        return Response::builder()
            .status(status)
            .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
            .map(|mut r| {
                *r.headers_mut() = headers;
                r
            })
            .unwrap_or_else(|_| error_response(&state, cfg, StatusCode::BAD_GATEWAY, "WS 上游拒绝升级", None));
    }

    let resp_headers = resp.headers().clone();
    let mut resp = resp;
    let upstream_upgrade = hyper::upgrade::on(&mut resp);
    state.metrics.ws_upgrades.fetch_add(1, Ordering::Relaxed);
    state.record_profile(ua, ip, 101);

    tokio::spawn(async move {
        match (client_upgrade.await, upstream_upgrade.await) {
            (Ok(c), Ok(u)) => {
                let mut c = TokioIo::new(c);
                let mut u = TokioIo::new(u);
                let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
            }
            _ => tracing::debug!("WS 升级失败"),
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
        .map(|mut r| {
            *r.headers_mut() = resp_headers;
            r
        })
        .unwrap_or_else(|_| error_response(&state, cfg, StatusCode::INTERNAL_SERVER_ERROR, "WS 响应构造失败", None))
}

// ---------------- 头处理 ----------------

fn is_websocket_upgrade(h: &http::HeaderMap) -> bool {
    let up = h
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let conn = h
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);
    up && conn
}

/// BOLA 身份：优先用 Bearer token 的 JWT header 段做指纹，避免把不同用户算成同一个人。
fn jwt_identity(h: &http::HeaderMap) -> Option<String> {
    let raw = h.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer "))?;
    let head = token.split('.').next()?;
    Some(format!("jwt:{}", &head[..head.len().min(24)]))
}

/// 统一的 Server 头：空配置 = 删除（不暴露上游版本），非空 = 覆盖。
fn server_header_value(cfg: &Config) -> Option<HeaderValue> {
    let raw = cfg.server.server_header.trim();
    if raw.is_empty() {
        None
    } else {
        HeaderValue::from_str(raw).ok()
    }
}

fn apply_server_header(cfg: &Config, headers: &mut http::HeaderMap) {
    match server_header_value(cfg) {
        Some(v) => {
            headers.insert(SERVER, v);
        }
        None => {
            headers.remove(SERVER);
        }
    }
}

fn strip_hop_by_hop(headers: &mut http::HeaderMap, keep_te_trailers: bool) {
    let extra: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .filter(|t| !t.is_empty() && t != "close" && t != "keep-alive" && t != "upgrade")
        .collect();

    for name in HOP_BY_HOP {
        if keep_te_trailers && name == "te" {
            continue;
        }
        headers.remove(name);
    }
    for name in extra {
        if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(n);
        }
    }
}

fn header_rule_matches(rule: &HeaderRule, path: &str, host: Option<&str>, status: u16) -> bool {
    if !rule.enabled || rule.name.trim().is_empty() {
        return false;
    }
    if !rule.match_path.is_empty() && !path.starts_with(&rule.match_path) {
        return false;
    }
    if !rule.match_host.is_empty() {
        let h = host.unwrap_or("");
        if !h.eq_ignore_ascii_case(&rule.match_host) {
            return false;
        }
    }
    if rule.when_status != 0 && rule.when_status != status {
        return false;
    }
    true
}

fn apply_header_rules(
    cfg: &Config,
    phase: HeaderPhase,
    headers: &mut http::HeaderMap,
    path: &str,
    host: Option<&str>,
    status: u16,
) -> usize {
    let mut applied = 0;
    for rule in cfg.header_rules.iter().filter(|r| r.phase == phase) {
        if !header_rule_matches(rule, path, host, status) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(rule.name.trim().as_bytes()) else {
            continue;
        };
        match rule.action {
            HeaderAction::Remove => {
                headers.remove(&name);
                applied += 1;
            }
            HeaderAction::Set => {
                if let Ok(v) = HeaderValue::from_str(&rule.value) {
                    headers.insert(name, v);
                    applied += 1;
                }
            }
            HeaderAction::Add => {
                if let Ok(v) = HeaderValue::from_str(&rule.value) {
                    headers.append(name, v);
                    applied += 1;
                }
            }
        }
    }
    applied
}

fn append_forwarded(
    headers: &mut http::HeaderMap,
    peer: &std::net::SocketAddr,
    host: Option<&str>,
    scheme: &str,
) {
    let ip = peer.ip().to_string();
    let merged = match headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        Some(prev) => format!("{prev}, {ip}"),
        None => ip,
    };
    if let Ok(v) = HeaderValue::from_str(&merged) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v);
    }
    if let Some(host) = host {
        if let Ok(v) = HeaderValue::from_str(host) {
            headers.insert(HeaderName::from_static("x-forwarded-host"), v);
        }
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_str(scheme).unwrap_or(HeaderValue::from_static("http")),
    );
    let via = format!(
        "{} optical/{}",
        headers
            .get("via")
            .and_then(|v| v.to_str().ok())
            .map(|s| format!("{s}, "))
            .unwrap_or_default(),
        env!("CARGO_PKG_VERSION")
    );
    if let Ok(v) = HeaderValue::from_str(&via) {
        headers.insert(HeaderName::from_static("via"), v);
    }
}

fn insert_debug_headers(
    headers: &mut http::HeaderMap,
    decision: &Decision,
    authority: &str,
    elapsed: Duration,
    backend: Option<&str>,
    lb: Option<&str>,
) {
    if let Ok(v) = HeaderValue::from_str(decision.route_name.as_deref().unwrap_or("default")) {
        headers.insert(HeaderName::from_static("x-optical-route"), v);
    }
    if let Some(name) = backend {
        if let Ok(v) = HeaderValue::from_str(name) {
            headers.insert(HeaderName::from_static("x-optical-backend"), v);
        }
    }
    if let Some(lb) = lb {
        if let Ok(v) = HeaderValue::from_str(lb) {
            headers.insert(HeaderName::from_static("x-optical-lb"), v);
        }
    }
    if let Ok(v) = HeaderValue::from_str(authority) {
        headers.insert(HeaderName::from_static("x-optical-upstream"), v);
    }
    headers.insert(
        HeaderName::from_static("x-optical-duration-ms"),
        HeaderValue::from_str(&elapsed.as_millis().to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
}

fn fail(
    state: &AppState,
    cfg: &Config,
    ua: &str,
    ip: &str,
    status: StatusCode,
    msg: impl AsRef<str>,
) -> Response<ProxyBody> {
    state.metrics.errors.fetch_add(1, Ordering::Relaxed);
    state.record_profile(ua, ip, status.as_u16());
    tracing::warn!(%status, reason = msg.as_ref(), "转发失败");
    error_response(state, cfg, status, msg.as_ref(), None)
}

/// CORS 预检响应：只回浏览器要看的头，不带 body。
fn cors_preflight(cors: &crate::apps::CorsConfig, origin: &str, req: &http::HeaderMap) -> Response<ProxyBody> {
    let mut b = Response::builder().status(StatusCode::NO_CONTENT);
    if let Some(allow) = cors.allows(origin) {
        b = b.header("access-control-allow-origin", allow);
        b = b.header("access-control-allow-methods", cors.methods.join(", "));
        let allow_headers = if cors.headers.is_empty() {
            req.get("access-control-request-headers")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*")
                .to_string()
        } else {
            cors.headers.join(", ")
        };
        b = b.header("access-control-allow-headers", allow_headers);
        if cors.credentials {
            b = b.header("access-control-allow-credentials", "true");
        }
        b = b.header("access-control-max-age", cors.max_age.to_string());
        b = b.header("vary", "origin");
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).map_err(|n| match n {}).boxed()))
}

/// 给真实响应套 CORS 头
fn apply_cors(cors: &crate::apps::CorsConfig, origin: &str, headers: &mut http::HeaderMap) {
    if !cors.enabled || origin.is_empty() {
        return;
    }
    if let Some(allow) = cors.allows(origin) {
        if let Ok(v) = HeaderValue::from_str(&allow) {
            headers.insert(http::header::HeaderName::from_static("access-control-allow-origin"), v);
        }
        if cors.credentials {
            headers.insert(
                http::header::HeaderName::from_static("access-control-allow-credentials"),
                HeaderValue::from_static("true"),
            );
        }
        if !cors.expose.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&cors.expose.join(", ")) {
                headers.insert(http::header::HeaderName::from_static("access-control-expose-headers"), v);
            }
        }
        headers.insert(
            http::header::HeaderName::from_static("vary"),
            HeaderValue::from_static("origin"),
        );
    }
}

/// 规则产生的重定向。状态码只认 301/302/303/307/308，其它按 302 处理，
/// 免得配置里写个 200 让人以为"重定向没生效"。
fn redirect_response(
    state: &Arc<AppState>,
    cfg: &crate::config::Config,
    status: u16,
    to: &str,
) -> Response<ProxyBody> {
    let code = match status {
        301 | 302 | 303 | 307 | 308 => StatusCode::from_u16(status).unwrap_or(StatusCode::FOUND),
        _ => StatusCode::FOUND,
    };
    let loc = HeaderValue::from_str(to)
        .unwrap_or_else(|_| HeaderValue::from_static("/"));
    let server = cfg.server.server_header.clone();
    let mut b = Response::builder()
        .status(code)
        .header(http::header::LOCATION, loc)
        .header(http::header::CACHE_CONTROL, "no-store");
    if !server.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&server) {
            b = b.header(SERVER, v);
        }
    }
    let _ = state;
    b.body(
        Full::new(Bytes::from(format!("重定向到 {to}")))
            .map_err(|never| match never {})
            .boxed(),
    )
    .unwrap_or_else(|_| {
        error_response(state, cfg, StatusCode::INTERNAL_SERVER_ERROR, "重定向构造失败", None)
    })
}

/// 把规则动作里的响应头（server_name / 附加头 / 命中标记）写到响应上。
fn apply_rule_headers<B>(resp: &mut Response<B>, hit: &crate::rules::Resolved) {
    if let Some(name) = &hit.actions.server_name {
        if let Ok(v) = HeaderValue::from_str(name) {
            resp.headers_mut().insert(SERVER, v);
        }
    }
    for (k, v) in hit.actions.response_headers.iter() {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            resp.headers_mut().insert(name, val);
        }
    }
    if !hit.hit.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&hit.hit.join(",")) {
            resp.headers_mut()
                .insert(HeaderName::from_static("x-optical-rule"), v);
        }
    }
}

/// 本地生成的错误响应：优先用运维自定义的错误页，绝不把内部细节原样吐给客户端。
fn error_response(
    state: &AppState,
    cfg: &Config,
    status: StatusCode,
    msg: &str,
    rule: Option<&str>,
) -> Response<ProxyBody> {
    let paths = cfg.resolve_paths(&state.config_path);
    let (text, ct) = crate::errors::render(cfg, &paths, status, msg);
    let body = Full::new(Bytes::from(text))
        .map_err(|never| match never {})
        .boxed();
    let mut b = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, ct)
        // 错误页不缓存：CDN 缓存 5xx 会把一次抖动放大成持续故障
        .header(http::header::CACHE_CONTROL, "no-store");
    if let Some(v) = server_header_value(cfg) {
        b = b.header(SERVER, v);
    }
    if let Some(r) = rule {
        if let Ok(v) = HeaderValue::from_str(r) {
            b = b.header(HeaderName::from_static("x-optical-waf"), v);
        }
    }
    b.body(body).expect("静态构造的响应不会失败")
}

impl AppState {
    /// accept 循环读限流参数：绝不在热路径上等配置锁。
    pub fn config_for_limits(&self) -> (usize, u32) {
        match self.try_config() {
            Some(c) => {
                if c.waf.enabled && c.waf.dos.enabled {
                    (c.waf.dos.conn_per_ip, c.waf.dos.conn_burst_per_sec)
                } else {
                    (0, 0)
                }
            }
            None => (512, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_and_connection_named_removed() {
        let mut h = http::HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive, X-Custom"));
        h.insert(HeaderName::from_static("x-custom"), HeaderValue::from_static("1"));
        h.insert(HeaderName::from_static("x-keep"), HeaderValue::from_static("1"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        strip_hop_by_hop(&mut h, false);
        assert!(!h.contains_key("connection"));
        assert!(!h.contains_key("x-custom"));
        assert!(!h.contains_key("transfer-encoding"));
        assert!(h.contains_key("x-keep"));
    }

    #[test]
    fn grpc_keeps_te_trailers() {
        let mut h = http::HeaderMap::new();
        h.insert("te", HeaderValue::from_static("trailers"));
        strip_hop_by_hop(&mut h, true);
        assert!(h.contains_key("te"));
    }

    #[test]
    fn header_rules_set_add_remove() {
        let cfg = Config {
            header_rules: vec![
                HeaderRule {
                    phase: HeaderPhase::Response,
                    action: HeaderAction::Set,
                    name: "X-Frame-Options".into(),
                    value: "DENY".into(),
                    ..Default::default()
                },
                HeaderRule {
                    phase: HeaderPhase::Response,
                    action: HeaderAction::Remove,
                    name: "server".into(),
                    match_path: "/api".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut h = http::HeaderMap::new();
        h.insert("server", HeaderValue::from_static("nginx"));
        let n = apply_header_rules(&cfg, HeaderPhase::Response, &mut h, "/api/x", None, 200);
        assert_eq!(n, 2);
        assert_eq!(h["x-frame-options"], "DENY");
        assert!(!h.contains_key("server"), "路径命中时 server 应被删除");
    }

    #[test]
    fn header_rule_status_filter() {
        let cfg = Config {
            header_rules: vec![HeaderRule {
                phase: HeaderPhase::Response,
                action: HeaderAction::Set,
                name: "X-Only-404".into(),
                value: "1".into(),
                when_status: 404,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut h = http::HeaderMap::new();
        apply_header_rules(&cfg, HeaderPhase::Response, &mut h, "/", None, 200);
        assert!(!h.contains_key("x-only-404"));
        apply_header_rules(&cfg, HeaderPhase::Response, &mut h, "/", None, 404);
        assert!(h.contains_key("x-only-404"));
    }

    #[test]
    fn websocket_detection() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        assert!(is_websocket_upgrade(&h));
        h.remove(CONNECTION);
        assert!(!is_websocket_upgrade(&h));
    }

    #[test]
    fn forwarded_headers_appended() {
        let mut h = http::HeaderMap::new();
        h.insert(HeaderName::from_static("x-forwarded-for"), HeaderValue::from_static("1.2.3.4"));
        let peer: std::net::SocketAddr = "10.0.0.9:5555".parse().unwrap();
        append_forwarded(&mut h, &peer, Some("api.local"), "https");
        assert_eq!(h["x-forwarded-for"], "1.2.3.4, 10.0.0.9");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert!(h["via"].to_str().unwrap().contains("optical/"));
    }
}
