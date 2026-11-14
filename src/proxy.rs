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

const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    // 老代理客户端（部分 Java 库、旧 curl 配置）会发这个，它不是标准头，
    // 原样转给上游只会让上游多一层误解
    "proxy-connection",
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
    /// 连接池参数（所有客户端共享同一套，超时分池不影响池参数）
    keepalive_secs: u64,
    pool_idle_secs: u64,
    pool_max_idle: usize,
    /// 按建连超时定制的客户端。
    ///
    /// 为什么不能只用一个全局 5 秒：`HttpConnector` 的建连超时是构造期固定的，
    /// 没有 per-request 入口。要么改全局（影响所有请求），要么按超时值分池——
    /// 而且分池本身是对的：不同超时的连接不该混在一个池里复用。
    variants: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, (HttpClient, HttpClient)>>>,
}

impl Clients {
    pub fn new(keepalive_secs: u64, pool_idle_secs: u64, pool_max_idle: usize) -> Self {
        Self {
            h1: build_client(false, 5_000, keepalive_secs, pool_idle_secs, pool_max_idle),
            h2: build_client(true, 5_000, keepalive_secs, pool_idle_secs, pool_max_idle),
            keepalive_secs,
            pool_idle_secs,
            pool_max_idle,
            variants: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// 取一个建连超时为 `connect_ms` 的客户端。None / 0 用默认那一对。
    fn pick(&self, http2_only: bool, connect_ms: Option<u64>) -> HttpClient {
        let ms = match connect_ms {
            Some(v) => v.clamp(50, 60_000),
            None => return if http2_only { self.h2.clone() } else { self.h1.clone() },
        };
        if ms == 5_000 {
            return if http2_only { self.h2.clone() } else { self.h1.clone() };
        }
        let mut g = self.variants.lock().unwrap_or_else(|e| e.into_inner());
        // 上限 16 组：规则里乱填一堆不同的毫秒数也不能让这里长成内存泄漏
        if g.len() > 16 && !g.contains_key(&ms) {
            g.clear();
        }
        let e = g.entry(ms).or_insert_with(|| {
            (
                build_client(false, ms, self.keepalive_secs, self.pool_idle_secs, self.pool_max_idle),
                build_client(true, ms, self.keepalive_secs, self.pool_idle_secs, self.pool_max_idle),
            )
        });
        if http2_only { e.1.clone() } else { e.0.clone() }
    }
}

impl Default for Clients {
    fn default() -> Self {
        Self::new(30, 30, 32)
    }
}

fn build_client(
    http2_only: bool,
    connect_ms: u64,
    keepalive_secs: u64,
    pool_idle_secs: u64,
    pool_max_idle: usize,
) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_millis(connect_ms)));
    connector.set_keepalive(Some(Duration::from_secs(keepalive_secs)));
    let mut b = Client::builder(TokioExecutor::new());
    b.pool_idle_timeout(Duration::from_secs(pool_idle_secs))
        .pool_max_idle_per_host(pool_max_idle);
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
    let cfg = state.snapshot().await;
    let clients = Clients::new(
        cfg.server.upstream_keepalive_secs,
        cfg.server.upstream_pool_idle_secs,
        cfg.server.upstream_pool_max_idle,
    );
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

    // 真实客户端 IP：默认就取 TCP 对端；只有对端在 trusted_proxies 里才看转发头
    let client_ip = client_ip(req.headers(), peer.ip(), &cfg.server.trusted_proxies);
    let ip_str = client_ip.to_string();

    // WS 必须在消费 request 之前把 upgrade future 取出来，hyper 只允许这一次
    let ws_upgrade = if is_websocket_upgrade(req.headers()) {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let (mut parts, incoming) = req.into_parts();
    let original_host = request_host(&parts.uri, &parts.headers);

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

    // ---- 全局背压：在途请求闸门 ----
    // 放在 IP 名单之后：被名单拒掉的请求不该占额度。
    // 放在读 body 之前：真正省资源的是"还没开始缓冲就拒绝"。
    //
    // 关于粒度：这里数的是"正在处理中的请求"，不是"整个响应传完"。
    // 流式响应的 body 由 hyper 的流控管着，不会因为我们不计数就无限堆积；
    // 而把 body 也纳入在途统计，就得给每个响应包一层，代价大于收益。
    let bp = &cfg.backpressure;
    let _bp_guard = if bp.enabled
        && (bp.max_in_flight > 0 || bp.max_in_flight_per_ip > 0)
    {
        match state
            .backpressure
            .try_enter(Some(&ip_str), bp.max_in_flight, bp.max_in_flight_per_ip)
        {
            Some(g) => Some(g),
            None => {
                state
                    .metrics
                    .backpressure_rejects
                    .fetch_add(1, Ordering::Relaxed);
                let status = StatusCode::from_u16(bp.status_code)
                    .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                return throttle_response(
                    &state,
                    &cfg,
                    status,
                    format!(
                        "网关当前在途请求过多（全局上限 {}，单 IP 上限 {}），先拒后放",
                        bp.max_in_flight, bp.max_in_flight_per_ip
                    ),
                    bp.retry_after_secs,
                );
            }
        }
    } else {
        None
    };

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

    // 统计记账：早于选路的出口只有域名，没有 route/backend。
    // 以前这些地方调 record_profile（空维度），于是 WAF 拦截、限流、重定向、
    // 上游失败在分析里全被归到 "—" 底下——Host 一栏 994 次只有一条 `-` 就是这么来的。
    macro_rules! note {
        ($status:expr) => {
            note!($status, "")
        };
        // 带 route 的版本：规则直接返回时用 `rule:<名字>`，
        // 否则"路由"一栏只剩 `-`，看不出这条响应是谁给的
        ($status:expr, $route:expr) => {
            state.record_hit(
                &ua,
                &ip_str,
                $status,
                crate::stats::ReqDims {
                    route: $route,
                    backend: "",
                    host: &host_str,
                },
                0,
            )
        };
    }
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
    let act = &rule_hit.actions;

    // ---- 规则级限速 / 背压 ----
    // 动作是"最后一条命中的规则说了算"，所以 key 里的规则名也取最后那条——
    // 否则桶会挂在一个其实没生效的规则名下，查限额时对不上号。
    let hit_rule = rule_hit.hit.last().map(String::as_str).unwrap_or("-");
    // 规则直接返回响应时，把它记进 route 维度：`rule:<名字>`。
    // 这类请求根本没选路，留空只能是 `-`——排查时看不出是规则干的。
    let rule_route = rule_hit
        .hit
        .last()
        .map(|n| format!("rule:{n}"))
        .unwrap_or_default();
    if let Some(rl) = &act.rate_limit {
        if rl.qps > 0 {
            let bucket = limit_bucket(rl.key, hit_rule, &ip_str);
            let burst = if rl.burst > 0 { rl.burst } else { rl.qps };
            let v = state.rate_limiter.allow(&bucket, rl.qps, burst);
            if !v.allowed {
                state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                let status =
                    StatusCode::from_u16(rl.status_code).unwrap_or(StatusCode::TOO_MANY_REQUESTS);
                return throttle_response(
                    &state,
                    &cfg,
                    status,
                    format!(
                        "触发规则「{hit_rule}」的限速：{}/s，突发 {}",
                        rl.qps, burst
                    ),
                    v.retry_after,
                );
            }
        }
    }
    // 规则级在途：guard 必须活到本函数结束，所以绑在函数作用域的变量上
    let _rule_guard = match &act.max_in_flight {
        Some(il) if il.limit > 0 => {
            let key = limit_bucket(il.key, hit_rule, &ip_str);
            match state.rule_inflight.try_enter(Some(&key), 0, il.limit) {
                Some(g) => Some(g),
                None => {
                    state
                        .metrics
                        .backpressure_rejects
                        .fetch_add(1, Ordering::Relaxed);
                    let status = StatusCode::from_u16(il.status_code)
                        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                    return throttle_response(
                        &state,
                        &cfg,
                        status,
                        format!("触发规则「{hit_rule}」的在途上限（{}）", il.limit),
                        cfg.backpressure.retry_after_secs.max(1),
                    );
                }
            }
        }
        _ => None,
    };

    let vars = crate::rules::Vars {
        host: &host_str,
        path: &path,
        query: &query_str,
        method: &method_str,
    };

    // ---- DoS 体积闸门（读 body 之前就拦）----
    if cfg.waf.enabled && cfg.waf.dos.enabled && cfg.waf.dos.max_body_bytes > 0
        && content_length > cfg.waf.dos.max_body_bytes
    {
        state.metrics.waf_blocks.fetch_add(1, Ordering::Relaxed);
        state.record_rule_hit("dos-body-size");
        note!(413);
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
            note!(403);
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
                note!(401);
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
        note!(301, &rule_route);
        return redirect_response(&state, &cfg, 301, &format!("https://{host}{uri}"));
    }

    if let Some(r) = &act.redirect {
        if !r.to.is_empty() {
            let target = crate::rules::expand(&r.to, &vars);
            note!(r.status, &rule_route);
            return redirect_response(&state, &cfg, r.status.max(300), &target);
        }
    }

    if let Some(c) = &act.custom_response {
        note!(c.status, &rule_route);
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
            note!(413);
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
        note!(403);
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
        note!(301);
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

    // ---- 规则级回源：优先级最高，盖过路由的后端选择 ----
    // 源站组复用后端组（同一个 pick、同一套 LB 与探活），不另造一套并行机制。
    if let Some(u) = act.upstream.as_deref().filter(|s| !s.trim().is_empty()) {
        decision.upstream = u.to_string();
        backend_name = None;
        lb_used = None;
    } else if let Some(g) = act.origin_group.as_deref().filter(|s| !s.trim().is_empty()) {
        let strategy = cfg.resolve_lb(None, Some(g));
        if let Some(p) = state.backends.pick(
            &cfg,
            crate::config::TargetSpec::Group(g),
            strategy,
            Some(client_ip),
        ) {
            decision.upstream = p.backend.url.clone();
            if p.backend.timeout_ms > 0 {
                decision.timeout_ms = p.backend.timeout_ms;
            }
            backend_name = Some(p.backend.name.clone());
            lb_used = Some(p.strategy.label());
            if p.degraded {
                tracing::warn!(group = %g, backend = %p.backend.name, "源站组无健康成员，降级转发");
            }
        } else {
            tracing::warn!(group = %g, "规则引用的源站组没有可用后端，回退默认上游");
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
                    // 走默认上游时也要有名字：留空会让"路由"这一栏只剩 `-`，
                    // 分不清"没配路由"和"配了但没命中"
                    route: decision.route_name.as_deref().unwrap_or("default"),
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
        return fail(
            &state,
            &cfg,
            &ua,
            &ip_str,
            &host_str,
            Some(decision.route_name.as_deref().unwrap_or("default")),
            StatusCode::BAD_GATEWAY,
            "上游地址解析失败",
        );
    };
    let up_scheme = base.scheme_str().unwrap_or("http").to_string();
    let authority = match base.authority() {
        Some(a) => a.as_str().to_string(),
        None => {
            return fail(
                &state,
                &cfg,
                &ua,
                &ip_str,
                &host_str,
                Some(decision.route_name.as_deref().unwrap_or("default")),
                StatusCode::BAD_GATEWAY,
                "上游缺少 host",
            )
        }
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
            return fail(
                &state,
                &cfg,
                &ua,
                &ip_str,
                &host_str,
                Some(decision.route_name.as_deref().unwrap_or("default")),
                StatusCode::BAD_GATEWAY,
                format!("构造上游 URI 失败: {e}"),
            )
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
    append_forwarded(&mut parts.headers, client_ip, peer.ip(), original_host.as_deref(), scheme);

    // 压缩要在响应回来之后决定，但请求头马上就被 move 进上游请求了，先留住
    let accept_encoding = parts
        .headers
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let is_h2 = parts.version == Version::HTTP_2;
    parts.uri = uri;
    parts.version = if is_h2 { Version::HTTP_2 } else { Version::HTTP_11 };
    let upstream_req = Request::from_parts(parts, forward_body);

    let client = clients.pick(is_h2, act.connect_timeout_ms);
    let timeout_ms = act.upstream_timeout_ms.unwrap_or(decision.timeout_ms);
    let timeout = Duration::from_millis(timeout_ms);
    let resp = match tokio::time::timeout(timeout, client.request(upstream_req)).await {
        Err(_) => {
            return fail(
                &state,
                &cfg,
                &ua,
                &ip_str,
                &host_str,
                Some(decision.route_name.as_deref().unwrap_or("default")),
                StatusCode::GATEWAY_TIMEOUT,
                format!("上游超时（{} ms）", timeout_ms),
            )
        }
        Ok(Err(e)) => {
            // 把目标写进去：只回一句 "连接上游失败" 的话，人只能去猜是证书、
            // 是域名、还是后端没起。这里直接点名是谁连不上。
            return fail(
                &state,
                &cfg,
                &ua,
                &ip_str,
                &host_str,
                Some(decision.route_name.as_deref().unwrap_or("default")),
                StatusCode::BAD_GATEWAY,
                format!(
                    "连接上游失败: {e}（目标 {up_scheme}://{authority}；常见原因：后端没在监听、端口写错、回源协议该用 http 却写了 https）"
                ),
            )
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

    // ---- 响应压缩（gzip / brotli）----
    // 只在"长度已知且落在区间内、上游没压过、类型是文本"时才考虑；
    // 其余直传——压错了比不压更糟，尤其是把已经压过的再压一遍。
    let enc = crate::compress::negotiate(&accept_encoding, &cfg.compression);
    let content_type = rparts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let want_compress = enc.is_some()
        && crate::compress::should_compress(
            &cfg.compression,
            status.as_u16(),
            content_type.as_deref(),
            Some(body_len as u64),
            rparts.headers.contains_key(http::header::CONTENT_ENCODING),
        );

    let body: ProxyBody = if want_cache || want_compress {
        match rbody.collect().await {
            Ok(c) => {
                let bytes = c.to_bytes();
                if want_cache {
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
                }

                if let Some(e) = enc.filter(|_| want_compress) {
                    // 小于可压区间时 should_compress 已经拦掉了，这里只处理编码
                    match crate::compress::encode(e, &bytes, cfg.compression.level) {
                        Ok(z) if z.len() < bytes.len() => {
                            // 压完必须改头：长度变了、ETag 描述的是未压缩表示、
                            // 还要让 CDN 按 Accept-Encoding 分桶
                            rparts.headers.remove(http::header::CONTENT_LENGTH);
                            rparts.headers.remove(http::header::ETAG);
                            if let Ok(v) = HeaderValue::from_str(e.as_str()) {
                                rparts.headers.insert(http::header::CONTENT_ENCODING, v);
                            }
                            append_vary(&mut rparts.headers, "accept-encoding");
                            state
                                .metrics
                                .bytes_saved
                                .fetch_add((bytes.len() - z.len()) as u64, Ordering::Relaxed);
                            return Response::from_parts(
                                rparts,
                                Full::new(Bytes::from(z)).map_err(|never| match never {}).boxed(),
                            );
                        }
                        // 压完反而更大（几百字节的响应就是这样），老老实实直传
                        Ok(_) => {}
                        Err(err) => tracing::debug!(error = %err, enc = e.as_str(), "压缩失败，直传"),
                    }
                }
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
            route: decision.route_name.as_deref().unwrap_or("default"),
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

/// 往 `Vary` 里追加一个字段。已有的值要保留——覆盖掉别人写的
/// `Vary: Accept-Encoding, Origin` 会让缓存串味。
fn append_vary(headers: &mut http::HeaderMap, field: &str) {
    let have = headers
        .get(http::header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let already = have.split(',').any(|x| x.trim() == field);
    if already {
        return;
    }
    let next = if have.is_empty() {
        field.to_string()
    } else {
        format!("{}, {}", headers[http::header::VARY].to_str().unwrap_or("").trim(), field)
    };
    if let Ok(v) = HeaderValue::from_str(&next) {
        headers.insert(http::header::VARY, v);
    }
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
        state.record_hit(
            ua,
            ip,
            status.as_u16(),
            crate::stats::ReqDims {
                route: "",
                backend: "",
                host: meta.authority,
            },
            0,
        );
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
    state.record_hit(
        ua,
        ip,
        101,
        crate::stats::ReqDims {
            route: "",
            backend: "",
            host: meta.authority,
        },
        0,
    );

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

fn parse_trusted(list: &[String], ip: &std::net::IpAddr) -> bool {
    let s = ip.to_string();
    list.iter().any(|c| crate::rules::cidr_match(c, &s))
}

/// 客户端真实 IP。
///
/// 规则很简单，但顺序很关键：**只有直连对端在 `trusted_proxies` 里时才看转发头**。
/// 否则任何人都能写一个 `X-Forwarded-For: 1.2.3.4` 把自己伪装掉——
/// 那时 IP 黑名单和按 IP 限流会同时变成摆设。
fn client_ip(
    headers: &http::HeaderMap,
    peer: std::net::IpAddr,
    trusted: &[String],
) -> std::net::IpAddr {
    if trusted.is_empty() || !parse_trusted(trusted, &peer) {
        return peer;
    }
    let mut chain: Vec<String> = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if chain.is_empty() {
        // 部分 CDN 只给专有头，不给标准 XFF
        for name in ["cf-connecting-ip", "x-real-ip", "true-client-ip"] {
            if let Some(v) = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                chain.push(v.to_string());
                break;
            }
        }
    }
    // 从右往左找第一个"不在可信段里"的地址：那是离我们最近的真实客户端。
    // 从左往右取会被伪造链坑到（攻击者在最左边随便写）。
    for candidate in chain.iter().rev() {
        if let Ok(a) = candidate.parse::<std::net::IpAddr>() {
            if !parse_trusted(trusted, &a) {
                return a;
            }
        }
    }
    peer
}

/// 请求 ID：透传上游/客户端带来的，没有就生成一个。
/// 长度要卡住——这东西会进日志和响应头，超长值属于给自己找麻烦。
fn request_id(headers: &http::HeaderMap) -> String {
    if let Some(v) = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128)
    {
        return v.to_string();
    }
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// 给上游补齐全套"代理链"头。
///
/// 之前只有 XFF / X-Forwarded-Host / Proto 三个，实际部署里会缺：
/// - `X-Real-IP`：nginx 生态的后端第一眼就看它，没有就拿 XFF 最后一跳猜；
/// - `X-Forwarded-Port`：生成绝对 URL、判断是否需要跳转时要用；
/// - `Forwarded`：RFC 7239 标准头，新一点的框架开始只看它；
/// - `X-Request-Id`：没有就生成，全链路日志才有共同的串。
fn append_forwarded(
    headers: &mut http::HeaderMap,
    // client：解析出的真实客户端（可信代理链里最靠右的那个不可信地址）
    // peer：直连对端。XFF 追加的是它，不是 client——
    // 追加 client 会让 "1.2.3.4, 1.2.3.4" 这种自重复进链，
    // 后面任何按跳数解析的中间件都会读错。
    client: std::net::IpAddr,
    peer: std::net::IpAddr,
    host: Option<&str>,
    scheme: &str,
) {
    let ip = client.to_string();
    let hop = peer.to_string();
    let merged = match headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        Some(prev) => format!("{prev}, {hop}"),
        None => hop.clone(),
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
    // X-Real-IP：直接覆盖而不是追加。它语义是"单个客户端地址"，
    // 追加成 "1.2.3.4, 5.6.7.8" 之后后端 parse 会直接失败。
    if let Ok(v) = HeaderValue::from_str(&ip) {
        headers.insert(HeaderName::from_static("x-real-ip"), v);
    }

    // X-Forwarded-Port：优先用原始 Host 里的端口，没有就按协议默认端口
    let port = host
        .and_then(|h| h.rsplit_once(':'))
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    headers.insert(
        HeaderName::from_static("x-forwarded-port"),
        HeaderValue::from_str(&port.to_string()).unwrap_or(HeaderValue::from_static("80")),
    );

    // Forwarded（RFC 7239）。IPv6 必须加引号并套方括号，否则分号分隔会解析错。
    let for_part = if ip.contains(':') {
        format!("\"[{ip}]\"")
    } else {
        ip.clone()
    };
    let mut fwd = format!("for={for_part};proto={scheme}");
    if let Some(h) = host.filter(|h| !h.is_empty()) {
        fwd.push_str(&format!(";host={h}"));
    }
    let merged_fwd = match headers
        .get("forwarded")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        Some(prev) => format!("{prev}, {fwd}"),
        None => fwd,
    };
    if let Ok(v) = HeaderValue::from_str(&merged_fwd) {
        headers.insert(HeaderName::from_static("forwarded"), v);
    }

    // 请求 ID：透传已有的，没有就生成一个
    let rid = request_id(headers);
    if let Ok(v) = HeaderValue::from_str(&rid) {
        headers.insert(HeaderName::from_static("x-request-id"), v);
    }

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
    // 域名与路由：没有它们，所有上游失败在分析里都会被归到 "—" 底下，
    // 想查"哪个站点在报错"时一条都用不上
    host: &str,
    route: Option<&str>,
    status: StatusCode,
    msg: impl AsRef<str>,
) -> Response<ProxyBody> {
    state.metrics.errors.fetch_add(1, Ordering::Relaxed);
    state.record_hit(
        ua,
        ip,
        status.as_u16(),
        crate::stats::ReqDims {
            route: route.unwrap_or(""),
            backend: "",
            host,
        },
        0,
    );
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
/// 取请求的域名。
///
/// 顺序：URI 的 authority → `Host` 头。
///
/// **不能反过来**：HTTP/2 客户端压根不发 `Host`，它用 `:authority`，
/// 而 hyper 把这个值放进 URI 的 authority 里。只读 `Host` 头的话，
/// 所有走 h2 的请求（浏览器 + 现代 CDN 回源基本都是）域名全是空的——
/// 线上表现就是统计里 Host 那一栏只剩一条 `-`（994 次全是它），
/// 站点/vhost 匹配、按域名分组的规则也一并落空。
fn request_host(uri: &Uri, headers: &http::HeaderMap) -> Option<String> {
    uri.authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            headers
                .get(HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
}

/// 把几种限速维度映射成桶键。格式统一在这里定，查问题时才不用猜。
fn limit_bucket(key: crate::rules::LimitKey, rule: &str, ip: &str) -> String {
    use crate::rules::LimitKey;
    match key {
        LimitKey::ClientIp => format!("ip:{ip}"),
        LimitKey::Rule => format!("rule:{rule}"),
        LimitKey::RuleIp => format!("ri:{rule}|{ip}"),
    }
}

/// 限速/背压的响应。和普通错误页共用渲染，但必须带 `Retry-After`：
/// 没有它，客户端只能瞎重试，等于把限速变成压测。
fn throttle_response(
    state: &AppState,
    cfg: &Config,
    status: StatusCode,
    msg: String,
    retry_after: u64,
) -> Response<ProxyBody> {
    let mut r = error_response(state, cfg, status, &msg, None);
    // 上限 60 秒：回一个很大的数字没人等，反而让人以为服务挂了
    let secs = retry_after.clamp(1, 60);
    if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
        r.headers_mut().insert(http::header::RETRY_AFTER, v);
    }
    r
}

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
    /// 连接级闸门的阈值：(单 IP 并发, 单 IP 每秒新建)。
    ///
    /// 优先级：`[backpressure]` 显式配了就用它；没配（0）回落到 `waf.dos`。
    /// 这样既能把"连接准入"和"攻击检测"分开调，也不会让老配置突然失去保护。
    pub fn config_for_limits(&self) -> (usize, u32) {
        match self.try_config() {
            Some(c) => {
                let bp = &c.backpressure;
                if bp.enabled {
                    let conn = if bp.conn_per_ip > 0 {
                        bp.conn_per_ip
                    } else if c.waf.enabled && c.waf.dos.enabled {
                        c.waf.dos.conn_per_ip
                    } else {
                        0
                    };
                    let burst = if bp.conn_burst_per_sec > 0 {
                        bp.conn_burst_per_sec
                    } else if c.waf.enabled && c.waf.dos.enabled {
                        c.waf.dos.conn_burst_per_sec
                    } else {
                        0
                    };
                    return (conn, burst);
                }
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
    fn host_comes_from_authority_when_there_is_no_host_header() {
        // HTTP/2 就是这样：没有 Host 头，只有 :authority（hyper 放进 URI）。
        // 线上踩过：只读 Host 头 → 统计里 Host 一栏 994 次全是 `-`。
        let uri: Uri = "https://optical.zakoflare.com/api/x?y=1".parse().unwrap();
        let h = http::HeaderMap::new();
        assert_eq!(
            request_host(&uri, &h).as_deref(),
            Some("optical.zakoflare.com")
        );
    }

    #[test]
    fn host_falls_back_to_host_header_for_http1() {
        // HTTP/1.1 的 origin-form 只有 path，域名仍在 Host 头里
        let uri: Uri = "/api/x".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("example.com:8080"));
        assert_eq!(request_host(&uri, &h).as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn host_is_none_when_neither_is_present() {
        let uri: Uri = "/".parse().unwrap();
        assert!(request_host(&uri, &http::HeaderMap::new()).is_none());
    }

    #[test]
    fn authority_wins_over_conflicting_host_header() {
        // 两者都有时以 authority 为准：h2 的 :authority 才是权威值，
        // 中间件偶尔会塞一个不一致的 Host 头进来
        let uri: Uri = "https://real.example/x".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.insert(HOST, HeaderValue::from_static("spoofed.example"));
        assert_eq!(request_host(&uri, &h).as_deref(), Some("real.example"));
    }

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
        let client: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        append_forwarded(&mut h, client, "10.0.0.9".parse().unwrap(), Some("api.local"), "https");
        assert_eq!(h["x-forwarded-for"], "1.2.3.4, 10.0.0.9");
        assert_eq!(h["x-forwarded-proto"], "https");
        // 后端最常读的那个头
        assert_eq!(h["x-real-ip"], "10.0.0.9");
        // 端口从 Host 里拿不到就按协议默认
        assert_eq!(h["x-forwarded-port"], "443");
        // RFC 7239
        assert!(h["forwarded"].to_str().unwrap().contains("for=10.0.0.9"));
        assert!(h["forwarded"].to_str().unwrap().contains("proto=https"));
        // 请求 ID 必须存在，否则全链路日志串不起来
        assert!(!h["x-request-id"].is_empty());
        assert!(h["via"].to_str().unwrap().contains("optical/"));
    }

    #[test]
    fn forwarded_port_uses_host_port_when_present() {
        let mut h = http::HeaderMap::new();
        let client: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        append_forwarded(&mut h, client, "10.0.0.9".parse().unwrap(), Some("api.local:8443"), "https");
        assert_eq!(h["x-forwarded-port"], "8443");
    }

    #[test]
    fn forwarded_ipv6_is_quoted_for_rfc7239() {
        // RFC 7239 要求 IPv6 用 "[::1]" 并加引号，否则分号分隔会解析错
        let mut h = http::HeaderMap::new();
        let client: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        append_forwarded(&mut h, client, "10.0.0.9".parse().unwrap(), Some("api.local"), "https");
        let f = h["forwarded"].to_str().unwrap();
        assert!(f.contains("for=\"[2001:db8::1]\""), "{f}");
    }

    #[test]
    fn request_id_is_preserved_when_provided() {
        let mut h = http::HeaderMap::new();
        h.insert("x-request-id", HeaderValue::from_static("trace-abc-123"));
        let client: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        append_forwarded(&mut h, client, "10.0.0.9".parse().unwrap(), None, "http");
        assert_eq!(h["x-request-id"], "trace-abc-123");
    }

    #[test]
    fn untrusted_peer_cannot_spoof_xff() {
        // 默认不信任任何代理：客户端自带 XFF 也不能改变它在我们眼里的身份，
        // 否则 IP 黑名单和按 IP 限流同时失效
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        let peer: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(client_ip(&h, peer, &[]).to_string(), "203.0.113.9");
        // 配了可信段，但对端不在里面，同样不采信
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(client_ip(&h, peer, &trusted).to_string(), "203.0.113.9");
    }

    #[test]
    fn trusted_peer_uses_xff_and_takes_nearest_hop() {
        let mut h = http::HeaderMap::new();
        // 左边是攻击者伪造的，右边才是真实客户端
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 198.51.100.7, 10.0.0.5"),
        );
        let peer: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".to_string()];
        // 从右往左找第一个不可信的：10.0.0.5 在可信段内，继续往左 → 198.51.100.7
        assert_eq!(client_ip(&h, peer, &trusted).to_string(), "198.51.100.7");
    }

    #[test]
    fn trusted_peer_falls_back_to_cdn_specific_header() {
        // 有些 CDN 只给 CF-Connecting-IP，不给标准 XFF
        let mut h = http::HeaderMap::new();
        h.insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.7"));
        let peer: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(client_ip(&h, peer, &trusted).to_string(), "198.51.100.7");
    }

    #[test]
    fn trusted_peer_without_headers_is_itself() {
        let h = http::HeaderMap::new();
        let peer: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".to_string()];
        assert_eq!(client_ip(&h, peer, &trusted).to_string(), "10.0.0.9");
    }
}
