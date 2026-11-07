//! 管理面：认证 + REST API + 内嵌 WebUI。
//!
//! 与 CLI 完全同构：所有写操作最终都落到同一份 TOML（校验 → 快照 → 原子写盘 → 换内存），
//! 所以 WebUI 能改的东西 CLI 都能改，反之亦然。
//!
//! 认证：`[admin] enabled = true` 时，除登录/健康检查外的所有 `/api/*` 都要求会话 Cookie。
//! 首次启动若未设置口令，会生成随机口令并打印到控制台（不会静默无密码放行）。

use crate::config::{AdminConfig, Config};
use crate::state::AppState;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::net::TcpListener;

const INDEX_HTML: &str = include_str!("webui/index.html");
const COOKIE_NAME: &str = "optical_sid";

pub async fn serve(state: Arc<AppState>, listener: TcpListener) -> anyhow::Result<()> {
    let public = Router::new()
        .route("/", get(index))
        .route("/favicon.ico", get(favicon))
        .route("/api/health", get(api_health))
        .route("/api/auth/me", get(api_me))
        .route("/api/auth/login", post(api_login))
        .route("/api/auth/logout", post(api_logout));

    let protected = Router::new()
        .route("/api/status", get(api_status))
        .route("/api/metrics", get(api_metrics))
        .route("/api/history", get(api_history))
        .route("/api/config", get(api_get_config).put(api_put_config))
        .route("/api/reload", post(api_reload))
        .route("/api/snapshots", get(api_snapshots))
        .route("/api/snapshots/{id}", delete(api_delete_snapshot))
        .route("/api/snapshots/{id}/restore", post(api_restore_snapshot))
        .route("/api/audit", get(api_audit).delete(api_clear_audit))
        .route("/api/cache/purge", post(api_cache_purge))
        .route("/api/totp/new", post(api_totp_new))
        .route("/api/totp/qr", get(api_totp_qr))
        .route("/api/error-pages/preview", get(api_error_preview))
        .route("/api/ws", get(api_ws))
        .route("/api/admin/password", post(api_set_password))
        .route("/api/backends", get(api_backends))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = public.merge(protected).fallback(not_found).with_state(state);

    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- 认证 ----------

async fn require_auth(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let cfg = st.snapshot().await;
    if !cfg.admin.enabled {
        return next.run(req).await;
    }
    let token = cookie_value(req.headers(), COOKIE_NAME).unwrap_or_default();
    if st.auth.check(&token) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "未登录或会话已过期", "code": "unauthorized" })),
        )
            .into_response()
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{name}=");
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&prefix) {
            return Some(v.trim().to_string());
        }
    }
    None
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    totp: String,
}

async fn api_me(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Json<Value> {
    let cfg = st.snapshot().await;
    let token = cookie_value(&headers, COOKIE_NAME).unwrap_or_default();
    let authed = if cfg.admin.enabled { st.auth.check(&token) } else { true };
    Json(json!({
        "ok": true,
        "authenticated": authed,
        "admin_enabled": cfg.admin.enabled,
        "totp_enabled": cfg.admin.totp_enabled,
        "username": cfg.admin.username,
        "sessions": st.auth.active_sessions(),
    }))
}

async fn api_login(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    let cfg = st.snapshot().await;
    if !cfg.admin.enabled {
        return Json(json!({ "ok": true, "note": "admin.enabled = false，未启用认证" })).into_response();
    }
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("local")
        .to_string();

    match st
        .auth
        .login(&cfg.admin, &req.username, &req.password, &req.totp, &ip)
    {
        Ok(token) => {
            let ttl = cfg.admin.session_ttl_secs;
            let cookie = format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={ttl}");
            let mut resp = Json(json!({ "ok": true, "expires_in": ttl })).into_response();
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                resp.headers_mut().insert(header::SET_COOKIE, v);
            }
            resp
        }
        Err(e) => {
            let status = match e {
                crate::auth::AuthError::TooManyAttempts { .. } => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::UNAUTHORIZED,
            };
            (
                status,
                Json(json!({ "ok": false, "code": e.code(), "error": e.message() })),
            )
                .into_response()
        }
    }
}

async fn api_logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers, COOKIE_NAME) {
        st.auth.logout(&token);
    }
    let mut resp = Json(json!({ "ok": true })).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("{COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0")) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

async fn api_totp_new(State(st): State<Arc<AppState>>) -> Json<Value> {
    let cfg = st.snapshot().await;
    let secret = crate::auth::random_totp_secret();
    let alg = cfg.admin.totp_algorithm;
    Json(json!({
        "ok": true,
        "secret": secret,
        "algorithm": alg.otpauth_name(),
        "uri": crate::auth::otpauth_uri(&secret, &cfg.admin.username, alg),
    }))
}

#[derive(Deserialize)]
struct PreviewQuery {
    status: Option<u16>,
    message: Option<String>,
}

/// 错误页预览：直接吐渲染结果，方便在面板里改完立刻看效果，不用去伪造一次 502。
async fn api_error_preview(
    State(st): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<PreviewQuery>,
) -> Response {
    let cfg = st.snapshot().await;
    let status = StatusCode::from_u16(q.status.unwrap_or(502)).unwrap_or(StatusCode::BAD_GATEWAY);
    let msg = q
        .message
        .unwrap_or_else(|| format!("{}（预览）", crate::errors::reason_phrase(status)));
    let paths = cfg.resolve_paths(&st.config_path);
    let (body, ct) = crate::errors::render(&cfg, &paths, status, &msg);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "no-store".into())],
        body,
    )
        .into_response()
}

#[derive(Deserialize)]
struct PasswordReq {
    password: String,
}

/// 改口令：明文只在这一次请求里出现，落盘的是 argon2 哈希。
async fn api_set_password(
    State(st): State<Arc<AppState>>,
    Json(req): Json<PasswordReq>,
) -> Result<Json<Value>, ApiError> {
    if req.password.chars().count() < 8 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "口令至少 8 位".into()));
    }
    let hash = crate::auth::hash_password(&req.password)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut cfg = st.snapshot().await;
    cfg.admin.password_hash = hash;
    st.apply(cfg).await.map_err(ApiError::bad)?;
    Ok(Json(json!({ "ok": true, "changed": true })))
}

// ---------- 静态 ----------

async fn index() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            // 不缓存：否则改完 UI 用户还在看旧页面，以为改动没生效
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(INDEX_HTML),
    )
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "ok": false, "error": "not found" })),
    )
}

// ---------- 读 ----------

async fn api_health() -> Json<Value> {
    Json(json!({ "ok": true, "service": "optical" }))
}

async fn api_status(State(st): State<Arc<AppState>>) -> Json<Value> {
    Json(status_payload(&st).await)
}

/// 管理面状态载荷：REST 与 WebSocket 共用，避免两边字段漂移。
async fn status_payload(st: &Arc<AppState>) -> Value {
    let cfg = st.snapshot().await;
    json!({
        "ok": true,
        "name": "optical",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": st.uptime_secs().await,
        "listen": cfg.server.listen,
        "admin_listen": cfg.server.admin_listen,
        "default_upstream": cfg.server.default_upstream,
        "request_timeout_ms": cfg.server.request_timeout_ms,
        "log_level": cfg.server.log_level,
        "routes": cfg.routes.len(),
        "backends": cfg.backends.len(),
        "backend_groups": cfg.backend_groups.len(),
        "lb": cfg.server.lb,
        "header_rules": cfg.header_rules.len(),
        "waf": {
            "enabled": cfg.waf.enabled,
            "mode": cfg.waf.mode,
            "score_threshold": cfg.waf.score_threshold,
            "inspect_max_bytes": cfg.server.max_inspect_bytes,
        },
        "tls": {
            "enabled": cfg.tls.enabled,
            "listen": cfg.tls.listen,
            "min_version": cfg.tls.min_version,
        },
        "admin": {
            "enabled": cfg.admin.enabled,
            "username": cfg.admin.username,
            "totp_enabled": cfg.admin.totp_enabled,
            "sessions": st.auth.active_sessions(),
        },
        "cache": { "enabled": cfg.cache.enabled, "ttl_secs": cfg.cache.ttl_secs },
        "metrics": st.metrics_snapshot(),
        "conns": { "active": st.active_conns(), "ips": st.active_ips() },
        "extensions": cfg.extensions,
        "overrides": st.override_keys().await,
        "config_path": st.config_path.display().to_string(),
        // 实际解析出来的落盘位置：证明"非固化路径"不是嘴上说说
        "paths": {
            "data_dir": st.paths.data_dir.display().to_string(),
            "config_history_dir": st.conf_history.dir().display().to_string(),
            "audit_file": st.paths.audit_file.display().to_string(),
            "tls_dir": st.paths.tls_dir.display().to_string(),
            "error_pages_dir": st.error_pages_dir(&cfg).display().to_string(),
        },
        "error_pages": {
            "enabled": cfg.error_pages.enabled,
            "dir": cfg.error_pages.dir,
            "content_type": cfg.error_pages.content_type,
            "inline": cfg.error_pages.bodies.len(),
        },
        "sample_interval_ms": cfg.metrics.sample_interval_ms,
        // 档位保留点数：前端用它算窗口（间隔 × 点数），不用等 /api/history
        "sample_points": st.sampling().1,
        "ws_clients": st.metrics.ws_clients.load(std::sync::atomic::Ordering::Relaxed),
        "config_rev": st.config_rev(),
        "listen_v6": cfg.server.listen_v6,
        "admin_listen_v6": cfg.server.admin_listen_v6,
        "tls_listen_v6": cfg.tls.listen_v6,
    })
}

/// WebSocket 实时通道：每秒推一份与 REST 同构的快照，前端不用再轮询。
/// 鉴权由 require_auth 中间件在升级前完成（Cookie 无效直接 401，不会进入升级）。
async fn api_ws(ws: WebSocketUpgrade, State(st): State<Arc<AppState>>) -> Response {
    ws.on_upgrade(move |socket| ws_loop(socket, st))
}

async fn ws_loop(mut socket: WebSocket, st: Arc<AppState>) {
    st.metrics
        .ws_clients
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    struct Guard(Arc<AppState>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0
                .metrics
                .ws_clients
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    let _guard = Guard(st.clone());

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let cfg = st.snapshot().await;
                let mut payload = status_payload(&st).await;
                payload["type"] = json!("snapshot");
                payload["history"] = json!(st.history_snapshot());
                payload["top"] = json!({
                    "ua": st.top_ua(cfg.metrics.top_n.max(1)),
                    "ip": st.top_ip(cfg.metrics.top_n.max(1)),
                    "rules": st.top_rules(cfg.metrics.top_n.max(1)),
                });
                payload["backend_list"] = json!(st.backends.snapshot(&cfg));
                payload["backend_groups"] = json!(st.backends.groups(&cfg));
                if socket
                    .send(Message::Text(payload.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    // 客户端不需要发消息；忽略 ping/pong 之外的输入
                    _ => {}
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct QrQuery {
    secret: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    alg: String,
}

/// TOTP 二维码：服务端直接渲染 SVG，避免引入前端 QR 库或 CDN。
async fn api_totp_qr(
    State(st): State<Arc<AppState>>,
    Query(q): Query<QrQuery>,
) -> Response {
    if q.secret.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "missing secret").into_response();
    }
    let cfg = st.snapshot().await;
    let alg = match q.alg.trim().to_ascii_lowercase().as_str() {
        "sha256" => crate::config::TotpAlgorithm::Sha256,
        "sha512" => crate::config::TotpAlgorithm::Sha512,
        "sha1" => crate::config::TotpAlgorithm::Sha1,
        _ => cfg.admin.totp_algorithm,
    };
    let user = if q.user.trim().is_empty() {
        cfg.admin.username.as_str()
    } else {
        q.user.trim()
    };
    let uri = crate::auth::otpauth_uri(q.secret.trim(), user, alg);
    match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => {
            let svg = code
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(200, 200)
                .dark_color(qrcode::render::svg::Color("#1b222e"))
                .light_color(qrcode::render::svg::Color("#ffffff"))
                .build();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "image/svg+xml"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                svg,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("生成二维码失败: {e}"),
        )
            .into_response(),
    }
}

async fn api_metrics(State(st): State<Arc<AppState>>) -> Json<Value> {
    let cfg = st.snapshot().await;
    let n = cfg.metrics.top_n.max(1);
    Json(json!({
        "ok": true,
        "metrics": st.metrics_snapshot(),
        "top": {
            "ua": st.top_ua(n),
            "ip": st.top_ip(n),
            "rules": st.top_rules(n),
        },
        "backends": st.backends.snapshot(&cfg),
        "backend_groups": st.backends.groups(&cfg),
        "uptime_secs": st.uptime_secs().await,
    }))
}

async fn api_history(State(st): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({ "ok": true, "history": st.history_snapshot() }))
}

async fn api_backends(State(st): State<Arc<AppState>>) -> Json<Value> {
    let cfg = st.snapshot().await;
    Json(json!({
        "ok": true,
        "backends": st.backends.snapshot(&cfg),
        "groups": st.backends.groups(&cfg),
        "config": cfg.backends,
        "group_config": cfg.backend_groups,
        "default_lb": cfg.server.lb,
    }))
}

async fn api_get_config(State(st): State<Arc<AppState>>) -> Json<Value> {
    let cfg = st.snapshot().await;
    Json(json!({
        "ok": true,
        "path": st.config_path.display().to_string(),
        "rev": st.config_rev(),
        "toml": cfg.to_toml(),
        "config": cfg,
    }))
}

async fn api_snapshots(State(st): State<Arc<AppState>>) -> Json<Value> {
    let cfg = st.snapshot().await;
    Json(json!({
        "ok": true,
        "dir": st.conf_history.dir().display().to_string(),
        "storage": cfg.storage,
        "snapshots": st.snapshots(),
    }))
}

async fn api_audit(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Json<Value> {
    let limit = headers
        .get("x-limit")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200);
    Json(json!({ "ok": true, "entries": st.audit.recent(limit.min(1000)) }))
}

// ---------- 写 ----------

async fn api_reload(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    st.reload_from_disk().await.map_err(ApiError::bad)?;
    Ok(Json(json!({ "ok": true, "reloaded": true })))
}

async fn api_put_config(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    // 乐观锁：客户端带上读取时的版本号；版本不一致说明别的会话已经改过，拒绝覆盖。
    if let Some(raw) = headers.get("x-optical-config-rev").and_then(|v| v.to_str().ok()) {
        if let Ok(base) = raw.trim().parse::<u64>() {
            let current = st.config_rev();
            if base != current {
                return Err(ApiError::conflict(format!(
                    "配置已被其他会话修改（你的版本 {base}，当前 {current}）。请刷新页面后重试，避免覆盖别人的改动。"
                )));
            }
        }
    }

    let ctype = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let text = String::from_utf8(body.to_vec())
        .map_err(|e| ApiError::bad(anyhow::anyhow!("请求体不是合法 UTF-8: {e}")))?;

    let cfg: Config = if ctype.contains("json") {
        serde_json::from_str(&text).map_err(|e| ApiError::bad(anyhow::anyhow!("JSON 解析失败: {e}")))?
    } else if ctype.contains("toml") || ctype.contains("text/plain") {
        toml::from_str(&text).map_err(|e| ApiError::bad(anyhow::anyhow!("TOML 解析失败: {e}")))?
    } else {
        match serde_json::from_str::<Config>(&text) {
            Ok(c) => c,
            Err(_) => toml::from_str(&text)
                .map_err(|e| ApiError::bad(anyhow::anyhow!("无法识别请求体（TOML 错误: {e}）")))?,
        }
    };

    let before = st.snapshot().await;
    let restart_required =
        before.server.listen != cfg.server.listen || before.server.admin_listen != cfg.server.admin_listen;
    let tls_restart = before.tls.enabled != cfg.tls.enabled || before.tls.listen != cfg.tls.listen;

    st.apply(cfg).await.map_err(ApiError::bad)?;
    Ok(Json(json!({
        "ok": true,
        "applied": true,
        "restart_required": restart_required,
        "tls_restart_required": tls_restart,
    })))
}

async fn api_restore_snapshot(
    State(st): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    st.restore_snapshot(&id).await.map_err(ApiError::bad)?;
    Ok(Json(json!({ "ok": true, "restored": id })))
}

async fn api_delete_snapshot(
    State(st): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    st.conf_history.delete(&id).map_err(ApiError::bad)?;
    Ok(Json(json!({ "ok": true, "deleted": id })))
}

async fn api_clear_audit(State(st): State<Arc<AppState>>) -> Json<Value> {
    st.audit.clear();
    Json(json!({ "ok": true }))
}

async fn api_cache_purge(State(st): State<Arc<AppState>>) -> Json<Value> {
    st.cache.purge();
    Json(json!({ "ok": true, "purged": true }))
}

// ---------- 错误 ----------

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_REQUEST, e.to_string())
    }
    #[allow(dead_code)]
    fn not_found(msg: String) -> Self {
        ApiError(StatusCode::NOT_FOUND, msg)
    }

    fn conflict(msg: String) -> Self {
        ApiError(StatusCode::CONFLICT, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "ok": false, "error": self.1 }))).into_response()
    }
}

/// 首次启动没配口令时，生成一个随机口令（调用方负责打印并落盘）。
pub fn ensure_admin_password(cfg: &mut AdminConfig) -> Option<String> {
    if !cfg.enabled || !cfg.password_hash.is_empty() {
        return None;
    }
    let pw = crate::auth::random_password(16);
    match crate::auth::hash_password(&pw) {
        Ok(h) => {
            cfg.password_hash = h;
            Some(pw)
        }
        Err(e) => {
            tracing::error!(error = %e, "生成管理面口令失败");
            None
        }
    }
}
