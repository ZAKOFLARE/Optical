//! 演示用回显上游。
//!
//! 网关 Demo 需要一个能立刻回话的后端，否则每次验证都得现搭 nginx/python。
//! `optical upstream-echo --listen 127.0.0.1:8081` 就能让 smoke 测试跑通。

use axum::body::Bytes;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::net::TcpListener;

pub async fn serve(listen: &str) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/health", get(|| async { (StatusCode::OK, "ok") }))
        // 升级测试端点：回 101 之后把收到的字节原样吐回，用来验证 WS 隧道
        .route("/ws", get(ws_upgrade))
        .fallback(echo);

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| anyhow::anyhow!("回显上游监听失败（{listen}）: {e}"))?;

    tracing::info!("回显上游已启动: http://{listen}");
    println!("  echo upstream  http://{listen}   (GET /health 用于探活)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ws_upgrade(mut req: Request) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if key.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing sec-websocket-key").into_response();
    }
    let accept = ws_accept(&key);
    let on_upgrade = hyper::upgrade::on(&mut req);

    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut io = hyper_util::rt::TokioIo::new(upgraded);
            // 原样回吐字节：验证网关的双向隧道真的通了
            let mut buf = [0u8; 4096];
            loop {
                match io.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if io.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    let mut resp = StatusCode::SWITCHING_PROTOCOLS.into_response();
    let h = resp.headers_mut();
    h.insert("connection", "Upgrade".parse().unwrap());
    h.insert("upgrade", "websocket".parse().unwrap());
    h.insert("sec-websocket-accept", accept.parse().unwrap());
    resp
}

/// RFC 6455 的 Sec-WebSocket-Accept：base64(sha1(key + GUID))
fn ws_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hasher.finalize())
}

async fn echo(req: Request) -> impl IntoResponse {
    let (parts, body) = req.into_parts();
    let bytes: Bytes = axum::body::to_bytes(body, 2 * 1024 * 1024)
        .await
        .unwrap_or_default();

    let headers: serde_json::Map<String, Value> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(String::from_utf8_lossy(v.as_bytes()).to_string()),
            )
        })
        .collect();

    let text = String::from_utf8_lossy(&bytes).to_string();
    let payload = json!({
        "service": "optical-echo",
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "headers": headers,
        "body_len": bytes.len(),
        "body": text.chars().take(512).collect::<String>(),
    });

    (StatusCode::OK, Json(payload))
}
