//! TLS 1.2 / 1.3 终止。
//!
//! 证书来源两种：配置里写 PEM 路径，或者留空让网关自己生成一份自签开发证书（落盘复用，
//! 免得每次重启都让浏览器重新点"仍然继续"）。
//!
//! 最低版本由 `tls.min_version` 决定：`1.3` 时只装载 TLS1.3，`1.2` 时两者都开。

use crate::config::TlsConfig;
use crate::proxy::{self, Clients};
use crate::state::AppState;
use anyhow::{anyhow, Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::ServerConfig as RustlsConfig;
use tokio_rustls::TlsAcceptor;

/// 初始化加密后端（rustls 0.23 要求显式安装 CryptoProvider）。
pub fn install_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

pub struct TlsMaterial {
    pub acceptor: TlsAcceptor,
    /// 自签时返回证书路径，方便运维去信任它
    pub cert_path: Option<PathBuf>,
    pub self_signed: bool,
    pub versions: &'static str,
}

/// `tls_dir` 是自签证书的落盘目录（来自 `[paths] tls_dir`），
/// `base_dir` 用于解析配置里的相对证书路径（以配置文件所在目录为准）。
pub fn build_acceptor(cfg: &TlsConfig, tls_dir: &Path, base_dir: &Path) -> Result<TlsMaterial> {
    install_crypto_provider();

    let (cert_pem, key_pem, self_signed, cert_path) = if cfg.cert.is_empty() || cfg.key.is_empty() {
        let dir = tls_dir.to_path_buf();
        std::fs::create_dir_all(&dir).ok();
        let cert_path = dir.join("dev-cert.pem");
        let key_path = dir.join("dev-key.pem");
        if cert_path.exists() && key_path.exists() {
            (
                std::fs::read_to_string(&cert_path)?,
                std::fs::read_to_string(&key_path)?,
                true,
                Some(cert_path),
            )
        } else {
            let names = vec![
                "localhost".to_string(),
                "optical.local".to_string(),
                "127.0.0.1".to_string(),
            ];
            let key_pair = rcgen::KeyPair::generate().context("生成自签私钥失败")?;
            let mut params = rcgen::CertificateParams::new(names).context("构造证书参数失败")?;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Optical Dev Gateway");
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationName, "Optical");
            let cert = params.self_signed(&key_pair).context("签发自签证书失败")?;
            let cert_pem = cert.pem();
            let key_pem = key_pair.serialize_pem();
            std::fs::write(&cert_path, &cert_pem).ok();
            std::fs::write(&key_path, &key_pem).ok();
            (cert_pem, key_pem, true, Some(cert_path))
        }
    } else {
        let cert_path = crate::config::resolve_one(&cfg.cert, base_dir);
        let key_path = crate::config::resolve_one(&cfg.key, base_dir);
        let cert = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("读取证书失败: {}", cert_path.display()))?;
        let key = std::fs::read_to_string(&key_path)
            .with_context(|| format!("读取私钥失败: {}", key_path.display()))?;
        (cert, key, false, None)
    };

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<_, _>>()
            .context("解析证书 PEM 失败")?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("解析私钥 PEM 失败")?
        .ok_or_else(|| anyhow!("私钥文件里没有 PKCS#8/PKCS#1/SEC1 私钥"))?;

    // 用 const 静态切片，避免临时数组的借用问题
    const TLS13_ONLY: &[&tokio_rustls::rustls::SupportedProtocolVersion] =
        &[&tokio_rustls::rustls::version::TLS13];
    const TLS12_AND_13: &[&tokio_rustls::rustls::SupportedProtocolVersion] = &[
        &tokio_rustls::rustls::version::TLS13,
        &tokio_rustls::rustls::version::TLS12,
    ];
    let versions = if cfg.min_version == "1.3" {
        TLS13_ONLY
    } else {
        TLS12_AND_13
    };

    let mut server = RustlsConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("装载证书失败")?;

    // 只允许 HTTP/1.1 与 h2，别把 ALPN 交给默认值
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsMaterial {
        acceptor: TlsAcceptor::from(Arc::new(server)),
        cert_path,
        self_signed,
        versions: if cfg.min_version == "1.3" { "TLS 1.3" } else { "TLS 1.2+" },
    })
}

/// HTTPS 监听循环：先握手再交给同一套 handle。
pub async fn serve(state: Arc<AppState>, listener: TcpListener, acceptor: TlsAcceptor) -> Result<()> {
    let clients = Clients::new();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "TLS accept 失败");
                continue;
            }
        };
        let (max_active, max_per_sec) = state.config_for_limits();
        let Some(guard) = state.try_acquire_conn(peer.ip(), max_active, max_per_sec) else {
            tracing::warn!(%peer, "TLS 连接数超限");
            drop(stream);
            continue;
        };

        let acceptor = acceptor.clone();
        let state = state.clone();
        let clients = clients.clone();

        tokio::spawn(async move {
            let tls = match tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::debug!(%peer, error = %e, "TLS 握手失败");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "TLS 握手超时");
                    return;
                }
            };
            state
                .metrics
                .tls_handshakes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let io = TokioIo::new(tls);
            let builder = auto::Builder::new(TokioExecutor::new());
            let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                let state = state.clone();
                let clients = clients.clone();
                async move {
                    let resp = proxy::handle(req, state, clients, peer, "https").await;
                    Ok::<_, Infallible>(resp)
                }
            });
            if let Err(err) = builder.serve_connection_with_upgrades(io, svc).await {
                tracing::debug!(%peer, error = %err, "TLS 连接结束");
            }
            drop(guard);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_material_is_created() {
        let dir = std::env::temp_dir().join(format!("optical-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = TlsConfig {
            enabled: true,
            cert: String::new(),
            key: String::new(),
            ..Default::default()
        };
        let m = build_acceptor(&cfg, &dir, &dir).unwrap();
        assert!(m.self_signed);
        assert!(m.cert_path.unwrap().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls13_only_versions() {
        let dir = std::env::temp_dir().join(format!("optical-tls13-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = TlsConfig {
            enabled: true,
            min_version: "1.3".into(),
            ..Default::default()
        };
        let m = build_acceptor(&cfg, &dir, &dir).unwrap();
        assert_eq!(m.versions, "TLS 1.3");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
