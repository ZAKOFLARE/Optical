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
use sha2::{Digest, Sha256};
// 只挑需要的：`x509_parser::prelude::*` 会把它的 `time` 模块带进来，
// 把外部 `time` crate 遮掉（OffsetDateTime 会变成私有类型，报一堆莫名的错）。
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;
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
    /// 配置的证书加载失败、退回自签时的原因。空 = 没降级。
    /// 这个字段存在的意义就是"别让人对着一个 502 猜"。
    pub degraded: Option<String>,
}

/// `tls_dir` 是自签证书的落盘目录（来自 `[paths] tls_dir`），
/// `base_dir` 用于解析配置里的相对证书路径（以配置文件所在目录为准）。
pub fn build_acceptor(cfg: &TlsConfig, tls_dir: &Path, base_dir: &Path) -> Result<TlsMaterial> {
    install_crypto_provider();

    let dir = tls_dir.to_path_buf();
    std::fs::create_dir_all(&dir).ok();
    let dev_cert = dir.join("dev-cert.pem");
    let dev_key = dir.join("dev-key.pem");

    // 自签（无论是"本来就要自签"还是"配置的证书废了"）都走同一条路：
    // 把真实域名签进 SAN，否则 https://<域名> 上去永远报"证书不匹配"。
    let self_signed_material = || -> Result<(String, String)> {
        if dev_cert.exists() && dev_key.exists() {
            if let (Ok(c), Ok(k)) = (
                std::fs::read_to_string(&dev_cert),
                std::fs::read_to_string(&dev_key),
            ) {
                return Ok((c, k));
            }
        }
        generate_self_signed(&dir, &san_names(cfg), cfg.self_signed_days)
    };

    let configured = !(cfg.cert.trim().is_empty() || cfg.key.trim().is_empty());
    let mut degraded: Option<String> = None;

    // 先把配置的证书读出来并验证能装载；坏了再决定是降级还是拒绝
    let loaded: Option<(String, String)> = if configured {
        let cert_path = crate::config::resolve_one(&cfg.cert, base_dir);
        let key_path = crate::config::resolve_one(&cfg.key, base_dir);
        let attempt = (|| -> Result<(String, String)> {
            let cert = std::fs::read_to_string(&cert_path)
                .with_context(|| format!("读取证书失败: {}", cert_path.display()))?;
            let key = std::fs::read_to_string(&key_path)
                .with_context(|| format!("读取私钥失败: {}", key_path.display()))?;
            // 这里先试装一遍：私钥与证书不配对、算法不支持，都要在启动时暴露，
            // 而不是等浏览器握手失败
            build_config(cfg, &cert, &key)?;
            Ok((cert, key))
        })();
        match attempt {
            Ok(v) => Some(v),
            Err(e) => {
                if cfg.degrade == "strict" {
                    return Err(e.context("TLS 证书不可用，且 tls.degrade = strict"));
                }
                degraded = Some(format!("{e:#}"));
                tracing::error!(
                    error = %format!("{e:#}"),
                    "配置的 TLS 证书不可用，已退回自签证书继续服务（tls.degrade = self-signed）"
                );
                None
            }
        }
    } else {
        None
    };

    let (cert_pem, key_pem, self_signed, cert_path) = match loaded {
        Some((c, k)) => (c, k, false, None),
        None => {
            let (c, k) = self_signed_material().context("自签证书生成失败")?;
            (c, k, true, Some(dev_cert.clone()))
        }
    };

    let server = build_config(cfg, &cert_pem, &key_pem)?;

    Ok(TlsMaterial {
        acceptor: TlsAcceptor::from(Arc::new(server)),
        cert_path,
        self_signed,
        versions: if cfg.min_version == "1.3" { "TLS 1.3" } else { "TLS 1.2+" },
        degraded,
    })
}

/// 用一对 PEM 装出 rustls 配置。抽出来是为了"先验证再决定要不要降级"：
/// 证书与私钥不配对这件事，只有真装一遍才知道。
fn build_config(cfg: &TlsConfig, cert_pem: &str, key_pem: &str) -> Result<RustlsConfig> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
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

    // 会话复用显式配置，不依赖 rustls 默认值：
    // 默认值改了（或某天被裁剪）会悄悄退化成"每次完整握手"，性能掉一截还没日志。
    // TLS 1.2 会话缓存条数；0 = 关闭恢复
    server.session_storage =
        tokio_rustls::rustls::server::ServerSessionMemoryCache::new(cfg.session_cache_size);
    // TLS 1.3 会话票据开关：rustls 用"发送票据数量"表达，0 = 关。
    // 默认发 2 张，够客户端连开多条连接时各自恢复。
    server.send_tls13_tickets = if cfg.session_tickets { 2 } else { 0 };

    Ok(server)
}

/// 可热替换的 acceptor。
///
/// 定位很明确：**续签是 ACME 客户端的事，我们只负责从指定路径读**。
/// 所以这里不做签发、不做 OCSP、不碰文件写入——只盯着 cert/key 的
/// (长度, mtime) 指纹，变了就重新装载，握手继续用新证书。
///
/// 两条硬规矩：
/// 1. 新证书装载失败时**保留旧的那个**。ACME 客户端写文件不是原子的，
///    某一刻读到半截 PEM 是常态，这时候要是退回自签，等于把线上证书
///    换成了浏览器不认的那种——比不热载更糟。
/// 2. 指纹只在成功替换后更新。失败就下一轮重试，不会因为"试过了"而放弃。
pub struct HotAcceptor {
    inner: std::sync::RwLock<Arc<TlsAcceptor>>,
    cfg: TlsConfig,
    tls_dir: PathBuf,
    base_dir: PathBuf,
    /// 要盯的文件
    watch: Vec<PathBuf>,
    /// 上次成功装载时的指纹
    fp: std::sync::Mutex<String>,
    /// 当前生效的是不是自签（决定"新证书坏掉"要不要拦住）
    self_signed: std::sync::atomic::AtomicBool,
    /// 配置里是否显式指定了证书
    configured: bool,
}

impl HotAcceptor {
    pub fn new(cfg: &TlsConfig, tls_dir: &Path, base_dir: &Path, m: TlsMaterial) -> Self {
        let configured = !(cfg.cert.trim().is_empty() || cfg.key.trim().is_empty());
        let watch = if configured {
            vec![
                crate::config::resolve_one(&cfg.cert, base_dir),
                crate::config::resolve_one(&cfg.key, base_dir),
            ]
        } else {
            // 没配证书时也会重签（覆盖 dev-cert.pem），同样要能感知
            vec![tls_dir.join("dev-cert.pem"), tls_dir.join("dev-key.pem")]
        };
        let me = Self {
            inner: std::sync::RwLock::new(Arc::new(m.acceptor)),
            cfg: cfg.clone(),
            tls_dir: tls_dir.to_path_buf(),
            base_dir: base_dir.to_path_buf(),
            watch,
            fp: std::sync::Mutex::new(String::new()),
            self_signed: std::sync::atomic::AtomicBool::new(m.self_signed),
            configured,
        };
        // 基线必须在**建对象时**就取，不能留到第一次检查：
        // 启动后到第一次检查之间的 20 秒里，ACME 客户端完全可能已经把文件换了，
        // 那时再取基线，等于把新指纹当成起点，之后永远不触发替换
        // （线上实测踩过：touch 完等半分钟什么都没发生）。
        *me.fp.lock().unwrap_or_else(|e| e.into_inner()) = me.fingerprint();
        me
    }

    pub fn acceptor(&self) -> Arc<TlsAcceptor> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn fingerprint(&self) -> String {
        let mut out = String::new();
        for p in &self.watch {
            match std::fs::metadata(p) {
                Ok(m) => {
                    let mtime = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos())
                        .unwrap_or(0);
                    out.push_str(&format!("{}:{mtime}:{}|", p.display(), m.len()));
                }
                Err(_) => out.push_str(&format!("{}:missing|", p.display())),
            }
        }
        out
    }

    /// 文件变了就重新装载。`None` = 没变化；`Some(Ok)` = 已换新；`Some(Err)` = 试过但保留旧证书。
    pub fn maybe_reload(&self) -> Option<std::result::Result<String, String>> {
        let fp = self.fingerprint();
        {
            let cur = self.fp.lock().unwrap_or_else(|e| e.into_inner());
            // 首次检查：把当前指纹记下来当基线，不做替换
            if cur.is_empty() {
                drop(cur);
                *self.fp.lock().unwrap_or_else(|e| e.into_inner()) = fp;
                return None;
            }
            if *cur == fp {
                return None;
            }
        }

        match build_acceptor(&self.cfg, &self.tls_dir, &self.base_dir) {
            Ok(m) => {
                // 配置了真证书，但这次装出来的是自签 —— 说明新文件读不了或对不上，
                // 典型场景是 ACME 客户端正写到一半。保留旧证书，下一轮再看。
                if self.configured && m.self_signed {
                    let why = m.degraded.unwrap_or_else(|| "新证书暂时不可用".into());
                    return Some(Err(format!("证书文件已变化但无法装载，继续使用当前证书：{why}")));
                }
                let was = self
                    .self_signed
                    .load(std::sync::atomic::Ordering::Relaxed);
                *self.inner.write().unwrap_or_else(|e| e.into_inner()) =
                    Arc::new(m.acceptor);
                self.self_signed
                    .store(m.self_signed, std::sync::atomic::Ordering::Relaxed);
                *self.fp.lock().unwrap_or_else(|e| e.into_inner()) = fp;
                let msg = if was && !m.self_signed {
                    "已从自签切换为配置的证书".to_string()
                } else {
                    format!("证书已重新装载（{}）", m.versions)
                };
                Some(Ok(msg))
            }
            Err(e) => Some(Err(format!("重新装载证书失败：{e:#}"))),
        }
    }
}

/// 证书热载循环。20 秒一轮：ACME 续签是"天"级别的事，
/// 这里只是让"换了文件"到"生效"之间的窗口足够短，又不至于每秒 stat 一遍。
pub fn spawn_hot_reload(state: Arc<AppState>, hot: Arc<HotAcceptor>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            match hot.maybe_reload() {
                None => {}
                Some(Ok(msg)) => {
                    tracing::info!(%msg, "TLS 证书已热更新");
                    state.set_tls_degraded(None);
                    let cfg = state.snapshot().await;
                    state.audit.push(
                        &cfg.storage,
                        crate::storage::AuditEntry {
                            ts_ms: crate::storage::now_ms(),
                            kind: "tls.reload".into(),
                            detail: msg,
                            identity: String::new(),
                            path: "/tls".into(),
                            rule: "tls-hot-reload".into(),
                        },
                    );
                }
                Some(Err(e)) => {
                    // 只是 warn，不动 degraded：旧证书还在正常服务，
                    // 这时候标成"降级"会误导人以为线上已经换成自签了
                    tracing::warn!(error = %e, "证书文件变了但未能热更新，继续使用当前证书");
                }
            }
        }
    });
}

/// HTTPS 监听循环：先握手再交给同一套 handle。
pub async fn serve(state: Arc<AppState>, listener: TcpListener, hot: Arc<HotAcceptor>) -> Result<()> {
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

        // 每次 accept 现取：热更新换的是里面那个 Arc，已经建立的连接不受影响
        let acceptor = hot.acceptor();
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

/// 自签证书要签进去的名字：本机固定项 + 配置里的 san。
/// 顺序稳定（去重后排序），重复生成得到同样的 SAN 列表，便于比对。
fn san_names(cfg: &TlsConfig) -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    for n in &cfg.san {
        let n = n.trim();
        if !n.is_empty() {
            names.push(n.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

/// 生成并落盘自签证书 + 一份 sidecar 元数据（SAN / 起止时间）。
/// 存元数据是为了管理面能如实展示到期时间，而不是去解析 X.509。
fn generate_self_signed(
    dir: &Path,
    names: &[String],
    days: u32,
) -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate().context("生成自签私钥失败")?;
    let mut params = rcgen::CertificateParams::new(names.to_vec()).context("构造证书参数失败")?;
    // 证书有效期必须真的吃 self_signed_days，否则这个配置项就是摆设
    let days = days.clamp(1, 3650) as i64;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = params.not_before + time::Duration::days(days);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Optical Gateway");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Optical");
    let not_before = params.not_before.unix_timestamp();
    let not_after = params.not_after.unix_timestamp();
    let cert = params.self_signed(&key_pair).context("签发自签证书失败")?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    std::fs::write(dir.join("dev-cert.pem"), &cert_pem).ok();
    std::fs::write(dir.join("dev-key.pem"), &key_pem).ok();
    #[cfg(unix)]
    {
        // 默认 umask 会给 0644：自签私钥也是私钥，别的账户能读等于没有保护
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("dev-key.pem"), std::fs::Permissions::from_mode(0o600)).ok();
    }
    let meta = serde_json::json!({
        "names": names,
        "not_before": not_before,
        "not_after": not_after,
        "generated_at": time::OffsetDateTime::now_utc().unix_timestamp(),
    });
    std::fs::write(dir.join("dev-cert.json"), serde_json::to_vec_pretty(&meta)?).ok();
    Ok((cert_pem, key_pem))
}

/// 重签自签证书。外部托管的 cert/key 不碰——那是别人的证书，覆盖等于闯祸。
pub fn reset_self_signed(cfg: &TlsConfig, tls_dir: &Path, names: &[String]) -> Result<Vec<String>> {
    if !cfg.cert.is_empty() || !cfg.key.is_empty() {
        return Err(anyhow!(
            "配置里指定了 cert/key，证书由外部管理；请替换文件后重启，不要在网关上重签"
        ));
    }
    let dir = tls_dir.to_path_buf();
    std::fs::create_dir_all(&dir)?;
    let mut all = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    for n in names {
        let n = n.trim();
        if !n.is_empty() {
            all.push(n.to_string());
        }
    }
    all.sort();
    all.dedup();
    generate_self_signed(&dir, &all, cfg.self_signed_days)?;
    Ok(all)
}

/// 一张证书里我们真正需要展示的东西。
///
/// 不做信任链验证：网关没有 CA 库，也不该替运维判断"这张证书可不可信"——
/// 那是签发方和 ACME 客户端的事。这里只回答"它说自己是谁、什么时候过期、
/// 能不能真的拿它握上手"。
#[derive(Debug)]
pub struct CertFacts {
    /// SAN 里的域名与 IP（没写 SAN 时退回 CN）
    pub names: Vec<String>,
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
    /// 叶子证书的 SHA-256 指纹，跟 ACME 客户端打印的那串对得上
    pub fingerprint: String,
    /// 链上证书数量（叶子 + 中间）
    pub chain_len: usize,
}

/// 解析证书链（叶子在前）。
pub fn parse_chain(cert_pem: &str) -> Result<CertFacts> {
    let ders: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .context("证书 PEM 解析失败")?;
    let leaf = ders
        .first()
        .ok_or_else(|| anyhow!("PEM 里没有 CERTIFICATE 块（是不是把私钥贴到证书框了？）"))?;

    let (_, cert) = parse_x509_certificate(leaf.as_ref())
        .map_err(|e| anyhow!("X.509 解析失败: {e}"))?;

    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            match gn {
                GeneralName::DNSName(d) => names.push((*d).to_string()),
                GeneralName::IPAddress(raw) => {
                    if let Some(ip) = ip_from_bytes(raw) {
                        names.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    if names.is_empty() {
        if let Some(cn) = cert.subject().iter_common_name().next().and_then(|c| c.as_str().ok()) {
            names.push(cn.to_string());
        }
    }
    names.sort();
    names.dedup();

    let digest = Sha256::digest(leaf.as_ref());
    let fingerprint = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();

    Ok(CertFacts {
        names,
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        fingerprint,
        chain_len: ders.len(),
    })
}

/// SAN 里的 IP 是 4 或 16 字节裸地址，转成人能看的写法。
fn ip_from_bytes(raw: &[u8]) -> Option<String> {
    match raw.len() {
        4 => Some(std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string()),
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(raw);
            Some(std::net::Ipv6Addr::from(b).to_string())
        }
        _ => None,
    }
}

/// 校验"这对证书和私钥能不能真的用起来"。
///
/// 最硬的检查就是把它装进 rustls：算法不支持、链和私钥不匹配，都会在这一步现原形，
/// 而不是等重启后浏览器报 ERR_SSL_*，再回来猜是哪一步错了。
pub fn check_pair(cert_pem: &str, key_pem: &str) -> Result<CertFacts> {
    let facts = parse_chain(cert_pem)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .context("证书 PEM 解析失败")?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("私钥 PEM 解析失败")?
        .ok_or_else(|| anyhow!("私钥里没有 PKCS#8 / PKCS#1 / SEC1 内容"))?;

    install_crypto_provider();
    RustlsConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("证书与私钥对不上，或密钥算法不受支持")?;

    Ok(facts)
}

/// 备份后落盘：证书 0644、私钥 0600。
/// 权限错一次就等于把私钥公开，这里不交给 umask 决定。
pub fn write_material(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Vec<PathBuf>> {
    for p in [cert_path, key_path] {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("创建证书目录失败: {}", dir.display()))?;
        }
    }

    let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut backups = Vec::new();
    for p in [cert_path, key_path] {
        if !p.exists() {
            continue;
        }
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "cert".into());
        let bak = p.with_file_name(format!("{name}.bak.{stamp}"));
        if std::fs::copy(p, &bak).is_ok() {
            backups.push(bak);
        }
    }

    std::fs::write(cert_path, cert_pem)
        .with_context(|| format!("写入证书失败: {}", cert_path.display()))?;
    std::fs::write(key_path, key_pem)
        .with_context(|| format!("写入私钥失败: {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("设置私钥权限失败: {}", key_path.display()))?;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644)).ok();
    }

    // 备份只留最近三份：证书轮换很频繁，不清理会把目录塞满
    prune_backups(cert_path, 3);
    prune_backups(key_path, 3);
    Ok(backups)
}

fn prune_backups(path: &Path, keep: usize) {
    let Some(dir) = path.parent() else { return };
    let Some(name) = path.file_name().map(|s| s.to_string_lossy().to_string()) else {
        return;
    };
    let prefix = format!("{name}.bak.");
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut found: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
        .map(|e| e.path())
        .collect();
    // 文件名里的时间戳是定长的，字典序即时间序
    found.sort();
    while found.len() > keep {
        let old = found.remove(0);
        let _ = std::fs::remove_file(old);
    }
}

/// 管理面用的证书概况
pub fn describe(cfg: &TlsConfig, tls_dir: &Path, base_dir: &Path) -> serde_json::Value {
    let external = !cfg.cert.is_empty() && !cfg.key.is_empty();
    let (cert_path, key_path) = if external {
        (
            crate::config::resolve_one(&cfg.cert, base_dir),
            crate::config::resolve_one(&cfg.key, base_dir),
        )
    } else {
        (tls_dir.join("dev-cert.pem"), tls_dir.join("dev-key.pem"))
    };
    let exists = cert_path.exists() && key_path.exists();
    let mut names: Vec<String> = Vec::new();
    let mut not_after = 0i64;
    let mut not_before = 0i64;
    let mut issuer = String::new();
    let mut fingerprint = String::new();
    let mut chain_len = 0usize;

    // 先解析真实证书：外部证书没有 sidecar，以前这一栏永远是空的
    // （"证书明明装了，页面上域名和到期时间却显示 —"），现在按文件说话。
    if cert_path.exists() {
        if let Ok(raw) = std::fs::read_to_string(&cert_path) {
            if let Ok(f) = parse_chain(&raw) {
                names = f.names;
                not_before = f.not_before;
                not_after = f.not_after;
                issuer = f.issuer;
                fingerprint = f.fingerprint;
                chain_len = f.chain_len;
            }
        }
    }

    // 自签证书有 sidecar 元数据，解析失败时（比如文件被换掉了）退回它
    if !external && names.is_empty() {
        if let Ok(raw) = std::fs::read_to_string(tls_dir.join("dev-cert.json")) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                names = v["names"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                not_after = v["not_after"].as_i64().unwrap_or(0);
                not_before = v["not_before"].as_i64().unwrap_or(0);
            }
        }
    }
    let modified = std::fs::metadata(&cert_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    serde_json::json!({
        "enabled": cfg.enabled,
        "listen": cfg.listen,
        "listen_v6": cfg.listen_v6,
        "min_version": cfg.min_version,
        "self_signed": !external,
        "cert_path": cert_path.display().to_string(),
        "key_path": key_path.display().to_string(),
        "exists": exists,
        "names": names,
        "configured_san": cfg.san,
        "issuer": issuer,
        "fingerprint": fingerprint,
        "chain_len": chain_len,
        "expired": not_after > 0 && not_after <= time::OffsetDateTime::now_utc().unix_timestamp(),
        "http_redirect": cfg.http_redirect,
        "not_before": not_before,
        "not_after": not_after,
        "cert_mtime": modified,
        "generated_at": if exists { modified } else { 0 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 造一对测试用的自签材料，避免测试依赖外部证书文件
    fn test_pair(names: &[&str]) -> (String, String) {
        let kp = rcgen::KeyPair::generate().unwrap();
        let list: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let params = rcgen::CertificateParams::new(list).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem(), kp.serialize_pem())
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "optical-tls-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn broken_cert_falls_back_to_self_signed_instead_of_killing_https() {
        // 这是线上真实踩过的坑：证书路径写错 → 443 直接不监听 → CDN 回源失败 → 用户看到 502。
        // 证书是"更好的锁"，不是"门本身"：锁坏了不该把门焊死。
        let dir = tmpdir("degrade");
        let mut cfg = TlsConfig::default();
        cfg.enabled = true;
        cfg.cert = "/nonexistent/cert.pem".into();
        cfg.key = "/nonexistent/key.pem".into();
        cfg.degrade = "self-signed".into();

        let m = build_acceptor(&cfg, &dir, &dir).expect("证书坏了也要能起来");
        assert!(m.self_signed, "应退回自签");
        assert!(m.degraded.is_some(), "必须留下降级原因，否则又在让人猜");
        assert!(m.degraded.unwrap().contains("证书"), "原因要说清是证书的问题");
        assert!(dir.join("dev-cert.pem").exists(), "自签材料要落盘复用");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strict_mode_refuses_to_start_without_a_usable_cert() {
        let dir = tmpdir("strict");
        let mut cfg = TlsConfig::default();
        cfg.enabled = true;
        cfg.cert = "/nonexistent/cert.pem".into();
        cfg.key = "/nonexistent/key.pem".into();
        cfg.degrade = "strict".into();
        match build_acceptor(&cfg, &dir, &dir) {
            Ok(_) => panic!("strict 模式下不该起得来"),
            Err(e) => assert!(format!("{e:#}").contains("strict"), "{e:#}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mismatched_key_is_detected_at_startup() {
        // 证书和私钥不是一对：装载时就该炸，而不是等浏览器握手失败
        let dir = tmpdir("mismatch");
        let (cert_a, _key_a) = test_pair(&["a.example.com"]);
        let (_cert_b, key_b) = test_pair(&["b.example.com"]);
        std::fs::write(dir.join("c.pem"), &cert_a).unwrap();
        std::fs::write(dir.join("k.pem"), &key_b).unwrap();

        let mut cfg = TlsConfig::default();
        cfg.enabled = true;
        cfg.cert = dir.join("c.pem").display().to_string();
        cfg.key = dir.join("k.pem").display().to_string();
        cfg.degrade = "self-signed".into();
        let m = build_acceptor(&cfg, &dir, &dir).expect("降级模式下仍要能起来");
        assert!(m.degraded.is_some(), "错配要给出原因");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn good_cert_is_used_as_is_and_not_marked_degraded() {
        let dir = tmpdir("good");
        let (cert, key) = test_pair(&["good.example.com"]);
        std::fs::write(dir.join("c.pem"), &cert).unwrap();
        std::fs::write(dir.join("k.pem"), &key).unwrap();
        let mut cfg = TlsConfig::default();
        cfg.enabled = true;
        cfg.cert = dir.join("c.pem").display().to_string();
        cfg.key = dir.join("k.pem").display().to_string();
        let m = build_acceptor(&cfg, &dir, &dir).unwrap();
        assert!(!m.self_signed);
        assert!(m.degraded.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn session_resumption_flags_are_applied() {
        let (c, k) = test_pair(&["a.example.com"]);
        let mut cfg = TlsConfig::default();
        // 票据关闭 → rustls 发 0 张
        cfg.session_tickets = false;
        let sc = build_config(&cfg, &c, &k).unwrap();
        assert_eq!(sc.send_tls13_tickets, 0, "session_tickets=false 时应发 0 张票据");
        // 开启 → 默认发 2 张
        cfg.session_tickets = true;
        let sc = build_config(&cfg, &c, &k).unwrap();
        assert_eq!(sc.send_tls13_tickets, 2, "session_tickets=true 时应发 2 张票据");
    }

    #[test]
    fn hot_acceptor_picks_up_replaced_certificate() {
        let dir = tmpdir("hot-ok");
        let (c1, k1) = test_pair(&["one.example.com"]);
        std::fs::write(dir.join("c.pem"), &c1).unwrap();
        std::fs::write(dir.join("k.pem"), &k1).unwrap();
        let mut cfg = TlsConfig::default();
        cfg.enabled = true;
        cfg.cert = dir.join("c.pem").display().to_string();
        cfg.key = dir.join("k.pem").display().to_string();

        let m = build_acceptor(&cfg, &dir, &dir).unwrap();
        let hot = HotAcceptor::new(&cfg, &dir, &dir, m);
        assert!(hot.maybe_reload().is_none(), "第一次只建基线，不做替换");

        // 模拟 ACME 客户端换上新证书
        let (c2, k2) = test_pair(&["two.example.com"]);
        std::fs::write(dir.join("c.pem"), &c2).unwrap();
        std::fs::write(dir.join("k.pem"), &k2).unwrap();
        let r = hot.maybe_reload().expect("文件变了就该尝试");
        assert!(r.is_ok(), "{r:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hot_acceptor_keeps_old_cert_when_new_file_is_broken() {
        // ACME 客户端写文件不是原子的：读到半截 PEM 是常态。
        // 这时候必须继续用旧的，绝不能退回自签把线上证书换掉。
        let dir = tmpdir("hot-broken");
        let (c1, k1) = test_pair(&["one.example.com"]);
        std::fs::write(dir.join("c.pem"), &c1).unwrap();
        std::fs::write(dir.join("k.pem"), &k1).unwrap();
        let mut cfg = TlsConfig::default();
        cfg.enabled = true;
        cfg.cert = dir.join("c.pem").display().to_string();
        cfg.key = dir.join("k.pem").display().to_string();
        cfg.degrade = "self-signed".into();

        let m = build_acceptor(&cfg, &dir, &dir).unwrap();
        let hot = HotAcceptor::new(&cfg, &dir, &dir, m);
        hot.maybe_reload();
        let before = hot.acceptor();

        std::fs::write(dir.join("c.pem"), "-----BEGIN CERTIFICATE-----\ntrunc").unwrap();
        let r = hot.maybe_reload().expect("文件变了就该尝试");
        assert!(r.is_err(), "坏文件不该被接受：{r:?}");
        assert!(
            std::sync::Arc::ptr_eq(&before, &hot.acceptor()),
            "装载失败必须保留旧的 acceptor"
        );

        // 下一轮还能重试（指纹没被错误地更新成新值）
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parsed_cert_reports_names_and_validity() {
        let (cert, _key) = test_pair(&["a.example.com", "*.example.com"]);
        let f = parse_chain(&cert).unwrap();
        assert!(f.names.contains(&"a.example.com".to_string()), "{:?}", f.names);
        assert!(f.names.contains(&"*.example.com".to_string()), "{:?}", f.names);
        assert!(f.not_after > f.not_before);
        assert_eq!(f.chain_len, 1);
        assert_eq!(f.fingerprint.len(), 64, "SHA-256 十六进制应该是 64 个字符");
    }

    #[test]
    fn mismatched_key_is_rejected() {
        // 拿 A 的证书配 B 的私钥：必须在保存前就拒绝，而不是等重启后浏览器报错
        let (cert_a, _key_a) = test_pair(&["a.example.com"]);
        let (_cert_b, key_b) = test_pair(&["b.example.com"]);
        assert!(check_pair(&cert_a, &key_b).is_err());
    }

    #[test]
    fn matching_pair_passes() {
        let (cert, key) = test_pair(&["a.example.com"]);
        assert!(check_pair(&cert, &key).is_ok());
    }

    #[test]
    fn cert_box_with_private_key_says_so() {
        // 把私钥贴进证书框是最常见的误操作，报错得直说
        let (_cert, key) = test_pair(&["a.example.com"]);
        let err = parse_chain(&key).unwrap_err().to_string();
        assert!(err.contains("CERTIFICATE"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_written_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("optical-tls-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = test_pair(&["a.example.com"]);
        let cp = dir.join("c.pem");
        let kp = dir.join("k.pem");
        write_material(&cp, &kp, &cert, &key).unwrap();
        let mode = std::fs::metadata(&kp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "私钥权限必须是 0600，实际 {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_material_is_backed_up_and_pruned() {
        let dir = std::env::temp_dir().join(format!("optical-tls-bak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cp = dir.join("c.pem");
        let kp = dir.join("k.pem");
        let (cert, key) = test_pair(&["a.example.com"]);

        // 连写四次：备份应只保留最近三份，别把目录塞满
        for _ in 0..4 {
            write_material(&cp, &kp, &cert, &key).unwrap();
            // 时间戳精度是秒，同一秒内会重名，手动错开
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("c.pem.bak."))
            .collect();
        assert!(backups.len() <= 3, "备份数量 {}", backups.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
