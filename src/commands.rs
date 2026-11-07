//! 子命令实现。
//!
//! 约定：CLI 的写操作 = 改同一份 TOML + 尽力通知运行中的实例立即重载
//! （通知失败也无所谓，进程内的 mtime 轮询 1s 内一定会捡到）。
//!
//! 管理面开了认证之后，CLI 用进程启动时写下的本地令牌（0600）访问 API，
//! 不是靠"回环免登录"这种口子。

use crate::cli::{ConfigCmd, RouteCmd, StatusArgs};
use crate::config::{Config, Overrides};
use crate::state::{spawn_sampler, spawn_watcher, AppState};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub fn init_logging(level: &str) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| level.to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_new(&filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

// ---------- 启动网关 ----------

pub async fn run_gateway(config_opt: Option<PathBuf>, args: crate::cli::RunArgs) -> Result<()> {
    let path = crate::config::resolve_path(config_opt);
    let (mut cfg, created) = Config::load_or_init(&path)?;

    // 首次启动没配口令 → 生成随机口令，只存哈希，明文打印一次
    let generated_pw = crate::admin::ensure_admin_password(&mut cfg.admin);
    if generated_pw.is_some() {
        cfg.save(&path).ok();
    }

    let overrides = Overrides {
        listen: args.listen,
        admin_listen: args.admin_listen,
        upstream: args.upstream,
        timeout_ms: args.timeout_ms,
        log_level: args.log_level,
    };
    overrides.apply(&mut cfg);
    cfg.validate_ok_in(base_dir_of(&path))?;
    init_logging(&cfg.server.log_level);

    if created {
        tracing::info!(path = %path.display(), "未找到配置文件，已生成示例配置");
    }
    if !overrides.is_empty() {
        tracing::info!("启动参数覆盖已生效（仅本次运行，不会写回文件）");
    }

    let abs_path = absolutize(&path);
    let state = Arc::new(AppState::new(cfg.clone(), abs_path.clone(), overrides));
    spawn_watcher(state.clone());
    spawn_sampler(state.clone());

    // 后端健康检查：每秒扫一遍，各后端按自己的间隔执行
    {
        let st = state.clone();
        crate::backends::spawn_health_checks(state.backends.clone(), move || st.try_config());
    }

    // CLI 本地会话：启动签发 → 落盘 0600 → 退出删除
    let token_path = abs_path.with_extension("token");
    let cli_token = format!("cli-{}", crate::auth::random_password(32));
    state
        .auth
        .add_session(&cli_token, cfg.admin.session_ttl_secs.max(3600) * 24);
    write_token(&token_path, &cli_token);

    let gw_listener = bind(&cfg.server.listen, "网关").await?;
    let admin_listener = bind(&cfg.server.admin_listen, "管理面").await?;

    // 可选 IPv6：留空即关闭，不猜系统有没有 v6
    let gw_v6 = if cfg.server.listen_v6.trim().is_empty() {
        None
    } else {
        Some(bind(&cfg.server.listen_v6, "网关 IPv6").await?)
    };
    let admin_v6 = if cfg.server.admin_listen_v6.trim().is_empty() {
        None
    } else {
        Some(bind(&cfg.server.admin_listen_v6, "管理面 IPv6").await?)
    };

    let tls_setup = if cfg.tls.enabled {
        match bind(&cfg.tls.listen, "HTTPS").await {
            Ok(l) => {
                match crate::tls::build_acceptor(&cfg.tls, &state.paths.tls_dir, state.base_dir()) {
                    Ok(m) => {
                        let l6 = if cfg.tls.listen_v6.trim().is_empty() {
                            None
                        } else {
                            match bind(&cfg.tls.listen_v6, "HTTPS IPv6").await {
                                Ok(x) => Some(x),
                                Err(e) => {
                                    tracing::error!(error = %e, "HTTPS IPv6 监听失败");
                                    None
                                }
                            }
                        };
                        Some((l, l6, m))
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "TLS 初始化失败，HTTPS 端口不启动");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "HTTPS 监听失败");
                None
            }
        }
    } else {
        None
    };

    banner(
        &cfg,
        &abs_path,
        generated_pw.as_deref(),
        tls_setup.as_ref().map(|(_, _, m)| m),
    );

    if let Some((listener, listener_v6, material)) = tls_setup {
        let acceptor = material.acceptor.clone();
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::tls::serve(st, listener, acceptor).await {
                tracing::error!(error = %e, "HTTPS 监听退出");
            }
        });
        if let Some(l6) = listener_v6 {
            let st = state.clone();
            let acceptor = material.acceptor;
            tokio::spawn(async move {
                if let Err(e) = crate::tls::serve(st, l6, acceptor).await {
                    tracing::error!(error = %e, "HTTPS IPv6 监听退出");
                }
            });
        }
    }

    if let Some(l6) = gw_v6 {
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::proxy::serve(st, l6).await {
                tracing::error!(error = %e, "网关 IPv6 监听退出");
            }
        });
    }
    if let Some(l6) = admin_v6 {
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::admin::serve(st, l6).await {
                tracing::error!(error = %e, "管理面 IPv6 监听退出");
            }
        });
    }

    if !cfg.extensions.filters.is_empty() {
        tracing::warn!(
            filters = ?cfg.extensions.filters,
            "extensions.filters 需要自研插件实现；当前由 WAF 引擎承担过滤，这些名称已跳过"
        );
    }

    tokio::select! {
        r = crate::proxy::serve(state.clone(), gw_listener) => r?,
        r = crate::admin::serve(state.clone(), admin_listener) => r?,
        _ = shutdown_signal() => {
            tracing::info!("收到退出信号，关闭监听");
        }
    }
    let _ = std::fs::remove_file(&token_path);
    Ok(())
}

/// 0600 写令牌文件：只有本机同用户可以读。
fn write_token(path: &Path, token: &str) {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(path) {
        let _ = writeln!(f, "{token}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

fn load_token(config_path: &Path) -> Option<String> {
    let p = absolutize(config_path).with_extension("token");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn bind(addr: &str, label: &str) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("{label}监听失败（{addr}），端口可能已被占用"))
}

fn banner(cfg: &Config, path: &Path, generated_pw: Option<&str>, tls: Option<&crate::tls::TlsMaterial>) {
    println!();
    println!("  OPTICAL  v{}", env!("CARGO_PKG_VERSION"));
    println!("  ----------------------------------------------------------------");
    println!("  gateway   http://{}", cfg.server.listen);
    if let Some(m) = tls {
        println!(
            "  https     https://{}  [{}]{}",
            cfg.tls.listen,
            m.versions,
            if m.self_signed { "  自签证书" } else { "" }
        );
        if let Some(p) = &m.cert_path {
            println!("  cert      {}", p.display());
        }
    }
    if !cfg.server.listen_v6.trim().is_empty() {
        println!("  gateway6  http://{}", cfg.server.listen_v6);
    }
    println!("  webui     http://{}", cfg.server.admin_listen);
    if !cfg.server.admin_listen_v6.trim().is_empty() {
        println!("  webui6    http://{}", cfg.server.admin_listen_v6);
    }
    if !cfg.tls.listen_v6.trim().is_empty() {
        println!("  https6    https://{}", cfg.tls.listen_v6);
    }
    println!("  upstream  {}", cfg.server.default_upstream);
    println!(
        "  routes    {}    backends {}    groups {}",
        cfg.routes.len(),
        cfg.backends.len(),
        cfg.backend_groups.len()
    );
    println!(
        "  lb        {}",
        cfg.server.lb.label()
    );
    println!(
        "  waf       {}  mode={:?}  threshold={}  header_rules {}",
        if cfg.waf.enabled { "on " } else { "off" },
        cfg.waf.mode,
        cfg.waf.score_threshold,
        cfg.header_rules.len()
    );
    println!("  config    {}", path.display());
    println!("  data      {}", cfg.resolve_paths(path).data_dir.display());
    // 不在 PATH 里就别让人每次敲 ./target/release/optical
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if !dir_in_path(dir) {
                println!("  tip       把 optical 装成全局命令（一次性）：optical install");
            }
        }
    }
    println!("  ----------------------------------------------------------------");
    if cfg.admin.enabled {
        match generated_pw {
            Some(pw) => {
                println!("  管理面首次启动，已生成登录口令（配置里只存哈希）：");
                println!("    用户名  {}", cfg.admin.username);
                println!("    口令    {pw}");
                println!("  登录后请在 WebUI「安全」里改掉。");
            }
            None => println!("  管理面认证：用户名 {}", cfg.admin.username),
        }
        if cfg.admin.totp_enabled {
            println!("  二次验证：已开启（TOTP）");
        }
    } else {
        println!("  管理面认证：已关闭（admin.enabled = false）");
    }
    println!();
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// 配置校验/证书解析的基准目录：配置文件所在目录（没有目录时用当前目录）。
pub(crate) fn base_dir_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

// ---------- config ----------

/// 安装目录：Unix 用 ~/.local/bin（不需要 root），Windows 用 %LOCALAPPDATA%\Programs\Optical。
fn default_install_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var("LOCALAPPDATA")
            .or_else(|_| std::env::var("USERPROFILE").map(|p| format!("{p}\\AppData\\Local")))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(base).join("Programs").join("Optical")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".local").join("bin")
    }
}

fn trim_sep(s: &str) -> String {
    s.trim_end_matches(['/', '\\']).to_lowercase()
}

fn dir_in_path(dir: &Path) -> bool {
    let want = trim_sep(&dir.to_string_lossy());
    std::env::var("PATH")
        .unwrap_or_default()
        .split(if cfg!(windows) { ';' } else { ':' })
        .any(|p| trim_sep(p) == want)
}

/// 把安装目录写进 PATH。
/// Unix 写进 shell rc（幂等）；Windows 只改"用户变量"，不碰系统 PATH，也不重排已有条目。
fn add_to_path(dir: &Path) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    let disp = dir.display().to_string();

    if cfg!(windows) {
        notes.push(win_user_path_note(&disp));
        return Ok(notes);
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let line = format!("export PATH=\"{disp}:$PATH\"  # added by optical install");
    let mut touched = Vec::new();
    let mut already = false;
    for rc in [".bashrc", ".zshrc", ".profile"] {
        let path = PathBuf::from(&home).join(rc);
        if !path.exists() {
            continue;
        }
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        if body.contains("added by optical install") && body.contains(&disp) {
            already = true;
            continue;
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&path) {
            let _ = writeln!(f, "\n{line}");
            touched.push(rc.to_string());
        }
    }
    if !touched.is_empty() {
        notes.push(format!(
            "已把 {disp} 加进 {}（重开终端或 source 一下生效）",
            touched.join(" / ")
        ));
    } else if already {
        notes.push(format!("{disp} 已在 shell 配置里，没有重复写入"));
    } else {
        notes.push(format!(
            "{disp} 没有可写入的 shell 配置；需要时手动加：{line}"
        ));
    }
    Ok(notes)
}

/// Windows 上改用户 PATH。用 PowerShell 的 [Environment] API 而不是 setx：
/// setx 会在 1024 字符处截断 PATH，那是能把整台机器搞坏的操作。
#[cfg(windows)]
fn win_user_path_note(disp: &str) -> String {
    let escaped = disp.replace('\'', "''");
    let script = format!(
        "$p=[Environment]::GetEnvironmentVariable('Path','User'); \
         if ($null -eq $p) {{ $p='' }}; \
         if ($p -notlike '*{d}*') {{ \
           [Environment]::SetEnvironmentVariable('Path', (($p.TrimEnd(';') + ';{d}').TrimStart(';')), 'User'); \
           Write-Output 'added' }} else {{ Write-Output 'exists' }}",
        d = escaped
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();
    match out {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("added") => {
            format!("已把 {disp} 写入用户 PATH（新开终端生效）")
        }
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("exists") => {
            format!("{disp} 已在用户 PATH 里")
        }
        Ok(o) => format!(
            "没能自动改 PATH（{}）；手动加：设置 → 系统 → 环境变量 → 用户变量 Path → 新建 {disp}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!(
            "没能自动改 PATH（{e}）；手动加：设置 → 系统 → 环境变量 → 用户变量 Path → 新建 {disp}"
        ),
    }
}

#[cfg(not(windows))]
fn win_user_path_note(disp: &str) -> String {
    disp.to_string()
}

pub async fn totp_cmd(config_opt: Option<PathBuf>, cmd: crate::cli::TotpCmd) -> Result<()> {
    let path = crate::config::resolve_path(config_opt);
    let mut cfg = Config::load(&path)?;
    use crate::cli::TotpCmd;
    match cmd {
        TotpCmd::Status => {
            println!("  config      {}", path.display());
            println!("  enabled     {}", cfg.admin.totp_enabled);
            println!("  algorithm   {}", cfg.admin.totp_algorithm.otpauth_name());
            println!(
                "  secret      {}",
                if cfg.admin.totp_secret.is_empty() {
                    "（未设置）".to_string()
                } else {
                    format!("已设置（{} 位 Base32，不在终端回显）", cfg.admin.totp_secret.len())
                }
            );
        }
        TotpCmd::Off => {
            let was = cfg.admin.totp_enabled;
            cfg.admin.totp_enabled = false;
            cfg.admin.totp_secret = String::new();
            cfg.validate_ok_in(path.parent().unwrap_or(Path::new(".")))?;
            cfg.save(&path)?;
            println!(
                "  已关闭 2FA{}，密钥已清除。运行中的实例会在 1 秒内热重载生效。",
                if was { "" } else { "（本来就是关的）" }
            );
            println!("  重新配置：WebUI「安全」→ 生成密钥 → 用 App 扫 → 填验证码点「验证」→ 保存");
        }
    }
    Ok(())
}

pub async fn install_cmd(args: crate::cli::InstallArgs) -> Result<()> {
    let exe = std::env::current_exe().context("拿不到当前可执行文件路径")?;
    let dir = args.dir.clone().unwrap_or_else(default_install_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("创建安装目录失败: {}", dir.display()))?;

    let name = exe
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from(if cfg!(windows) {
            "optical.exe"
        } else {
            "optical"
        }));
    let target = dir.join(&name);

    if target == exe {
        println!("  {} 就是当前位置，无需复制", target.display());
    } else {
        if target.exists() && !args.force {
            anyhow::bail!(
                "{} 已存在。要覆盖请加 --force（或先删掉它）",
                target.display()
            );
        }
        // 先复制到临时名再 rename：正在运行的旧二进制在 Windows 上不能被覆盖，
        // 但可以被改名——这样"覆盖安装"不会因为进程占用而失败。
        let tmp = dir.join(format!("{}.new", name.to_string_lossy()));
        std::fs::copy(&exe, &tmp).with_context(|| format!("复制到 {} 失败", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        }
        if target.exists() {
            let old = dir.join(format!("{}.old", name.to_string_lossy()));
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::rename(&target, &old);
        }
        std::fs::rename(&tmp, &target)
            .with_context(|| format!("安装到 {} 失败", target.display()))?;
        println!("  已安装  {}", target.display());
    }

    if args.no_path {
        println!("  按 --no-path 要求，未改动 PATH");
    } else if dir_in_path(&dir) {
        println!("  目录已在 PATH 中，直接敲 `optical` 即可");
    } else {
        for n in add_to_path(&dir)? {
            println!("  {n}");
        }
    }

    println!("\n  验证：新开一个终端 → optical --version");
    Ok(())
}

pub async fn config_cmd(config_opt: Option<PathBuf>, cmd: ConfigCmd) -> Result<()> {
    let path = crate::config::resolve_path(config_opt);

    match cmd {
        ConfigCmd::Show => {
            let (cfg, _) = Config::load_or_init(&path)?;
            cfg.validate_ok_in(base_dir_of(&path))?;
            print!("{}", cfg.to_toml());
        }
        ConfigCmd::Path => println!("{}", absolutize(&path).display()),
        ConfigCmd::Init { force } => {
            if path.exists() && !force {
                bail!("{} 已存在，如需覆盖请加 --force", path.display());
            }
            let cfg = crate::config::demo_config();
            cfg.save(&path)?;
            println!(
                "已写入干净配置（无示例路由/后端/分组）: {}",
                absolutize(&path).display()
            );
        }
        ConfigCmd::Validate => {
            let cfg = Config::load(&path)
                .with_context(|| format!("找不到或无法解析 {}", path.display()))?;
            let errs = cfg.validate_in(base_dir_of(&path));
            if errs.is_empty() {
                println!(
                    "OK  {} 项路由 / {} 个后端 / {} 条头规则，监听 {}，默认上游 {}",
                    cfg.routes.len(),
                    cfg.backends.len(),
                    cfg.header_rules.len(),
                    cfg.server.listen,
                    cfg.server.default_upstream
                );
            } else {
                for e in &errs {
                    eprintln!("ERROR {e}");
                }
                bail!("配置校验失败（{} 处错误）", errs.len());
            }
        }
        ConfigCmd::Set { key, value } => {
            let mut cfg = Config::load(&path)?;
            match key.replace('_', "-").as_str() {
                "listen" => cfg.server.listen = value,
                "admin-listen" => cfg.server.admin_listen = value,
                "default-upstream" => cfg.server.default_upstream = value,
                "timeout-ms" => {
                    cfg.server.request_timeout_ms = value
                        .parse()
                        .with_context(|| format!("timeout-ms 需要整数: {value}"))?
                }
                "log-level" => cfg.server.log_level = value,
                "waf-mode" => {
                    cfg.waf.mode = match value.as_str() {
                        "block" => crate::config::WafMode::Block,
                        "monitor" => crate::config::WafMode::Monitor,
                        other => bail!("waf-mode 只支持 block / monitor，收到 {other}"),
                    }
                }
                other => bail!(
                    "未知配置键: {other}（可用: listen / admin-listen / default-upstream / timeout-ms / log-level / waf-mode）"
                ),
            }
            cfg.validate_ok_in(base_dir_of(&path))?;
            cfg.save(&path)?;
            println!("已更新 {} → {}", key, absolutize(&path).display());
            notify_reload(&path, &cfg.server.admin_listen).await;
        }
    }
    Ok(())
}

// ---------- passwd ----------

pub async fn passwd_cmd(config_opt: Option<PathBuf>, args: crate::cli::PasswdArgs) -> Result<()> {
    if args.password.chars().count() < 8 {
        bail!("口令至少 8 位");
    }
    let hash = crate::auth::hash_password(&args.password)?;
    if !args.write {
        println!("{hash}");
        return Ok(());
    }
    let path = crate::config::resolve_path(config_opt);
    let mut cfg = Config::load(&path)
        .with_context(|| format!("找不到配置文件 {}，先跑一次 `optical run` 或 `config init`", path.display()))?;
    cfg.admin.password_hash = hash;
    cfg.validate_ok_in(base_dir_of(&path))?;
    cfg.save(&path)?;
    println!("已写入 admin.password_hash → {}（下次启动/热重载生效）", absolutize(&path).display());
    notify_reload(&path, &cfg.server.admin_listen).await;
    Ok(())
}

// ---------- route ----------

pub async fn route_cmd(config_opt: Option<PathBuf>, cmd: RouteCmd) -> Result<()> {
    let path = crate::config::resolve_path(config_opt);

    match cmd {
        RouteCmd::List => {
            let (cfg, _) = Config::load_or_init(&path)?;
            if cfg.routes.is_empty() {
                println!("（无路由，所有请求走默认上游 {}）", cfg.server.default_upstream);
                return Ok(());
            }
            println!("{:<14} {:<18} {:<12} {:<30} FLAGS", "NAME", "HOST", "PREFIX", "UPSTREAM/BACKEND");
            for r in &cfg.routes {
                let mut flags: Vec<String> = Vec::new();
                if r.strip_prefix {
                    flags.push("strip".into());
                }
                if !r.rewrite_host {
                    flags.push("keep-host".into());
                }
                if r.cache == Some(false) {
                    flags.push("no-cache".into());
                }
                if let Some(t) = r.timeout_ms {
                    flags.push(format!("timeout={t}ms"));
                }
                let target = if !r.backend_group.is_empty() {
                    format!("group:{}", r.backend_group)
                } else if r.backend.is_empty() {
                    r.upstream.clone()
                } else {
                    format!("@{}", r.backend)
                };
                println!(
                    "{:<14} {:<18} {:<12} {:<30} {}",
                    r.name,
                    r.host,
                    r.path_prefix,
                    target,
                    flags.join(",")
                );
            }
            println!(
                "\n默认上游（文件值）: {}   —— 运行中实例的生效值用 `optical status` 看",
                cfg.server.default_upstream
            );
        }
        RouteCmd::Add(a) => {
            let mut cfg = Config::load(&path)?;
            if cfg.routes.iter().any(|r| r.name == a.name) {
                bail!("路由名已存在: {}", a.name);
            }
            let mut r = crate::config::RouteConfig::new(&a.name, &a.host, &a.prefix, &a.upstream);
            r.strip_prefix = a.strip_prefix;
            if let Some(b) = &a.backend {
                if cfg.find_backend(b).is_none() {
                    bail!("backend 不存在: {b}（先用配置或 WebUI 添加后端）");
                }
                r.backend = b.clone();
                r.upstream.clear();
            }
            if let Some(g) = &a.backend_group {
                let declared = cfg.find_group(g).is_some();
                let implicit = cfg.backends.iter().any(|b| &b.group == g);
                if !declared && !implicit {
                    bail!("backend_group 不存在: {g}（先给后端填 group，或声明 [[backend_groups]]）");
                }
                r.backend_group = g.clone();
                r.backend.clear();
                r.upstream.clear();
            }
            cfg.routes.push(r);
            cfg.validate_ok_in(base_dir_of(&path))?;
            cfg.save(&path)?;
            let target = if let Some(g) = &a.backend_group {
                format!("group:{g}")
            } else if let Some(b) = &a.backend {
                format!("@{b}")
            } else {
                a.upstream.clone()
            };
            println!("已新增路由 {} → {}（匹配顺序: #{}）", a.name, target, cfg.routes.len());
            notify_reload(&path, &cfg.server.admin_listen).await;
        }
        RouteCmd::Remove { name } => {
            let mut cfg = Config::load(&path)?;
            let before = cfg.routes.len();
            cfg.routes.retain(|r| r.name != name);
            if cfg.routes.len() == before {
                bail!("没有这个路由: {name}");
            }
            cfg.save(&path)?;
            println!("已删除路由 {name}");
            notify_reload(&path, &cfg.server.admin_listen).await;
        }
    }
    Ok(())
}

// ---------- status ----------

pub async fn status_cmd(config_opt: Option<PathBuf>, args: StatusArgs) -> Result<()> {
    let path = crate::config::resolve_path(config_opt);
    let admin = match args.admin {
        Some(a) => a,
        None => Config::load(&path)
            .map(|c| c.server.admin_listen)
            .unwrap_or_else(|_| crate::config::DEFAULT_ADMIN_LISTEN.to_string()),
    };

    let body = match http_get(&path, &admin, "/api/status").await {
        Ok(b) => b,
        Err(e) => bail!("连不上管理面 http://{admin}（实例可能没启动）: {e}"),
    };

    if args.json {
        println!("{body}");
        return Ok(());
    }

    let v: serde_json::Value = serde_json::from_str(&body).context("返回内容不是合法 JSON")?;
    let g = |k: &str| v.get(k).cloned().unwrap_or(serde_json::Value::Null);
    let num = |o: &serde_json::Value, k: &str| o.get(k).and_then(|x| x.as_u64()).unwrap_or(0);

    println!("optical {} @ http://{admin}", g("version"));
    println!("  状态      {}", if g("ok").as_bool().unwrap_or(false) { "运行中" } else { "异常" });
    println!("  网关      http://{}", g("listen").as_str().unwrap_or("-"));
    if let Some(tls) = v.get("tls") {
        if tls.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false) {
            println!(
                "  HTTPS     https://{}  [{}]",
                tls.get("listen").and_then(|x| x.as_str()).unwrap_or("-"),
                tls.get("min_version").and_then(|x| x.as_str()).unwrap_or("-")
            );
        }
    }
    println!("  默认上游  {}", g("default_upstream").as_str().unwrap_or("-"));
    println!("  路由/后端 {}/{}", g("routes"), g("backends"));
    if let Some(w) = v.get("waf") {
        println!(
            "  WAF       {} mode={} threshold={}",
            if w.get("enabled").and_then(|b| b.as_bool()).unwrap_or(false) { "on" } else { "off" },
            w.get("mode").and_then(|x| x.as_str()).unwrap_or("-"),
            w.get("score_threshold").and_then(|x| x.as_u64()).unwrap_or(0)
        );
    }
    println!("  运行时长  {}s", g("uptime_secs"));
    if let Some(m) = v.get("metrics") {
        println!(
            "  流量      入 {} / 出 {}",
            human_bytes(num(m, "bytes_in")),
            human_bytes(num(m, "bytes_out"))
        );
        println!(
            "  请求      {} 总 / {} 错误 / 平均上游 {}ms",
            num(m, "requests"),
            num(m, "errors"),
            num(m, "avg_upstream_ms")
        );
        let hit_rate = m.get("cache_hit_rate").and_then(|x| x.as_f64()).unwrap_or(0.0);
        println!(
            "  缓存      命中率 {:.1}%（命中 {} / 未命中 {}）",
            hit_rate,
            num(m, "cache_hit"),
            num(m, "cache_miss")
        );
        let waf_rate = m.get("waf_hit_rate").and_then(|x| x.as_f64()).unwrap_or(0.0);
        println!(
            "  规则命中  {:.2}% / 拦截 {} 次 / 跳过检查 {} 次",
            waf_rate,
            num(m, "waf_blocks"),
            num(m, "waf_skipped")
        );
        println!(
            "  连接      WS 升级 {} / TLS 握手 {} / 重载 {}",
            num(m, "ws_upgrades"),
            num(m, "tls_handshakes"),
            num(m, "reloads")
        );
    }
    if let Some(c) = v.get("conns") {
        println!("  在线连接  {} 条 / {} 个 IP", num(c, "active"), num(c, "ips"));
    }
    println!("  配置      {}", g("config_path").as_str().unwrap_or("-"));
    Ok(())
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// 尽力通知运行中的实例重载；失败静默（mtime 轮询会兜住）。
async fn notify_reload(config_path: &Path, admin: &str) {
    let uri = format!("http://{admin}/api/reload");
    let mut builder = Request::post(uri);
    if let Some(token) = load_token(config_path) {
        builder = builder.header("cookie", format!("optical_sid={token}"));
    }
    if let Ok(req) = builder.body(Full::new(Bytes::new())) {
        let _ = tokio::time::timeout(Duration::from_millis(800), http_request(req)).await;
    }
}

async fn http_get(config_path: &Path, addr: &str, path: &str) -> Result<String> {
    let mut builder = Request::builder()
        .uri(format!("http://{addr}{path}"))
        .header("accept", "application/json");
    if let Some(token) = load_token(config_path) {
        builder = builder.header("cookie", format!("optical_sid={token}"));
    }
    let req = builder.body(Full::new(Bytes::new()))?;
    let body = tokio::time::timeout(Duration::from_millis(1500), http_request(req))
        .await
        .context("请求超时")??;
    Ok(String::from_utf8_lossy(&body).to_string())
}

async fn http_request(req: Request<Full<Bytes>>) -> Result<Bytes> {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_millis(600)));
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
    let resp = client.request(req).await?;
    let body = resp.into_body().collect().await?.to_bytes();
    Ok(body)
}
