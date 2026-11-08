//! 动态项目管理：把 Go / PHP / Java / Python / .NET / Node 这类常驻进程纳进来。
//!
//! 和静态站点的区别不是"能不能托管"，而是**谁在跑**：
//! 静态站点是网关自己读文件，动态项目是网关替你拉起一个子进程、
//! 把它的 127.0.0.1:port 映射到域名上，并且负责启停、CORS、日志尾巴。
//!
//! 刻意的取舍：
//! - 不做依赖安装/构建（那是 CI 的事），只负责"跑起来、跑挂了拉起来、能停"；
//! - 不监听端口探测来猜成功，用 `health_path` 主动探一次（可选）；
//! - 日志只留最近 N 行，落盘交给 journald（进程 stdout 直接进 journal）。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    pub enabled: bool,
    /// 允许的来源：`*`、精确 origin，或 `https://*.example.com` 这种通配
    pub origins: Vec<String>,
    pub methods: Vec<String>,
    /// 允许的请求头；留空则回显预检里的 Access-Control-Request-Headers
    pub headers: Vec<String>,
    pub expose: Vec<String>,
    pub credentials: bool,
    pub max_age: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            origins: vec!["*".to_string()],
            methods: vec![
                "GET".into(),
                "POST".into(),
                "PUT".into(),
                "PATCH".into(),
                "DELETE".into(),
                "HEAD".into(),
                "OPTIONS".into(),
            ],
            headers: Vec::new(),
            expose: Vec::new(),
            credentials: false,
            max_age: 600,
        }
    }
}

impl CorsConfig {
    /// 这个来源放不放行。`*` 通配 + credentials 是非法组合（浏览器会直接拒），
    /// 所以开了 credentials 就只认精确/前缀匹配。
    pub fn allows(&self, origin: &str) -> Option<String> {
        if !self.enabled || origin.is_empty() {
            return None;
        }
        if !self.credentials && self.origins.iter().any(|o| o == "*") {
            return Some("*".to_string());
        }
        for pat in &self.origins {
            // 裸 `*` 只在"不要求 credentials"那档处理过；走到这里说明开了 credentials，
            // 而 `*` + credentials 是浏览器明确禁止的组合，不能靠它放行。
            if pat == "*" {
                continue;
            }
            if pat == origin {
                return Some(origin.to_string());
            }
            if let Some(rest) = pat.strip_prefix("*.") {
                // *.example.com 只匹配子域，不匹配裸域
                if let Some(host) = origin.split("://").nth(1) {
                    let host = host.split(':').next().unwrap_or(host);
                    if host.ends_with(rest) && host.len() > rest.len() + 1 {
                        return Some(origin.to_string());
                    }
                }
            }
            if let Some(prefix) = pat.strip_suffix('*') {
                if origin.starts_with(prefix) {
                    return Some(origin.to_string());
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub name: String,
    /// 参与映射；关掉等于把域名从路由表里摘掉
    pub enabled: bool,
    /// 网关启动时自动拉起
    pub autostart: bool,
    /// 跑挂了自动拉起
    pub restart: bool,
    /// go / php / java / python / dotnet / node / custom —— 只用于展示与默认命令推断
    pub kind: String,
    /// 工作目录（相对路径按配置文件所在目录解析）
    pub cwd: String,
    /// 启动命令；留空时按 kind + entry 推断
    pub command: String,
    /// 入口文件/脚本（推断默认命令时用）
    pub entry: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// 应用在 127.0.0.1 上的端口
    pub port: u16,
    pub hosts: Vec<String>,
    pub path_prefix: String,
    pub strip_prefix: bool,
    /// 探测路径；空 = 不探
    pub health_path: String,
    pub cors: CorsConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            autostart: false,
            restart: true,
            kind: "custom".into(),
            cwd: String::new(),
            command: String::new(),
            entry: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            port: 0,
            hosts: vec!["*".into()],
            path_prefix: "/".into(),
            strip_prefix: false,
            health_path: String::new(),
            cors: CorsConfig::default(),
        }
    }
}

impl AppConfig {
    /// 最终要执行的命令行。显式 command 优先；否则按 kind 推断一个"能跑起来"的默认值。
    /// 推断只覆盖最常见的入口，复杂参数一律写 command，避免猜错比不猜更糟。
    pub fn command_line(&self) -> String {
        let mut line = if !self.command.trim().is_empty() {
            self.command.trim().to_string()
        } else {
            let entry = self.entry.trim();
            match self.kind.trim().to_ascii_lowercase().as_str() {
                "python" | "py" => format!("python3 {entry}"),
                "node" | "nodejs" => format!("node {entry}"),
                "php" => format!("php -S 127.0.0.1:{} -t {}", self.port, if entry.is_empty() { "." } else { entry }),
                "java" => format!("java -jar {entry}"),
                "dotnet" | "net" => format!("dotnet {entry}"),
                "go" => {
                    if entry.is_empty() {
                        "./app".to_string()
                    } else {
                        format!("./{entry}")
                    }
                }
                _ => entry.to_string(),
            }
        };
        if !self.args.is_empty() {
            line.push(' ');
            line.push_str(
                &self
                    .args
                    .iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        line
    }

    /// 应用映射到网关上的上游
    pub fn upstream(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// 命中哪个动态项目。精确域名优先于 `*`，路径前缀长的优先于短的。
pub fn pick<'a>(apps: &'a [AppConfig], host: &str, path: &str) -> Option<&'a AppConfig> {
    let h = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let mut best: Option<&AppConfig> = None;
    for app in apps.iter().filter(|a| a.enabled) {
        let prefix = if app.path_prefix.trim().is_empty() {
            "/"
        } else {
            app.path_prefix.as_str()
        };
        if !path.starts_with(prefix) {
            continue;
        }
        let host_hit = app
            .hosts
            .iter()
            .any(|p| p == "*" || p.split(':').next().unwrap_or(p).eq_ignore_ascii_case(&h));
        if !host_hit {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => {
                let bp = if b.path_prefix.trim().is_empty() { "/" } else { b.path_prefix.as_str() };
                // 精确域名 > 通配；同类型再比前缀长度
                let exact_new = !app.hosts.iter().any(|x| x == "*");
                let exact_old = !b.hosts.iter().any(|x| x == "*");
                (exact_new && !exact_old) || (exact_new == exact_old && prefix.len() > bp.len())
            }
        };
        if better {
            best = Some(app);
        }
    }
    best
}

/// 应用当前是否在跑（用于把"没启动"和"启动失败"区分开）
pub async fn is_running(manager: &AppManager, name: &str) -> bool {
    let mut g = manager.inner.lock().await;
    match g.get_mut(name) {
        Some(rt) => match rt.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        },
        None => false,
    }
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || "-_./:=@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub autostart: bool,
    pub restart: bool,
    pub port: u16,
    pub hosts: Vec<String>,
    pub path_prefix: String,
    pub cors: bool,
    pub command: String,
    pub running: bool,
    pub pid: u32,
    pub started_at: i64,
    /// 最近一次退出码（没退出过就是 None）
    pub last_exit: Option<i32>,
    pub restarts: u64,
    pub logs: Vec<String>,
}

struct Runtime {
    child: Option<tokio::process::Child>,
    pid: u32,
    started_at: i64,
    last_exit: Option<i32>,
    restarts: u64,
    want_running: bool,
    /// 用户主动停过：autostart 不再自动拉起它，直到有人再点一次启动。
    /// 没有这个标记，autostart 应用会"点了停止两秒后又活了"。
    stopped_by_user: bool,
    /// 最近一次自动拉起的时间，用来做退避（防止崩溃循环打满 CPU）
    last_spawn: Option<std::time::Instant>,
    logs: VecDeque<String>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            child: None,
            pid: 0,
            started_at: 0,
            last_exit: None,
            restarts: 0,
            want_running: false,
            stopped_by_user: false,
            last_spawn: None,
            logs: VecDeque::new(),
        }
    }
}

const LOG_LINES: usize = 200;
/// 崩溃循环保护：同一个应用 10 秒内最多自动拉起 3 次
const RESTART_WINDOW_SECS: u64 = 10;
const RESTART_MAX_IN_WINDOW: u64 = 3;

pub struct AppManager {
    inner: Mutex<HashMap<String, Runtime>>,
}

impl Default for AppManager {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

fn now_ms() -> i64 {
    crate::state::now_ms()
}

impl AppManager {
    /// 启动一个应用。已经在跑就直接返回原 pid（幂等，按钮点两下不会起两个进程）。
    pub async fn start(self: &Arc<Self>, app: &AppConfig, base_dir: &std::path::Path) -> anyhow::Result<u32> {
        let mut g = self.inner.lock().await;
        let rt = g.entry(app.name.clone()).or_default();
        if let Some(child) = rt.child.as_mut() {
            if let Ok(None) = child.try_wait() {
                return Ok(rt.pid);
            }
        }

        let cmd_line = app.command_line();
        if cmd_line.trim().is_empty() {
            anyhow::bail!("{} 没有可执行的命令（command 与 entry 都为空）", app.name);
        }
        let cwd = crate::config::resolve_one(&app.cwd, base_dir);
        if !cwd.as_os_str().is_empty() && !cwd.exists() {
            anyhow::bail!("{} 的工作目录不存在: {}", app.name, cwd.display());
        }

        let mut cmd = if cfg!(windows) {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(&cmd_line);
            c
        } else {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(&cmd_line);
            c
        };
        if !cwd.as_os_str().is_empty() {
            cmd.current_dir(&cwd);
        }
        for (k, v) in &app.env {
            cmd.env(k, v);
        }
        // 应用自己也要能拿到端口，省得配置里写两遍
        cmd.env("PORT", app.port.to_string());
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        cmd.kill_on_drop(false);

        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("{} 启动失败: {e}", app.name))?;
        let pid = child.id().unwrap_or(0);

        // stdout / stderr 各自一条读循环，写进同一个环形缓冲
        let logs = Arc::new(Mutex::new(()));
        drop(logs);
        self.pipe(&app.name, child.stdout.take(), "out");
        self.pipe(&app.name, child.stderr.take(), "err");

        rt.child = Some(child);
        rt.pid = pid;
        rt.started_at = now_ms();
        rt.want_running = true;
        rt.stopped_by_user = false;
        rt.last_spawn = Some(std::time::Instant::now());
        rt.logs
            .push_back(format!("[{}] $ {cmd_line}", short_time(now_ms())));
        trim_logs(&mut rt.logs);
        drop(g);

        tracing::info!(app = %app.name, pid, cmd = %cmd_line, "应用已启动");
        Ok(pid)
    }

    fn pipe(
        self: &Arc<Self>,
        name: &str,
        stream: Option<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
        tag: &'static str,
    ) {
        let Some(stream) = stream else { return };
        let me = self.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let mut g = me.inner.lock().await;
                if let Some(rt) = g.get_mut(&name) {
                    rt.logs
                        .push_back(format!("[{}] {tag} {line}", short_time(now_ms())));
                    trim_logs(&mut rt.logs);
                }
            }
        });
    }

    /// 停止：先 SIGKILL（子进程常常忽略 SIGTERM，且这里没有进程组），再回收。
    pub async fn stop(&self, name: &str) -> anyhow::Result<bool> {
        let mut g = self.inner.lock().await;
        let Some(rt) = g.get_mut(name) else {
            return Ok(false);
        };
        rt.want_running = false;
        rt.stopped_by_user = true;
        let Some(mut child) = rt.child.take() else {
            return Ok(false);
        };
        let _ = child.start_kill();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
        rt.pid = 0;
        rt.logs
            .push_back(format!("[{}] 已停止", short_time(now_ms())));
        trim_logs(&mut rt.logs);
        drop(g);
        Ok(true)
    }

    pub async fn restart(self: &Arc<Self>, app: &AppConfig, base_dir: &std::path::Path) -> anyhow::Result<u32> {
        self.stop(&app.name).await.ok();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.start(app, base_dir).await
    }

    pub async fn status(&self, apps: &[AppConfig]) -> Vec<AppStatus> {
        let mut g = self.inner.lock().await;
        let mut out: Vec<AppStatus> = Vec::new();
        for app in apps {
            let rt = g.entry(app.name.clone()).or_default();
            // 顺手回收已经退出的子进程，别让僵尸挂着
            let mut running = false;
            if let Some(child) = rt.child.as_mut() {
                match child.try_wait() {
                    Ok(None) => running = true,
                    Ok(Some(st)) => {
                        rt.last_exit = st.code();
                        rt.child = None;
                        rt.pid = 0;
                        rt.logs.push_back(format!(
                            "[{}] 退出 code={:?}",
                            short_time(now_ms()),
                            st.code()
                        ));
                        trim_logs(&mut rt.logs);
                    }
                    Err(_) => {}
                }
            }
            out.push(AppStatus {
                name: app.name.clone(),
                kind: app.kind.clone(),
                enabled: app.enabled,
                autostart: app.autostart,
                restart: app.restart,
                port: app.port,
                hosts: app.hosts.clone(),
                path_prefix: app.path_prefix.clone(),
                cors: app.cors.enabled,
                command: app.command_line(),
                running,
                pid: rt.pid,
                started_at: rt.started_at,
                last_exit: rt.last_exit,
                restarts: rt.restarts,
                logs: rt.logs.iter().cloned().collect(),
            });
        }
        out
    }

    /// 自动拉起：启动时 autostart、以及 restart=true 的崩溃拉起都走这里。
    pub async fn supervise(self: &Arc<Self>, apps: &[AppConfig], base_dir: &std::path::Path) {
        for app in apps {
            if !app.enabled || !app.autostart {
                continue;
            }
            let running = {
                let g = self.inner.lock().await;
                g.get(&app.name).map(|r| r.child.is_some()).unwrap_or(false)
            };
            if !running {
                let _ = self.start(app, base_dir).await;
            }
        }
    }

    /// 每个 supervisor tick 调一次：回收已退出的子进程，并按策略重启。
    pub async fn tick(self: &Arc<Self>, apps: &[AppConfig], base_dir: &std::path::Path) {
        let mut to_restart: Vec<String> = Vec::new();
        {
            let mut g = self.inner.lock().await;
            for app in apps {
                let Some(rt) = g.get_mut(&app.name) else {
                    continue;
                };
                let Some(child) = rt.child.as_mut() else {
                    // 没在跑有两种成因，处理方式不同：
                    //   1) 崩了 → 只有 restart=true 才拉；
                    //   2) 配置热加载后新增的 autostart 应用（want_running 还没被置位）
                    //      → 也要拉，否则"改了配置却纹丝不动"，只能靠人点一次启动。
                    let crashed = rt.want_running && app.enabled && app.restart;
                    let never_started = app.enabled
                        && app.autostart
                        && !rt.want_running
                        && !rt.stopped_by_user
                        // 启动失败时别每 2 秒重试一次，给 5 秒退避
                        && rt
                            .last_spawn
                            .map(|t| t.elapsed().as_secs() >= 5)
                            .unwrap_or(true);
                    if crashed || never_started {
                        to_restart.push(app.name.clone());
                    }
                    continue;
                };
                match child.try_wait() {
                    Ok(Some(st)) => {
                        rt.last_exit = st.code();
                        rt.child = None;
                        rt.pid = 0;
                        rt.logs.push_back(format!(
                            "[{}] 进程退出 code={:?}",
                            short_time(now_ms()),
                            st.code()
                        ));
                        trim_logs(&mut rt.logs);
                        if rt.want_running && app.restart {
                            // 退避：短时间内反复崩溃就多等一会儿，别把机器烧了
                            let too_fast = rt
                                .last_spawn
                                .map(|t| t.elapsed().as_secs() < RESTART_WINDOW_SECS)
                                .unwrap_or(false);
                            if rt.restarts % RESTART_MAX_IN_WINDOW == RESTART_MAX_IN_WINDOW - 1
                                && too_fast
                            {
                                rt.logs.push_back(format!(
                                    "[{}] 短时间反复退出，暂停自动拉起一轮",
                                    short_time(now_ms())
                                ));
                                trim_logs(&mut rt.logs);
                            }
                            to_restart.push(app.name.clone());
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }
            }
        }
        for name in to_restart {
            if let Some(app) = apps.iter().find(|a| a.name == name) {
                {
                    let mut g = self.inner.lock().await;
                    if let Some(rt) = g.get_mut(&name) {
                        rt.restarts += 1;
                    }
                }
                let _ = self.start(app, base_dir).await;
            }
        }
    }

    /// 配置里删掉的应用，把进程也一起收掉
    pub async fn reap_removed(&self, apps: &[AppConfig]) {
        let names: Vec<String> = {
            let g = self.inner.lock().await;
            g.keys().cloned().collect()
        };
        for n in names {
            if !apps.iter().any(|a| a.name == n) {
                self.stop(&n).await.ok();
            }
        }
    }
}

fn trim_logs(q: &mut VecDeque<String>) {
    while q.len() > LOG_LINES {
        q.pop_front();
    }
}

fn short_time(ms: i64) -> String {
    let secs = (ms / 1000) % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_prefers_explicit_and_quotes_args() {
        let mut a = AppConfig {
            command: "uvicorn app:app".into(),
            ..Default::default()
        };
        a.args = vec!["--host 0.0.0.0".into()];
        assert_eq!(a.command_line(), "uvicorn app:app '--host 0.0.0.0'");
    }

    #[test]
    fn command_line_infers_per_runtime() {
        let mut a = AppConfig {
            kind: "python".into(),
            entry: "main.py".into(),
            ..Default::default()
        };
        assert_eq!(a.command_line(), "python3 main.py");
        a.kind = "php".into();
        a.port = 9000;
        a.entry = "public".into();
        assert_eq!(a.command_line(), "php -S 127.0.0.1:9000 -t public");
        a.kind = "node".into();
        a.entry = "server.js".into();
        assert_eq!(a.command_line(), "node server.js");
    }

    #[test]
    fn cors_wildcard_and_credentials_never_mix() {
        let mut c = CorsConfig {
            enabled: true,
            credentials: true,
            ..Default::default()
        };
        // 开了 credentials，`*` 不能回显成 *（浏览器会拒）
        assert_eq!(c.allows("https://a.example.com"), None);
        c.origins = vec!["https://a.example.com".into()];
        assert_eq!(
            c.allows("https://a.example.com"),
            Some("https://a.example.com".to_string())
        );

        let open = CorsConfig {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(open.allows("https://b.example.com"), Some("*".to_string()));
    }

    #[test]
    fn cors_subdomain_pattern_does_not_match_bare_domain() {
        let c = CorsConfig {
            enabled: true,
            origins: vec!["*.example.com".into()],
            ..Default::default()
        };
        assert_eq!(
            c.allows("https://api.example.com"),
            Some("https://api.example.com".to_string())
        );
        assert_eq!(c.allows("https://example.com"), None);
    }

    #[test]
    fn upstream_is_loopback_port() {
        let a = AppConfig {
            port: 8081,
            ..Default::default()
        };
        assert_eq!(a.upstream(), "http://127.0.0.1:8081");
    }
}
