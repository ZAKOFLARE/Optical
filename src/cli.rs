//! 命令行定义。所有运行参数都能覆盖配置文件里的默认值。

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "optical",
    version,
    about = "Optical —— 跨平台网关（转发 / 路由 / WAF / TLS，CLI + WebUI）",
    after_help = "示例:\n  optical run --listen 0.0.0.0:8080 --upstream http://127.0.0.1:8081\n  optical route add --name api --prefix /api --upstream http://127.0.0.1:8082\n  optical status"
)]
pub struct Cli {
    /// 配置文件路径（默认 ./optical.toml，也可用环境变量 OPTICAL_CONFIG）
    #[arg(short = 'c', long, global = true, env = "OPTICAL_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 启动网关（无子命令时默认执行）
    Run(RunArgs),
    /// 查看/初始化/校验配置文件
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// 管理路由表
    Route {
        #[command(subcommand)]
        cmd: RouteCmd,
    },
    /// 查询运行中实例的状态
    Status(StatusArgs),
    /// 启动一个演示用回显上游（验证转发是否通）
    UpstreamEcho(EchoArgs),
    /// 生成/写入管理面口令（argon2 哈希）
    Passwd(PasswdArgs),
    /// 把当前可执行文件装进 PATH，之后任何目录都能直接敲 optical
    Install(InstallArgs),
    /// 管理工作面二次验证（离线应急：忘密钥/算法不对时关掉 2FA）
    Totp {
        #[command(subcommand)]
        cmd: TotpCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum TotpCmd {
    /// 关闭二次验证并清掉密钥（不需要登录，直接改配置文件）
    Off,
    /// 显示当前 2FA 状态与算法（不打印密钥）
    Status,
}

#[derive(Args, Debug, Default)]
pub struct InstallArgs {
    /// 安装目录；默认 ~/.local/bin，Windows 为 %LOCALAPPDATA%\Programs\Optical
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// 只复制文件，不碰 PATH
    #[arg(long)]
    pub no_path: bool,

    /// 目标已存在时覆盖
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug, Default)]
pub struct RunArgs {
    /// 网关监听地址，覆盖 server.listen
    #[arg(short = 'l', long, value_name = "IP:PORT")]
    pub listen: Option<String>,

    /// WebUI / REST 监听地址，覆盖 server.admin_listen
    #[arg(long, value_name = "IP:PORT")]
    pub admin_listen: Option<String>,

    /// 默认上游，覆盖 server.default_upstream
    #[arg(short = 'u', long, value_name = "URL")]
    pub upstream: Option<String>,

    /// 请求超时（毫秒），覆盖 server.request_timeout_ms
    #[arg(long, value_name = "MS")]
    pub timeout_ms: Option<u64>,

    /// 日志级别，覆盖 server.log_level
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// 打印生效配置（TOML）
    Show,
    /// 打印配置文件绝对路径
    Path,
    /// 生成示例配置
    Init {
        /// 已存在时覆盖
        #[arg(long)]
        force: bool,
    },
    /// 校验配置文件
    Validate,
    /// 修改 server 下的单项配置，例如 `config set listen 0.0.0.0:9090`
    Set {
        /// listen | admin-listen | default-upstream | timeout-ms | log-level
        key: String,
        value: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum RouteCmd {
    /// 列出路由表
    List,
    /// 新增路由（追加到末尾，匹配顺序即显示顺序）
    Add(RouteAddArgs),
    /// 删除路由
    Remove {
        /// 路由名
        name: String,
    },
}

#[derive(Args, Debug)]
pub struct RouteAddArgs {
    /// 路由名（唯一）
    #[arg(long)]
    pub name: String,

    /// 主机匹配：* / *.example.com / 精确域名
    #[arg(long, default_value = "*")]
    pub host: String,

    /// 路径前缀，必须 '/' 开头
    #[arg(long, default_value = "/")]
    pub prefix: String,

    /// 上游地址（与 --backend 二选一）
    #[arg(long, default_value = "")]
    pub upstream: String,

    /// 引用已配置的后端名（与 --backend-group / --upstream 三选一）
    #[arg(long)]
    pub backend: Option<String>,

    /// 引用后端分组名（组内按策略负载均衡）
    #[arg(long)]
    pub backend_group: Option<String>,

    /// 转发时剥离 path_prefix
    #[arg(long)]
    pub strip_prefix: bool,
}

#[derive(Args, Debug, Default)]
pub struct StatusArgs {
    /// 直接指定管理面地址（默认从配置文件读取）
    #[arg(long, value_name = "IP:PORT")]
    pub admin: Option<String>,

    /// 输出原始 JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct PasswdArgs {
    /// 明文口令（至少 8 位）；只用于本次计算，不落盘
    pub password: String,

    /// 直接写入配置文件（否则只打印哈希）
    #[arg(long)]
    pub write: bool,
}

#[derive(Args, Debug)]
pub struct EchoArgs {
    /// 回显服务监听地址
    #[arg(short = 'l', long, default_value = "127.0.0.1:8081")]
    pub listen: String,
}
