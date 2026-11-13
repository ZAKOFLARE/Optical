//! Optical —— 跨平台网关。
//!
//! 能力面：
//! - 转发 / 路由 / 后端池（权重 + 主动探活）/ 响应缓存
//! - WAF：DoS、XML、JWT、SQL、SSRF、BOLA、路径穿越、缓存欺骗、参数污染、帧限制
//! - 传输：HTTP/1.1、HTTP/2（gRPC 透传）、WebSocket 隧道、TLS 1.2/1.3
//! - 运维：CLI + WebUI（中英双语、明暗主题）、管理面认证（口令 + TOTP）、配置回溯、审计
//!
//! 明确未交付：QUIC/HTTP3（需要完整 h3 协议栈，见 README「未实现」一节）。

mod admin;
mod appearance;
mod apps;
mod auth;
mod backends;
mod cache;
mod cli;
mod commands;
mod compress;
mod config;
mod echo;
mod errors;
mod history;
mod ipfilter;
mod proxy;
mod route;
mod rules;
mod sites;
mod firewall;
mod stats;
mod state;
mod storage;
mod sys;
mod tls;
mod waf;

use clap::Parser;
use cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command.unwrap_or(Command::Run(Default::default())) {
        Command::Run(run) => commands::run_gateway(args.config, run).await,
        Command::Config { cmd } => commands::config_cmd(args.config, cmd).await,
        Command::Route { cmd } => commands::route_cmd(args.config, cmd).await,
        Command::Status(st) => commands::status_cmd(args.config, st).await,
        Command::Passwd(p) => commands::passwd_cmd(args.config, p).await,
        Command::Install(i) => commands::install_cmd(i).await,
        Command::Totp { cmd } => commands::totp_cmd(args.config, cmd).await,
        Command::UpstreamEcho(e) => {
            commands::init_logging("info");
            echo::serve(&e.listen).await
        }
    }
}
