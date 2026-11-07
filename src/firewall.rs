//! 系统防火墙联动：把网关真正监听的端口放行出去。
//!
//! 为什么单独一块、不塞进 rules：规则是"请求进来之后怎么处理"，
//! 端口放行是"包还没进内核栈就先决定能不能进"。两件事的生命周期、
//! 出错后果、排查路径完全不同——混在一个列表里，改 URL 规则时误删一条
//! INPUT 规则就能把自己锁在门外。
//!
//! 实现原则：
//! - **只做 ACCEPT，不做 DROP**。加放行不会切断已有连接，最坏情况是"没生效"，
//!   而不是"SSH 断了"。管理面端口被锁在外面这种事不能靠自觉。
//! - 幂等：每次重建自己的链/表，反复点"应用"结果一致。
//! - 后端按可用性自动挑：ufw（Debian 常见）→ nft → iptables。

use crate::config::Config;
use serde::Serialize;
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FirewallConfig {
    pub enabled: bool,
    /// `auto` / `nft` / `iptables` / `ufw` / `none`
    pub backend: String,
    /// 额外要放行的 TCP 端口（管理面、内部调试口等）
    pub extra_ports: Vec<u16>,
    /// 配置保存后自动重放（端口随监听地址一起变）
    pub auto_sync: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: "auto".to_string(),
            extra_ports: Vec::new(),
            auto_sync: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub ok: bool,
    /// 实际使用的后端
    pub backend: String,
    /// 期望放行的端口（去重排序后的最终结果）
    pub ports: Vec<u16>,
    /// 每条命令的执行结果摘要，出错时给运维看
    pub steps: Vec<String>,
    pub error: String,
}

fn has_cmd(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 自动挑后端：ufw 装了且启用优先（它自己维护 INPUT 链），否则 nft，再否则 iptables
pub fn detect() -> String {
    if has_cmd("ufw") {
        let active = Command::new("ufw")
            .arg("status")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
            .unwrap_or(false);
        if active {
            return "ufw".to_string();
        }
    }
    if has_cmd("nft") {
        return "nft".to_string();
    }
    if has_cmd("iptables") {
        return "iptables".to_string();
    }
    "none".to_string()
}

/// 从监听地址里抠端口。`0.0.0.0:8080`、`[::]:443`、`127.0.0.1:9000` 都要认。
pub fn port_of(listen: &str) -> Option<u16> {
    let s = listen.trim();
    if s.is_empty() {
        return None;
    }
    let tail = s.rsplit_once(':')?.1;
    tail.parse::<u16>().ok()
}

/// 网关实际会监听的端口集合 = 网关 + HTTPS + 管理面 + 用户额外指定
pub fn desired_ports(cfg: &Config) -> Vec<u16> {
    let mut v: Vec<u16> = Vec::new();
    for s in [
        Some(cfg.server.listen.clone()),
        Some(cfg.server.admin_listen.clone()),
        cfg.tls.enabled.then(|| cfg.tls.listen.clone()),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(p) = port_of(&s) {
            v.push(p);
        }
    }
    for s in [&cfg.server.listen_v6, &cfg.server.admin_listen_v6, &cfg.tls.listen_v6] {
        if let Some(p) = port_of(s) {
            v.push(p);
        }
    }
    v.extend(cfg.firewall.extra_ports.iter().copied().filter(|p| *p > 0));
    v.sort_unstable();
    v.dedup();
    v
}

fn run(script: &str) -> (bool, String) {
    match Command::new("sh").arg("-c").arg(script).output() {
        Ok(o) => {
            let mut msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            if !err.is_empty() {
                if !msg.is_empty() {
                    msg.push_str(" | ");
                }
                msg.push_str(&err);
            }
            (o.status.success(), msg)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// 同步到系统防火墙。**阻塞**调用 —— 由调用方丢进 spawn_blocking。
pub fn apply(cfg: &Config) -> Report {
    let ports = desired_ports(cfg);
    let mut steps = Vec::new();
    let mut backend = cfg.firewall.backend.trim().to_ascii_lowercase();
    if backend.is_empty() || backend == "auto" {
        backend = detect();
    }

    if !cfg.firewall.enabled {
        return Report {
            ok: false,
            backend,
            ports,
            steps,
            error: "防火墙联动未启用（[firewall] enabled = false）".to_string(),
        };
    }
    if ports.is_empty() {
        return Report {
            ok: false,
            backend,
            ports,
            steps,
            error: "没有可放行的端口".to_string(),
        };
    }

    let list = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let (ok, err) = match backend.as_str() {
        "ufw" => {
            let mut ok = true;
            let mut err = String::new();
            for p in &ports {
                let (o, m) = run(&format!("ufw allow {p}/tcp"));
                steps.push(format!("ufw allow {p}/tcp → {}", if o { "ok" } else { &m }));
                ok &= o;
                if !o {
                    err = m;
                }
            }
            (ok, err)
        }
        "nft" => {
            // 专用表 + 专用链：不碰系统已有的规则集，卸载时 `nft delete table inet optical` 即可
            let script = format!(
                "nft list table inet optical >/dev/null 2>&1 || nft add table inet optical\n\
                 nft 'add chain inet optical input {{ type filter hook input priority -10 ; }}' 2>/dev/null || true\n\
                 nft flush chain inet optical input\n\
                 nft add rule inet optical input tcp dport {{ {list} }} accept\n\
                 nft add rule inet optical input ct state established,related accept"
            );
            let (o, m) = run(&script);
            steps.push(format!("nft 表 inet optical 重建 → {}", if o { "ok" } else { &m }));
            (o, m)
        }
        "iptables" => {
            let mut script = String::from(
                "iptables -n OPTICAL_IN >/dev/null 2>&1 || iptables -N OPTICAL_IN\n\
                 iptables -F OPTICAL_IN\n",
            );
            for p in &ports {
                script.push_str(&format!(
                    "iptables -A OPTICAL_IN -p tcp --dport {p} -j ACCEPT\n"
                ));
            }
            // 已经挂在 INPUT 上就别重复挂，否则规则越积越多
            script.push_str(
                "iptables -C INPUT -j OPTICAL_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j OPTICAL_IN\n",
            );
            let (o, m) = run(&script);
            steps.push(format!("iptables 链 OPTICAL_IN 重建 → {}", if o { "ok" } else { &m }));
            (o, m)
        }
        "none" | "off" => (
            false,
            "后端为 none：没有可用的防火墙工具（nft / iptables / ufw 都没找到）".to_string(),
        ),
        other => (false, format!("未知的防火墙后端: {other}")),
    };

    Report {
        ok,
        backend,
        ports,
        steps,
        error: if ok { String::new() } else { err },
    }
}

/// 当前的放行状态（只读，不改任何东西）
pub fn status(cfg: &Config) -> Report {
    let ports = desired_ports(cfg);
    let mut backend = cfg.firewall.backend.trim().to_ascii_lowercase();
    if backend.is_empty() || backend == "auto" {
        backend = detect();
    }
    let mut steps = Vec::new();
    let detail = match backend.as_str() {
        "ufw" => run("ufw status numbered 2>&1 | head -40").1,
        "nft" => run("nft list chain inet optical input 2>&1 | head -40").1,
        "iptables" => run("iptables -S OPTICAL_IN 2>&1 | head -40").1,
        _ => String::new(),
    };
    if !detail.is_empty() {
        steps.push(detail);
    }
    Report {
        ok: true,
        backend,
        ports,
        steps,
        error: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_are_parsed_from_various_listen_forms() {
        assert_eq!(port_of("0.0.0.0:8080"), Some(8080));
        assert_eq!(port_of("[::]:443"), Some(443));
        assert_eq!(port_of("127.0.0.1:9000"), Some(9000));
        assert_eq!(port_of("garbage"), None);
    }

    #[test]
    fn desired_ports_cover_gateway_tls_admin_and_extras() {
        let mut c = Config::default();
        c.server.listen = "0.0.0.0:18080".into();
        c.server.admin_listen = "127.0.0.1:19100".into();
        c.tls.enabled = true;
        c.tls.listen = "0.0.0.0:18443".into();
        c.firewall.extra_ports = vec![18080, 2222];
        let p = desired_ports(&c);
        assert_eq!(p, vec![2222, 18080, 18443, 19100]);
    }

    #[test]
    fn disabled_firewall_reports_without_touching_system() {
        let mut c = Config::default();
        c.server.listen = "0.0.0.0:1234".into();
        c.firewall.enabled = false;
        let r = apply(&c);
        assert!(!r.ok);
        assert!(r.error.contains("未启用"));
    }
}
