//! 自定义错误页。
//!
//! 三级回退，顺序固定：
//! 1. `<error_pages_dir>/<status>.html` —— 运维放的文件，改完立刻生效（按 mtime 缓存）
//! 2. `[error_pages.bodies]` 里的内联模板（TOML 键要加引号，如 `"502" = "..."`）
//! 3. 内置模板
//!
//! 目录由 `config.resolve_paths()` 统一解析：默认 `<data_dir>/error-pages`，
//! 可以通过 `[paths] error_pages_dir` 或 `[error_pages] dir` 改到任何位置，
//! 容器里挂卷不需要改代码。
//!
//! 模板占位：`{{status}}` `{{reason}}` `{{message}}` `{{footer}}`。
//! `message` 会被 HTML 转义——错误信息里可能带用户输入的路径，不能直接拼进 HTML。

use crate::config::{Config, ResolvedPaths};
use http::StatusCode;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const BUILTIN: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{status}} {{reason}}</title>
<style>
  :root{color-scheme:light}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#f4f6f9;color:#1b222e;
    font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif}
  .box{width:min(560px,92vw);background:#fff;border:1px solid #e6e9ef;padding:28px 30px}
  .code{font:700 34px/1 ui-monospace,Consolas,monospace;color:#0052d9;letter-spacing:-.02em}
  .reason{margin:8px 0 0;font-size:15px;font-weight:600}
  .msg{margin:14px 0 0;padding:10px 12px;background:#fbfcfe;border-left:3px solid #d5dae3;
    font-size:12.5px;line-height:1.65;color:#5a6478;word-break:break-word}
  .foot{margin-top:18px;padding-top:12px;border-top:1px solid #e6e9ef;
    font-size:11.5px;color:#8b93a4;display:flex;justify-content:space-between}
</style>
</head>
<body>
  <div class="box">
    <div class="code">{{status}}</div>
    <p class="reason">{{reason}}</p>
    <div class="msg">{{message}}</div>
    <div class="foot"><span>{{footer}}</span><span>optical</span></div>
  </div>
</body>
</html>
"#;

/// 文件缓存：路径 → (mtime, 内容)。错误页是低频路径，但被刷的时候不能每次都打盘。
type Cache = Mutex<HashMap<PathBuf, (Option<SystemTime>, String)>>;

fn cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn read_cached(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok();
    let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some((cached_mtime, text)) = c.get(path) {
        if *cached_mtime == mtime {
            return Some(text.clone());
        }
    }
    let text = std::fs::read_to_string(path).ok()?;
    c.insert(path.to_path_buf(), (mtime, text.clone()));
    Some(text)
}

pub fn reason_phrase(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        418 => "I'm a Teapot",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// 渲染一个自定义错误页。返回 (body, content_type)。
pub fn render(
    cfg: &Config,
    paths: &ResolvedPaths,
    status: StatusCode,
    message: &str,
) -> (String, String) {
    if !cfg.error_pages.enabled {
        return (
            format!("{message}\n"),
            "text/plain; charset=utf-8".to_string(),
        );
    }

    let code = status.as_u16().to_string();
    let file = read_cached(&paths.error_pages_dir.join(format!("{code}.html")))
        .or_else(|| cfg.error_pages.bodies.get(&code).cloned());
    let template = file.unwrap_or_else(|| BUILTIN.to_string());

    let body = template
        .replace("{{status}}", &code)
        .replace("{{reason}}", reason_phrase(status))
        .replace("{{message}}", &escape_html(message))
        .replace("{{footer}}", &escape_html(&cfg.error_pages.footer));

    let ct = if cfg.error_pages.content_type.trim().is_empty() {
        "text/html; charset=utf-8".to_string()
    } else {
        cfg.error_pages.content_type.clone()
    };
    (body, ct)
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_paths(dir: PathBuf) -> ResolvedPaths {
        ResolvedPaths {
            data_dir: dir.clone(),
            config_history: dir.join("conf-history"),
            audit_file: dir.join("audit.jsonl"),
            tls_dir: dir.join("tls"),
            error_pages_dir: dir.join("error-pages"),
        }
    }

    #[test]
    fn builtin_used_when_nothing_configured() {
        let dir = std::env::temp_dir().join(format!("optical-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config::default();
        let (body, ct) = render(&cfg, &tmp_paths(dir), StatusCode::BAD_GATEWAY, "上游挂了");
        assert!(ct.starts_with("text/html"));
        assert!(body.contains("502"));
        assert!(body.contains("上游挂了"));
    }

    #[test]
    fn file_beats_inline_and_message_is_escaped() {
        let dir = std::env::temp_dir().join(format!("optical-err-file-{}", std::process::id()));
        let paths = tmp_paths(dir.clone());
        std::fs::create_dir_all(&paths.error_pages_dir).unwrap();
        std::fs::write(paths.error_pages_dir.join("502.html"), "<p>{{status}}|{{message}}</p>").unwrap();

        let mut cfg = Config::default();
        cfg.error_pages.bodies.insert("502".into(), "inline".into());
        let (body, _) = render(&cfg, &paths, StatusCode::BAD_GATEWAY, "<script>x</script>");
        assert!(body.contains("502"));
        assert!(!body.contains("<script>"), "message 必须被转义: {body}");
        assert!(body.contains("&lt;script&gt;"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_falls_back_to_plain_text() {
        let dir = std::env::temp_dir().join(format!("optical-err-off-{}", std::process::id()));
        let mut cfg = Config::default();
        cfg.error_pages.enabled = false;
        let (body, ct) = render(&cfg, &tmp_paths(dir), StatusCode::FORBIDDEN, "denied");
        assert_eq!(body, "denied\n");
        assert!(ct.starts_with("text/plain"));
    }
}
