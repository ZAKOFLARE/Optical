//! 外观自定义：主题色、图表样式、背景与图标。
//!
//! 设计取舍：**只有标量进配置文件，图片不进**。
//! 图片落在 `data_dir/branding/<kind>.<ext>`，URL 由文件本身现算（mtime 做版本号）。
//! 把路径或 URL 写进配置，迟早会和磁盘对不上——删了文件、迁了目录、换了实例，
//! 配置里那条 URL 依然指着不存在的名字，界面上就是一片空白。让文件当唯一事实。

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 可替换的四张图。顺序即界面上的呈现顺序。
pub const KINDS: [&str; 4] = ["bg", "loading", "login", "rail"];

/// 单张图上限。背景图会被浏览器解码成位图，太大只会拖慢首屏。
pub const MAX_ASSET_BYTES: usize = 4 * 1024 * 1024;

fn default_accent() -> String {
    "#0052d9".to_string()
}

fn default_chart_style() -> String {
    "line".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppearanceConfig {
    /// 总开关。关掉就回到内置视觉，但图片文件保留——下次开回来还是原样。
    pub enabled: bool,
    /// 主题色 `#rrggbb`
    pub accent: String,
    /// `line` | `bar`
    pub chart_style: String,
}

impl Default for AppearanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            accent: default_accent(),
            chart_style: default_chart_style(),
        }
    }
}

impl AppearanceConfig {
    /// 写进配置前先规整：颜色必须是 6 位十六进制，图表样式只认两个值。
    /// 手改配置写错时回落到默认，而不是把一个非法颜色塞进 CSS 变量。
    pub fn normalize(&mut self) {
        let a = self.accent.trim();
        let ok = a.len() == 7
            && a.starts_with('#')
            && a[1..].chars().all(|c| c.is_ascii_hexdigit());
        self.accent = if ok { a.to_ascii_lowercase() } else { default_accent() };
        if self.chart_style != "bar" {
            self.chart_style = default_chart_style();
        }
    }
}

/// 一张已落盘的图。
#[derive(Debug, Clone, Serialize)]
pub struct Asset {
    pub kind: String,
    /// 带版本号的地址；版本 = 文件 mtime（毫秒），换了图地址就变，缓存自然失效。
    pub url: String,
    pub mime: String,
    pub bytes: u64,
    pub uploaded_ms: i64,
}

pub fn branding_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("branding")
}

fn mime_of_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "avif" => "image/avif",
        _ => "application/octet-stream",
    }
}

fn ext_of_mime(mime: &str) -> Option<&'static str> {
    match mime.to_ascii_lowercase().as_str() {
        "image/png" => Some("png"),
        "image/jpeg" | "image/jpg" => Some("jpg"),
        "image/webp" => Some("webp"),
        "image/gif" => Some("gif"),
        "image/svg+xml" => Some("svg"),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some("ico"),
        "image/avif" => Some("avif"),
        _ => None,
    }
}

/// 找出某个 kind 已存在的文件（扩展名不定，可能是 png 也可能是 jpg）。
fn find_asset(dir: &Path, kind: &str) -> Option<PathBuf> {
    let rd = std::fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name()?.to_string_lossy().to_string();
        if name == kind {
            continue;
        }
        if let Some(rest) = name.strip_prefix(kind) {
            if rest.starts_with('.') {
                return Some(p);
            }
        }
    }
    None
}

fn asset_of(dir: &Path, kind: &str) -> Option<Asset> {
    let p = find_asset(dir, kind)?;
    let meta = std::fs::metadata(&p).ok()?;
    let ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let ext = p.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    Some(Asset {
        kind: kind.to_string(),
        url: format!("/api/branding/{kind}?v={ms}"),
        mime: mime_of_ext(&ext).to_string(),
        bytes: meta.len(),
        uploaded_ms: ms,
    })
}

pub fn list_assets(data_dir: &Path) -> Vec<Asset> {
    let dir = branding_dir(data_dir);
    KINDS.iter().filter_map(|k| asset_of(&dir, k)).collect()
}

/// 读一张图。返回 (字节, MIME)。
pub fn read_asset(data_dir: &Path, kind: &str) -> Option<(Vec<u8>, String)> {
    if !KINDS.contains(&kind) {
        return None;
    }
    let dir = branding_dir(data_dir);
    let p = find_asset(&dir, kind)?;
    let ext = p.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    let bytes = std::fs::read(&p).ok()?;
    Some((bytes, mime_of_ext(&ext).to_string()))
}

/// 落盘。同 kind 的旧文件先删——否则 png 换成 jpg 会留下两张，
/// `find_asset` 拿到哪张全看目录顺序，属于自己给自己埋的随机性。
pub fn save_asset(data_dir: &Path, kind: &str, mime: &str, bytes: &[u8]) -> Result<Asset> {
    if !KINDS.contains(&kind) {
        bail!("不认识的图片类型: {kind}");
    }
    if bytes.is_empty() {
        bail!("文件是空的");
    }
    if bytes.len() > MAX_ASSET_BYTES {
        bail!(
            "文件太大（{} MB），上限 {} MB",
            bytes.len() / 1024 / 1024,
            MAX_ASSET_BYTES / 1024 / 1024
        );
    }
    let ext = ext_of_mime(mime).with_context(|| format!("不支持的图片格式: {mime}"))?;
    if !sniff(kind, ext, bytes) {
        bail!("文件内容与声明的格式不符（{mime}）");
    }

    let dir = branding_dir(data_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("创建目录失败: {}", dir.display()))?;
    if let Some(old) = find_asset(&dir, kind) {
        let _ = std::fs::remove_file(old);
    }
    let path = dir.join(format!("{kind}.{ext}"));
    std::fs::write(&path, bytes).with_context(|| format!("写入失败: {}", path.display()))?;
    let _ = std::fs::set_permissions(&path, perms(0o644));
    // mtime 决定 URL 版本：写完之后立刻读回来，确保拿到的是这次写入的时间
    asset_of(&dir, kind).with_context(|| "写入后读不到文件".to_string())
}

pub fn delete_asset(data_dir: &Path, kind: &str) -> bool {
    let dir = branding_dir(data_dir);
    match find_asset(&dir, kind) {
        Some(p) => std::fs::remove_file(p).is_ok(),
        None => false,
    }
}

#[cfg(unix)]
fn perms(mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode)
}

#[cfg(not(unix))]
fn perms(_mode: u32) -> std::fs::Permissions {
    std::fs::metadata(".").map(|m| m.permissions()).unwrap_or_else(|_| {
        std::fs::metadata(std::env::temp_dir())
            .expect("temp dir")
            .permissions()
    })
}

/// 只认头部魔数，不信前端给的 mime。
/// SVG 是文本，没有魔数，退一步要求它以 `<svg` 或 XML 声明开头。
fn sniff(kind: &str, ext: &str, b: &[u8]) -> bool {
    match ext {
        "png" => b.starts_with(&[0x89, b'P', b'N', b'G']),
        "jpg" => b.starts_with(&[0xFF, 0xD8, 0xFF]),
        "gif" => b.starts_with(b"GIF8"),
        "webp" => b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP",
        "ico" => b.starts_with(&[0, 0, 1, 0]),
        "avif" => b.len() > 12 && &b[4..8] == b"ftyp",
        "svg" => {
            let head = String::from_utf8_lossy(&b[..b.len().min(512)]).to_ascii_lowercase();
            head.contains("<svg")
        }
        _ => {
            let _ = kind;
            false
        }
    }
}

/// 给前端的一份完整描述：配置 + 四张图（只有存在的才有）。
pub fn payload(cfg: &AppearanceConfig, data_dir: &Path) -> serde_json::Value {
    let assets = list_assets(data_dir);
    let get = |k: &str| {
        assets
            .iter()
            .find(|a| a.kind == k)
            .map(|a| a.url.clone())
            .unwrap_or_default()
    };
    serde_json::json!({
        "ok": true,
        "enabled": cfg.enabled,
        "accent": cfg.accent,
        "chart_style": cfg.chart_style,
        "bg": get("bg"),
        "loading": get("loading"),
        "login": get("login"),
        "rail": get("rail"),
        "assets": assets,
        "max_asset_mb": MAX_ASSET_BYTES / 1024 / 1024,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "optical-appearance-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // 最小可用 PNG 头，够过魔数校验
    const PNG: [u8; 16] = [
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
    ];

    #[test]
    fn accent_is_normalized() {
        let mut c = AppearanceConfig::default();
        c.accent = "  #FF0000 ".into();
        c.normalize();
        assert_eq!(c.accent, "#ff0000");
        // 非法值回落到默认，而不是把垃圾塞进 CSS 变量
        c.accent = "red".into();
        c.normalize();
        assert_eq!(c.accent, "#0052d9");
        c.accent = "#12345".into();
        c.normalize();
        assert_eq!(c.accent, "#0052d9");
    }

    #[test]
    fn chart_style_only_accepts_bar() {
        let mut c = AppearanceConfig::default();
        assert_eq!(c.chart_style, "line");
        c.chart_style = "bar".into();
        c.normalize();
        assert_eq!(c.chart_style, "bar");
        c.chart_style = "pie".into();
        c.normalize();
        assert_eq!(c.chart_style, "line");
    }

    #[test]
    fn save_read_delete_roundtrip() {
        let dir = tmp();
        let a = save_asset(&dir, "rail", "image/png", &PNG).unwrap();
        assert!(a.url.starts_with("/api/branding/rail"));
        let (bytes, mime) = read_asset(&dir, "rail").unwrap();
        assert_eq!(bytes, PNG);
        assert_eq!(mime, "image/png");
        assert_eq!(list_assets(&dir).len(), 1);
        assert!(delete_asset(&dir, "rail"));
        assert!(read_asset(&dir, "rail").is_none());
        assert!(!delete_asset(&dir, "rail"));
    }

    #[test]
    fn mime_must_match_content() {
        let dir = tmp();
        // 声明 PNG 但内容是 JPEG：前端可以撒谎，落盘前必须自己看一眼
        let err = save_asset(&dir, "bg", "image/png", &[0xFF, 0xD8, 0xFF, 0xE0]).unwrap_err();
        assert!(err.to_string().contains("不符"), "{err}");
        assert!(read_asset(&dir, "bg").is_none());
    }

    #[test]
    fn rejects_unknown_kind_and_empty() {
        let dir = tmp();
        assert!(save_asset(&dir, "favicon", "image/png", &PNG).is_err());
        assert!(save_asset(&dir, "rail", "image/png", &[]).is_err());
        assert!(save_asset(&dir, "rail", "image/x-whatever", &PNG).is_err());
        assert!(read_asset(&dir, "nope").is_none());
    }

    #[test]
    fn replacing_changes_url_and_leaves_one_file() {
        let dir = tmp();
        let a = save_asset(&dir, "rail", "image/png", &PNG).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(12));
        let b = save_asset(&dir, "rail", "image/png", &PNG).unwrap();
        // 版本号变了，浏览器不会拿旧图
        assert_ne!(a.url, b.url, "{} vs {}", a.url, b.url);
        // 且目录里只剩一张：换格式时旧文件要清掉，否则读哪张看运气
        let n = std::fs::read_dir(branding_dir(&dir)).unwrap().count();
        assert_eq!(n, 1);
    }

    #[test]
    fn png_to_jpg_switch_removes_png() {
        let dir = tmp();
        save_asset(&dir, "rail", "image/png", &PNG).unwrap();
        let jpg = [0xFFu8, 0xD8, 0xFF, 0xE0, 0, 0x10, b'J', b'F', b'I', b'F'];
        let a = save_asset(&dir, "rail", "image/jpeg", &jpg).unwrap();
        assert!(a.url.ends_with(".jpg") || a.url.contains("?v="), "{}", a.url);
        let names: Vec<String> = std::fs::read_dir(branding_dir(&dir))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["rail.jpg".to_string()], "{names:?}");
    }

    #[test]
    fn payload_omits_missing_assets() {
        let dir = tmp();
        save_asset(&dir, "login", "image/png", &PNG).unwrap();
        let mut c = AppearanceConfig::default();
        c.enabled = true;
        c.normalize();
        let v = payload(&c, &dir);
        assert!(v["login"].as_str().unwrap().starts_with("/api/branding/login"));
        assert_eq!(v["rail"].as_str().unwrap(), "");
        assert_eq!(v["chart_style"], "line");
    }
}
