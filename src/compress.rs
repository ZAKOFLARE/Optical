//! 响应压缩：gzip / brotli。
//!
//! 三条硬规则，都是从"压错了比不压更糟"反推出来的：
//!
//! 1. **只压"确定值得压"的东西**：文本类 + 大小在 `[min_bytes, max_bytes]` 之间。
//!    小于下限，头部开销比省下的还多；大于上限，为了一次响应把整块内容读进内存，
//!    等于给自己开一个 OOM 入口——网关宁可直传也不替你做这个决定。
//! 2. **上游已经压过就不再动**：`Content-Encoding` 已存在就原样透传，
//!    二次压缩只会得到更大的字节和更长的 CPU 时间。
//! 3. **压缩后必须改头**：删 `Content-Length`（长度变了）、
//!    删 `ETag`（它描述的是未压缩的表示，留着会让缓存交出错的字节）、
//!    加 `Vary: Accept-Encoding`（否则 CDN 会把 br 版本发给不支持 br 的客户端）。

use crate::config::CompressionConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enc {
    Gzip,
    Brotli,
}

impl Enc {
    pub fn as_str(self) -> &'static str {
        match self {
            Enc::Gzip => "gzip",
            Enc::Brotli => "br",
        }
    }
}

/// 解析 `Accept-Encoding` 并挑一个。带 q 值的要按 q 排序，不能只看谁先出现——
/// 浏览器普遍发 `gzip, deflate, br`，但 `br;q=0` 这种明确拒绝的写法必须尊重。
pub fn negotiate(accept: &str, cfg: &CompressionConfig) -> Option<Enc> {
    if !cfg.enabled {
        return None;
    }
    let mut gzip_q = 0.0f32;
    let mut br_q = 0.0f32;
    for part in accept.split(',') {
        let mut it = part.split(';');
        let name = it.next().unwrap_or("").trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for attr in it {
            let a = attr.trim();
            if let Some(v) = a.strip_prefix("q=").or_else(|| a.strip_prefix("Q=")) {
                q = v.trim().parse::<f32>().unwrap_or(0.0);
            }
        }
        match name.as_str() {
            // 通配符只在不认识任何具体编码时兜底
            "*" => {
                if gzip_q == 0.0 {
                    gzip_q = q * 0.5;
                }
            }
            "gzip" | "x-gzip" => gzip_q = q,
            "br" => br_q = q,
            _ => {}
        }
    }
    let mut best: Option<(Enc, f32)> = None;
    if cfg.brotli && br_q > 0.0 {
        best = Some((Enc::Brotli, br_q));
    }
    if cfg.gzip && gzip_q > 0.0 {
        // 同 q 时优先 br：同样的内容 br 通常再小 15%~20%
        match best {
            Some((_, bq)) if bq >= gzip_q => {}
            _ => best = Some((Enc::Gzip, gzip_q)),
        }
    }
    best.map(|(e, _)| e)
}

/// 这个响应值不值得压。返回 `None` 就直传。
pub fn should_compress(
    cfg: &CompressionConfig,
    status: u16,
    content_type: Option<&str>,
    content_length: Option<u64>,
    has_encoding: bool,
) -> bool {
    if !cfg.enabled || has_encoding {
        return false;
    }
    // 1xx/204/304 没有响应体，压了也没意义
    if status < 200 || status == 204 || status == 304 {
        return false;
    }
    let Some(ct) = content_type else { return false };
    if !is_compressible(ct) {
        return false;
    }
    // 长度未知（分块）时不压：要么整段缓冲（内存不可控），要么流式压（复杂度翻倍），
    // 两条路都不值得为一个"可能省点带宽"的收益去承担
    let Some(len) = content_length else {
        return false;
    };
    len >= cfg.min_bytes as u64 && len <= cfg.max_bytes as u64
}

/// 文本类才压。图片/视频/压缩包再压一轮通常只会变大。
pub fn is_compressible(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct.starts_with("text/") {
        return true;
    }
    matches!(
        ct.as_str(),
        "application/json"
            | "application/javascript"
            | "application/x-javascript"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "application/manifest+json"
            | "application/ld+json"
            | "application/wasm"
            | "image/svg+xml"
            | "font/ttf"
            | "font/otf"
            | "font/woff"
            | "font/woff2"
    )
}

/// 真正编码。`level` 是 1..9 的通用档位，gzip 直接映射，brotli 折半使用——
/// brotli 的 9 档在网关上会把 CPU 吃干净，而收益只有几个百分点。
pub fn encode(enc: Enc, data: &[u8], level: u32) -> std::io::Result<Vec<u8>> {
    let level = level.clamp(1, 9);
    match enc {
        Enc::Gzip => {
            use std::io::Write;
            let mut out = Vec::with_capacity(data.len() / 2 + 64);
            let mut w = flate2::write::GzEncoder::new(
                &mut out,
                flate2::Compression::new(level as u32),
            );
            w.write_all(data)?;
            w.finish()?;
            Ok(out)
        }
        Enc::Brotli => {
            // 质量档位：1..9 映射到 0..7（brotli 的 9~11 是"离线压"的档位）
            let q = (level.saturating_sub(1) * 7 / 8).min(7) as u32;
            let mut out = Vec::with_capacity(data.len() / 2 + 64);
            {
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, q, 22);
                use std::io::Write;
                w.write_all(data)?;
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CompressionConfig {
        CompressionConfig::default()
    }

    #[test]
    fn picks_brotli_when_accepted() {
        let c = cfg();
        assert_eq!(negotiate("gzip, deflate, br", &c), Some(Enc::Brotli));
        assert_eq!(negotiate("gzip", &c), Some(Enc::Gzip));
        assert_eq!(negotiate("identity", &c), None);
        assert_eq!(negotiate("", &c), None);
    }

    #[test]
    fn respects_q_values() {
        let c = cfg();
        // br;q=0 是"明确不要"，不能因为它是最后一个就选它
        assert_eq!(negotiate("br;q=0, gzip;q=0.8", &c), Some(Enc::Gzip));
        // gzip 更高就选 gzip，即使 br 在前
        assert_eq!(negotiate("br;q=0.5, gzip;q=0.9", &c), Some(Enc::Gzip));
        assert_eq!(negotiate("gzip;q=0, br;q=0", &c), None);
    }

    #[test]
    fn disabled_config_never_negotiates() {
        let mut c = cfg();
        c.enabled = false;
        assert_eq!(negotiate("gzip, br", &c), None);
        assert!(!should_compress(&c, 200, Some("text/html"), Some(4096), false));
    }

    #[test]
    fn honours_protocol_switches() {
        let mut c = cfg();
        c.brotli = false;
        assert_eq!(negotiate("br", &c), None);
        assert_eq!(negotiate("br, gzip", &c), Some(Enc::Gzip));
        c.gzip = false;
        assert_eq!(negotiate("br, gzip", &c), None);
    }

    #[test]
    fn skips_what_must_not_be_compressed() {
        let c = cfg();
        // 已经有编码
        assert!(!should_compress(&c, 200, Some("text/html"), Some(4096), true));
        // 文本以外
        assert!(!should_compress(&c, 200, Some("image/png"), Some(4096), false));
        assert!(!should_compress(&c, 200, Some("video/mp4"), Some(999_999), false));
        // 太小 / 太大
        assert!(!should_compress(&c, 200, Some("text/html"), Some(10), false));
        assert!(!should_compress(&c, 200, Some("text/html"), Some(50 * 1024 * 1024), false));
        // 长度未知
        assert!(!should_compress(&c, 200, Some("text/html"), None, false));
        // 无响应体的状态码
        assert!(!should_compress(&c, 204, Some("text/html"), Some(4096), false));
        assert!(!should_compress(&c, 304, Some("text/html"), Some(4096), false));
        // 值得压的
        assert!(should_compress(&c, 200, Some("text/html; charset=utf-8"), Some(4096), false));
        assert!(should_compress(&c, 200, Some("application/json"), Some(4096), false));
    }

    #[test]
    fn gzip_roundtrip_smaller() {
        let src = b"hello hello hello hello hello hello hello hello".repeat(50);
        let out = encode(Enc::Gzip, &src, 6).unwrap();
        assert!(out.len() < src.len(), "压缩后应更小：{} vs {}", out.len(), src.len());
        assert_eq!(&out[..2], &[0x1f, 0x8b], "gzip 魔数");
        let mut back = Vec::new();
        std::io::copy(&mut flate2::read::GzDecoder::new(&out[..]), &mut back).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn brotli_roundtrip_smaller() {
        let src = b"{\"key\":\"value\"}".repeat(200);
        let out = encode(Enc::Brotli, &src, 5).unwrap();
        assert!(out.len() < src.len(), "压缩后应更小：{} vs {}", out.len(), src.len());
        let mut back = Vec::new();
        let mut r = brotli::Decompressor::new(&out[..], 4096);
        std::io::copy(&mut r, &mut back).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn text_detection_covers_charset_and_svg() {
        assert!(is_compressible("text/css; charset=utf-8"));
        assert!(is_compressible("application/javascript"));
        assert!(is_compressible("image/svg+xml"));
        assert!(!is_compressible("application/octet-stream"));
        assert!(!is_compressible("application/zip"));
    }
}
