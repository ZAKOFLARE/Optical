//! 管理面认证：argon2 口令 + 可选 TOTP 二次验证 + 内存会话 + 登录限速。
//!
//! 取舍说明：会话放内存而不是写盘，进程重启即全部失效——对一个网关管理面来说，
//! 「重启后旧会话立刻作废」是特性不是缺陷。要分布式会话请上 Redis，那是另一个量级的事。

use crate::config::{AdminConfig, TotpAlgorithm};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug)]
pub enum AuthError {
    BadCredentials,
    TooManyAttempts { retry_after_secs: u64 },
    TotpRequired,
    TotpInvalid,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::BadCredentials => "bad_credentials",
            AuthError::TooManyAttempts { .. } => "too_many_attempts",
            AuthError::TotpRequired => "totp_required",
            AuthError::TotpInvalid => "totp_invalid",
        }
    }
    pub fn message(&self) -> String {
        match self {
            AuthError::BadCredentials => "用户名或口令错误".into(),
            AuthError::TooManyAttempts { retry_after_secs } => {
                format!("尝试过于频繁，请 {retry_after_secs}s 后再试")
            }
            AuthError::TotpRequired => "需要 6 位动态验证码".into(),
            AuthError::TotpInvalid => "动态验证码错误或已过期".into(),
        }
    }
}

#[derive(Default)]
pub struct AuthState {
    sessions: Mutex<HashMap<String, Instant>>,
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl AuthState {
    pub fn new() -> Self {
        Self::default()
    }

    /// 校验口令（+ TOTP），通过则签发会话令牌。
    pub fn login(
        &self,
        cfg: &AdminConfig,
        username: &str,
        password: &str,
        totp: &str,
        client_ip: &str,
    ) -> Result<String, AuthError> {
        let throttle_key = format!("{username}@{client_ip}");
        self.check_throttle(cfg, &throttle_key)?;

        let user_ok = username == cfg.username;
        let pass_ok = !cfg.password_hash.is_empty()
            && verify_password(&cfg.password_hash, password).unwrap_or(false);

        if !user_ok || !pass_ok {
            self.record_failure(cfg, &throttle_key);
            return Err(AuthError::BadCredentials);
        }

        if cfg.totp_enabled {
            if totp.trim().is_empty() {
                return Err(AuthError::TotpRequired);
            }
            if !totp_verify_alg(&cfg.totp_secret, totp.trim(), cfg.totp_algorithm) {
                self.record_failure(cfg, &throttle_key);
                return Err(AuthError::TotpInvalid);
            }
        }

        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&throttle_key);

        let token = random_token();
        let ttl = Duration::from_secs(cfg.session_ttl_secs.max(60));
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, exp| *exp > Instant::now());
        g.insert(token.clone(), Instant::now() + ttl);
        Ok(token)
    }

    /// 供 CLI 使用的本地会话（启动时由进程自己签发，落盘 0600，退出即失效）。
    pub fn add_session(&self, token: &str, ttl_secs: u64) {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(token.to_string(), Instant::now() + Duration::from_secs(ttl_secs.max(60)));
    }

    pub fn check(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match g.get(token) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                g.remove(token);
                false
            }
            None => false,
        }
    }

    pub fn logout(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }

    pub fn active_sessions(&self) -> usize {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, exp| *exp > Instant::now());
        g.len()
    }

    fn check_throttle(&self, cfg: &AdminConfig, key: &str) -> Result<(), AuthError> {
        let mut g = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let window = Duration::from_secs(cfg.failed_window_secs.max(1));
        if let Some((count, first)) = g.get(key) {
            if first.elapsed() > window {
                g.remove(key);
                return Ok(());
            }
            if *count >= cfg.max_failed_attempts {
                let left = window.saturating_sub(first.elapsed()).as_secs() + 1;
                return Err(AuthError::TooManyAttempts {
                    retry_after_secs: left,
                });
            }
        }
        Ok(())
    }

    fn record_failure(&self, cfg: &AdminConfig, key: &str) {
        let window = Duration::from_secs(cfg.failed_window_secs.max(1));
        let mut g = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let entry = g.entry(key.to_string()).or_insert((0, Instant::now()));
        if entry.1.elapsed() > window {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 哈希失败: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("口令哈希格式非法: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// 生成随机口令（首次启动没配 password_hash 时用）。
pub fn random_password(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    use rand::Rng;
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn random_token() -> String {
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_totp_secret() -> String {
    let mut rng = rand::thread_rng();
    use rand::RngCore;
    let mut buf = [0u8; 20];
    rng.fill_bytes(&mut buf);
    crate::config::encode_base32(&buf)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 6238 TOTP（30s / 6 位），摘要算法由配置决定。
///
/// 关于 SHA1：RFC 6238 的默认算法就是 HMAC-SHA1，绝大多数验证器只有显式声明时才认
/// SHA256/SHA512。这里的 SHA1 只保护"30 秒内有效的一次性数字"，不碰口令、不碰会话令牌；
/// 真要更强就在 `admin.totp_algorithm` 里切到 sha256/sha512（otpauth URI 会同步）。
pub fn totp_code_alg(secret_b32: &str, step_offset: i64, alg: TotpAlgorithm) -> Option<String> {
    let key = crate::config::decode_base32(secret_b32)?;
    let counter = ((now_unix() / 30) as i64 + step_offset).max(0) as u64;
    let msg = counter.to_be_bytes();

    let digest: Vec<u8> = match alg {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(&key).ok()?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(&key).ok()?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(&key).ok()?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // RFC 4226 动态截断：取最后一字节低 4 位作偏移，与摘要长度无关
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Some(format!("{:06}", bin % 1_000_000))
}

/// 兼容旧调用：默认 SHA1。生产路径用 `totp_code_alg`，这两个只给单测当参照实现。
#[cfg(test)]
pub fn totp_code(secret_b32: &str, step_offset: i64) -> Option<String> {
    totp_code_alg(secret_b32, step_offset, TotpAlgorithm::Sha1)
}

/// 前后各放宽一个时间片，容忍客户端时钟漂移。
pub fn totp_verify_alg(secret_b32: &str, code: &str, alg: TotpAlgorithm) -> bool {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    (-1..=1).any(|off| match totp_code_alg(secret_b32, off, alg) {
        Some(expected) => constant_eq(&expected, &code),
        None => false,
    })
}

#[cfg(test)]
pub fn totp_verify(secret_b32: &str, code: &str) -> bool {
    totp_verify_alg(secret_b32, code, TotpAlgorithm::Sha1)
}

fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// otpauth:// 链接，方便扫码导入验证器。算法必须和配置一致，否则验证器算出来的码永远不对。
pub fn otpauth_uri(secret: &str, user: &str, alg: TotpAlgorithm) -> String {
    format!(
        "otpauth://totp/Optical:{}?secret={}&issuer=Optical&algorithm={}&digits=6&period=30",
        user,
        secret,
        alg.otpauth_name()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_password(pw: &str) -> AdminConfig {
        AdminConfig {
            enabled: true,
            username: "admin".into(),
            password_hash: hash_password(pw).unwrap(),
            totp_enabled: false,
            totp_algorithm: TotpAlgorithm::Sha1,
            totp_secret: String::new(),
            session_ttl_secs: 3600,
            max_failed_attempts: 3,
            failed_window_secs: 60,
        }
    }

    #[test]
    fn password_roundtrip() {
        let h = hash_password("s3cret-pass").unwrap();
        assert!(verify_password(&h, "s3cret-pass").unwrap());
        assert!(!verify_password(&h, "wrong").unwrap());
    }

    #[test]
    fn login_issues_verifiable_session() {
        let c = cfg_with_password("pw");
        let a = AuthState::new();
        let token = a.login(&c, "admin", "pw", "", "1.2.3.4").unwrap();
        assert!(a.check(&token));
        a.logout(&token);
        assert!(!a.check(&token));
    }

    #[test]
    fn wrong_password_rejected_and_throttled() {
        let c = cfg_with_password("pw");
        let a = AuthState::new();
        for _ in 0..3 {
            assert!(matches!(
                a.login(&c, "admin", "bad", "", "1.2.3.4"),
                Err(AuthError::BadCredentials)
            ));
        }
        assert!(matches!(
            a.login(&c, "admin", "pw", "", "1.2.3.4"),
            Err(AuthError::TooManyAttempts { .. })
        ));
    }

    #[test]
    fn totp_requires_code_when_enabled() {
        let mut c = cfg_with_password("pw");
        c.totp_enabled = true;
        c.totp_secret = random_totp_secret();
        let a = AuthState::new();
        assert!(matches!(
            a.login(&c, "admin", "pw", "", "1.2.3.4"),
            Err(AuthError::TotpRequired)
        ));
        let code = totp_code_alg(&c.totp_secret, 0, TotpAlgorithm::Sha1).unwrap();
        assert!(a.login(&c, "admin", "pw", &code, "1.2.3.4").is_ok());
    }

    #[test]
    fn totp_rejects_bad_code() {
        let secret = random_totp_secret();
        assert!(!totp_verify(&secret, "000000") || totp_code(&secret, 0).as_deref() == Some("000000"));
        assert!(!totp_verify(&secret, "abc"));
        // 三种摘要都能自洽；跨算法不应互相通过
        for alg in [TotpAlgorithm::Sha1, TotpAlgorithm::Sha256, TotpAlgorithm::Sha512] {
            let c = totp_code_alg(&secret, 0, alg).unwrap();
            assert!(totp_verify_alg(&secret, &c, alg));
        }
        let sha1_code = totp_code_alg(&secret, 0, TotpAlgorithm::Sha1).unwrap();
        let sha256_code = totp_code_alg(&secret, 0, TotpAlgorithm::Sha256).unwrap();
        assert_ne!(sha1_code, sha256_code);
    }
}
