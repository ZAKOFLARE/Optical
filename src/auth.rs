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
            // 把"下一步该干嘛"写进错误里：只说"错误或已过期"，人只会去重装 App
            AuthError::TotpInvalid => "动态验证码错误或已过期（算法必须与 App 一致：Google Authenticator 只认 SHA1；密钥换了就要重新扫码。彻底进不去可在服务器上执行 optical totp off）".into(),
        }
    }
}

/// 一条在线会话。管理面只有自己一个人用，但"哪台设备还在线、什么时候来过"
/// 是排查问题的第一条线索（口令是不是被人在别处用了）。
#[derive(Debug, Clone)]
struct Session {
    /// 上游下发的是完整令牌（HttpOnly Cookie 里），列表里只给短 id：
    /// 把自己的会话令牌打到页面上，等于给它多一条泄露路径。
    id: String,
    created: SystemTime,
    last_seen: SystemTime,
    expires: Instant,
    ip: String,
    ua: String,
}

/// 给前端看的会话视图。
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub ip: String,
    pub ua: String,
    pub created_ms: i64,
    pub last_seen_ms: i64,
    /// 距离过期还有多少秒（负数/0 表示已过期，列表里其实不会出现）
    pub expires_in: u64,
    pub current: bool,
}

#[derive(Default)]
pub struct AuthState {
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

fn epoch_ms(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 会话令牌的短 id：同一条令牌永远算出同一个 id，但反推不回令牌。
fn session_id(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// UA 只做到"能认出是哪台机器的哪类客户端"就够了。
/// 完整 UA 又长又难读，而精确指纹在这里没有意义——网关不是广告联盟。
fn short_ua(ua: &str) -> String {
    let l = ua.to_ascii_lowercase();
    let os = if l.contains("windows") {
        "Windows"
    } else if l.contains("android") {
        "Android"
    } else if l.contains("iphone") || l.contains("ipad") || l.contains("ios") {
        "iOS"
    } else if l.contains("mac os") || l.contains("macintosh") {
        "macOS"
    } else if l.contains("linux") {
        "Linux"
    } else {
        ""
    };
    let br = if l.contains("edg/") {
        "Edge"
    } else if l.contains("opr/") || l.contains("opera") {
        "Opera"
    } else if l.contains("firefox") {
        "Firefox"
    } else if l.contains("chrome") || l.contains("crios") {
        "Chrome"
    } else if l.contains("safari") {
        "Safari"
    } else if l.contains("curl") {
        "curl"
    } else if l.contains("python") {
        "Python"
    } else if l.contains("wget") {
        "wget"
    } else {
        ""
    };
    match (br, os) {
        ("", "") => {
            if ua.trim().is_empty() {
                "未知客户端".to_string()
            } else {
                ua.chars().take(28).collect()
            }
        }
        ("", o) => o.to_string(),
        (b, "") => b.to_string(),
        (b, o) => format!("{b} · {o}"),
    }
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
        user_agent: &str,
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
        let now = SystemTime::now();
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, s| s.expires > Instant::now());
        // 单点登录：新会话进来，旧会话全部作废。
        // 放在登录成功之后清，登录失败不能把已登录的设备顶掉。
        if cfg.single_session {
            g.clear();
        }
        g.insert(
            token.clone(),
            Session {
                id: session_id(&token),
                created: now,
                last_seen: now,
                expires: Instant::now() + ttl,
                ip: client_ip.to_string(),
                ua: short_ua(user_agent),
            },
        );
        Ok(token)
    }

    /// 供 CLI 使用的本地会话（启动时由进程自己签发，落盘 0600，退出即失效）。
    pub fn add_session(&self, token: &str, ttl_secs: u64) {
        let now = SystemTime::now();
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(
            token.to_string(),
            Session {
                id: session_id(token),
                created: now,
                last_seen: now,
                expires: Instant::now() + Duration::from_secs(ttl_secs.max(60)),
                ip: "本机".into(),
                ua: "命令行会话".into(),
            },
        );
    }

    pub fn check(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let alive = match g.get(token) {
            Some(s) => s.expires > Instant::now(),
            None => false,
        };
        if !alive {
            g.remove(token);
            return false;
        }
        if let Some(s) = g.get_mut(token) {
            s.last_seen = SystemTime::now();
        }
        true
    }

    /// 在线设备列表，`current` 标出"就是你现在这条"。
    pub fn list(&self, current_token: &str) -> Vec<SessionInfo> {
        let now = Instant::now();
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, s| s.expires > now);
        let mut out: Vec<SessionInfo> = g
            .iter()
            .map(|(token, s)| SessionInfo {
                id: s.id.clone(),
                ip: s.ip.clone(),
                ua: s.ua.clone(),
                created_ms: epoch_ms(s.created),
                last_seen_ms: epoch_ms(s.last_seen),
                expires_in: s.expires.saturating_duration_since(now).as_secs(),
                current: token == current_token,
            })
            .collect();
        // 当前会话排最前面，其余按最近活跃排序——要找的通常是"那条不认识的"
        out.sort_by(|a, b| b.current.cmp(&a.current).then(b.last_seen_ms.cmp(&a.last_seen_ms)));
        out
    }

    /// 踢掉指定会话。返回是否真的踢掉了一条。
    pub fn revoke(&self, id: &str) -> bool {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|_, s| s.id != id);
        g.len() != before
    }

    /// 踢掉除当前之外的所有会话（"这不是我登的"时用得着）。
    pub fn revoke_others(&self, keep_token: &str) -> usize {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|token, _| token == keep_token);
        before - g.len()
    }

    pub fn logout(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }

    pub fn active_sessions(&self) -> usize {
        let mut g = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, s| s.expires > Instant::now());
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
            single_session: false,
        }
    }

    fn login(a: &AuthState, cfg: &AdminConfig, ua: &str) -> String {
        a.login(cfg, "admin", "s3cret-pass", "", "10.0.0.9", ua).unwrap()
    }

    #[test]
    fn session_records_device_and_marks_current() {
        let a = AuthState::new();
        let cfg = cfg_with_password("s3cret-pass");
        let t = login(&a, &cfg, "Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537.36");
        let list = a.list(&t);
        assert_eq!(list.len(), 1);
        assert!(list[0].current);
        assert_eq!(list[0].ip, "10.0.0.9");
        assert_eq!(list[0].ua, "Chrome · Windows");
        // 列表里只给短 id：完整令牌不该出现在任何响应里
        assert_eq!(list[0].id.len(), 12);
        assert!(!list[0].id.contains(&t[..4]));
        // 别人的视角：同一条会话不标 current
        assert!(!a.list("someone-else")[0].current);
    }

    #[test]
    fn revoke_by_id_kills_only_that_session() {
        let a = AuthState::new();
        let cfg = cfg_with_password("s3cret-pass");
        let t1 = login(&a, &cfg, "curl/8.0");
        let t2 = login(&a, &cfg, "curl/8.0");
        let id1 = a.list(&t1).iter().find(|s| s.current).unwrap().id.clone();
        assert!(a.revoke(&id1));
        assert!(!a.check(&t1), "被踢掉的会话不该还能用");
        assert!(a.check(&t2));
        assert!(!a.revoke(&id1), "重复踢同一条应当返回 false");
    }

    #[test]
    fn revoke_others_keeps_current() {
        let a = AuthState::new();
        let cfg = cfg_with_password("s3cret-pass");
        let t1 = login(&a, &cfg, "curl/8.0");
        let _ = login(&a, &cfg, "curl/8.0");
        let _ = login(&a, &cfg, "curl/8.0");
        assert_eq!(a.active_sessions(), 3);
        assert_eq!(a.revoke_others(&t1), 2);
        assert!(a.check(&t1));
        assert_eq!(a.active_sessions(), 1);
    }

    #[test]
    fn single_session_kicks_previous_login() {
        let mut cfg = cfg_with_password("s3cret-pass");
        cfg.single_session = true;
        let a = AuthState::new();
        let t1 = login(&a, &cfg, "curl/8.0");
        assert!(a.check(&t1));
        let t2 = login(&a, &cfg, "curl/8.0");
        // 新登录后旧会话必须当场失效：这是"单点登录"的全部意义
        assert!(!a.check(&t1));
        assert!(a.check(&t2));
        assert_eq!(a.active_sessions(), 1);
    }

    #[test]
    fn failed_login_does_not_drop_existing_sessions() {
        // 单点登录模式下，别人拿错口令反复尝试不能把已登录的人顶下线
        let mut cfg = cfg_with_password("s3cret-pass");
        cfg.single_session = true;
        let a = AuthState::new();
        let t1 = login(&a, &cfg, "curl/8.0");
        assert!(a.login(&cfg, "admin", "wrong", "", "1.2.3.4", "curl/8.0").is_err());
        assert!(a.check(&t1));
    }

    #[test]
    fn ua_shortener_picks_readable_label() {
        assert_eq!(short_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/121"), "Firefox · macOS");
        assert_eq!(short_ua("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit Chrome/119"), "Chrome · Linux");
        assert_eq!(short_ua(""), "未知客户端");
        assert_eq!(short_ua("curl/8.4.0"), "curl");
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
        let token = a.login(&c, "admin", "pw", "", "1.2.3.4", "test-agent").unwrap();
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
                a.login(&c, "admin", "bad", "", "1.2.3.4", "test-agent"),
                Err(AuthError::BadCredentials)
            ));
        }
        assert!(matches!(
            a.login(&c, "admin", "pw", "", "1.2.3.4", "test-agent"),
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
            a.login(&c, "admin", "pw", "", "1.2.3.4", "test-agent"),
            Err(AuthError::TotpRequired)
        ));
        let code = totp_code_alg(&c.totp_secret, 0, TotpAlgorithm::Sha1).unwrap();
        assert!(a.login(&c, "admin", "pw", &code, "1.2.3.4", "test-agent").is_ok());
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
