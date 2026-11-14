//! 配置模型：TOML 单一真相源。
//!
//! CLI 与 WebUI 都只操作这一个文件，进程内通过 mtime 轮询热重载，
//! 因此两种操作方式天然对齐，不存在两套状态。
//!
//! 所有安全/传输能力都是**配置驱动**：每项都有 `enabled` 开关，
//! 存储相关项（配置回溯、审计日志）都带条数/字节/天数三重配额，
//! 便于按服务器磁盘大小收缩。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
pub const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:9100";
pub const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:8081";
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_HTTPS_PORT: &str = "0.0.0.0:8443";

/// 整份配置。所有子结构都带 `#[serde(default)]`，配置文件可以只写关心的字段。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub admin: AdminConfig,
    pub cache: CacheConfig,
    pub storage: StorageConfig,
    pub paths: PathsConfig,
    pub error_pages: ErrorPagesConfig,
    pub metrics: MetricsConfig,
    pub waf: WafConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub header_rules: Vec<HeaderRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backend_groups: Vec<BackendGroupConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<BackendConfig>,
    // `[[apps]]` 展开出来的路由只存在于内存里：序列化时滤掉，
    // 否则它们会被写进配置文件、也会出现在管理面 JSON 里，
    // 下一次保存再展开就变成"重名路由"，直接报错。
    #[serde(skip_serializing_if = "Vec::is_empty", serialize_with = "serialize_user_routes")]
    pub routes: Vec<RouteConfig>,
    /// 自定义规则：按请求特征改写网关行为（缓存/回源/重定向/鉴权等）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<crate::rules::Rule>,
    /// 静态站点：网关自己托管，不必再挂一个 nginx
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<crate::sites::SiteConfig>,
    /// 动态项目：网关负责拉起进程、端口映射、CORS、启停
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<crate::apps::AppConfig>,
    /// 系统防火墙联动（端口放行），和 rules 刻意分开
    pub firewall: crate::firewall::FirewallConfig,
    /// IP 黑白名单：数据面入口的第一道闸
    pub ip_filter: crate::ipfilter::IpFilterConfig,
    /// 外观：主题色、图表样式、背景与图标
    pub appearance: crate::appearance::AppearanceConfig,
    /// 响应压缩：gzip / brotli
    pub compression: CompressionConfig,
    /// 交付形态（WebUI / WebSocket 开关）
    pub delivery: DeliveryConfig,
    /// 背压：连接级 + 请求级准入
    pub backpressure: BackpressureConfig,
    /// 维护与清理
    pub maintenance: MaintenanceConfig,
    pub extensions: ExtensionsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// 网关 HTTP 监听地址（IP:PORT）
    pub listen: String,
    /// 管理面（REST + WebUI）监听地址
    pub admin_listen: String,
    /// 网关的 IPv6 监听地址（如 "[::]:8080"）；空 = 不监听 v6
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub listen_v6: String,
    /// 管理面的 IPv6 监听地址；空 = 不监听 v6。公网 v6 建议配合防火墙限制来源
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub admin_listen_v6: String,
    /// 没有命中任何路由时的兜底上游
    pub default_upstream: String,
    /// 单次上游请求超时（毫秒）
    pub request_timeout_ms: u64,
    /// 日志级别：trace/debug/info/warn/error
    pub log_level: String,
    /// 请求体参与 WAF 检查的最大字节数；超出则跳过 body 检查（记 skip 计数）
    pub max_inspect_bytes: usize,
    /// 多久扫一次堆、把空闲页还给系统（秒）。0 = 关闭。
    /// malloc_trim 只是遍历 arena 释放空闲页，代价很小；高频轻扫比低频大扫更平稳。
    pub heap_trim_secs: u64,
    /// 后端负载均衡策略，路由可用 `lb` 覆盖
    pub lb: LbStrategy,
    /// 响应里的 Server 头。非空则统一覆盖（含转发响应），空串则删除该头。
    /// 默认 "optical"：网关是链路上唯一对客户端负责的一跳，版本号不该由上游泄露。
    pub server_header: String,
    /// 可信代理：这些来源发来的 `X-Forwarded-For` / `CF-Connecting-IP` 才作数。
    ///
    /// 空 = 谁都不信（默认）。这个默认是安全取向：XFF 是客户端能随便写的头，
    /// 无脑采信等于让任何人把自己伪装成 1.2.3.4——IP 黑名单和按 IP 限流会同时失效。
    /// 前面挂了 CDN / nginx 时，把它们的出口网段填进来：
    /// 例如 ["10.0.0.0/8", "172.16.0.0/12", "2408:8000::/20"]。
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trusted_proxies: Vec<String>,
}

/// 负载均衡策略。wrr / rr 需要游标，iphash 是纯函数，random 无状态。
///
/// 明确不实现 least-conn：那要求把"在飞请求数"的计数挂到响应体生命周期上，
/// 否则长连接/流式响应会系统性算错。宁可少一个策略，也不给一个读数骗人的。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LbStrategy {
    /// 加权轮询（默认）：按 weight 分配份额，简单可预测
    #[default]
    Wrr,
    /// 纯轮询：忽略 weight，每个成员平均分
    Rr,
    /// 按客户端 IP 哈希：同一 IP 固定落到同一后端，兼容有会话粘性的服务
    #[serde(rename = "iphash")]
    IpHash,
    /// 随机：无状态，适合后端数量多且差异小的场景
    Random,
}

impl LbStrategy {
    pub fn label(&self) -> &'static str {
        match self {
            LbStrategy::Wrr => "wrr",
            LbStrategy::Rr => "rr",
            LbStrategy::IpHash => "iphash",
            LbStrategy::Random => "random",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    /// HTTPS 监听地址
    pub listen: String,
    /// HTTPS 的 IPv6 监听地址；空 = 不监听 v6
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub listen_v6: String,
    /// PEM 证书路径；留空则启动时自动生成自签开发证书
    pub cert: String,
    /// PEM 私钥路径
    pub key: String,
    /// 最低协议版本：`1.2` 或 `1.3`
    pub min_version: String,
    /// 自签证书有效期（天）
    pub self_signed_days: u32,
    /// 自签证书要签进去的额外域名/IP（SAN）。写产品域名，浏览器才能对上号
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub san: Vec<String>,
    /// 明文 HTTP 一律 301 到 HTTPS（tls.enabled 为真时生效）
    #[serde(default)]
    pub http_redirect: bool,
    /// 证书不可用（路径写错、文件被删、私钥不配对）时怎么办：
    ///
    /// - `self-signed`（默认）：退回自签继续服务，把原因写在日志、审计和状态页上。
    ///   证书是"更好的锁"，不是"门本身"——锁坏了就把门焊死，等于用户访问的是 502。
    /// - `strict`：拒绝启动 HTTPS 监听（只有明确要求"没证书就别服务"时才用）。
    #[serde(default = "default_tls_degrade")]
    pub degrade: String,
    /// TLS 1.2 会话缓存的条数。会话恢复能让老客户端免一次完整握手
    /// （省一个 RTT + 一次非对称密钥计算）。0 = 关闭恢复。
    #[serde(default = "default_tls_session_cache")]
    pub session_cache_size: usize,
    /// TLS 1.3 会话票据。true = 发送票据（客户端恢复时 1-RTT 直连），
    /// false = 每次都是完整握手。票据让恢复不需要服务端存任何状态，
    /// 但代价是前向保密窗口拉长——关掉更保守。
    #[serde(default = "default_tls_tickets")]
    pub session_tickets: bool,
}

fn default_tls_session_cache() -> usize {
    1024
}

fn default_tls_tickets() -> bool {
    true
}

fn default_tls_degrade() -> String {
    "self-signed".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    /// 管理面是否要求登录。关闭后 /api/* 直接放行（仅建议本机调试）
    pub enabled: bool,
    pub username: String,
    /// argon2 哈希；为空时启动会生成随机口令并打印到控制台
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
    /// 是否启用 TOTP 二次验证
    pub totp_enabled: bool,
    /// TOTP 的 HMAC 摘要：sha1 / sha256 / sha512。
    ///
    /// 默认 sha1 不是"偷懒"：RFC 6238 的默认算法就是 HMAC-SHA1，绝大多数
    /// 验证器 App 只有在你显式声明时才认 SHA256。这里 SHA1 只用于一次性口令，
    /// 与口令存储（argon2id）、会话令牌（256-bit CSPRNG）完全无关。
    pub totp_algorithm: TotpAlgorithm,
    /// Base32 的 TOTP 密钥；为空时开启 2FA 会自动生成
    #[serde(skip_serializing_if = "String::is_empty")]
    pub totp_secret: String,
    /// 会话有效期（秒）
    pub session_ttl_secs: u64,
    /// 失败窗口内允许的失败次数
    pub max_failed_attempts: u32,
    /// 失败计数窗口（秒）
    pub failed_window_secs: u64,
    /// 单点登录：新登录成功后，其它设备上的会话立即作废。
    /// 想让"换个浏览器看看"也互不影响时保持 false。
    pub single_session: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    /// otpauth:// 里要写大写算法名
    pub fn otpauth_name(&self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl_secs: u64,
    pub max_bytes: usize,
    pub max_entries: usize,
    /// 只缓存这些状态码
    pub cacheable_status: Vec<u16>,
    /// 只缓存这些扩展名（空表示不限制）
    pub cacheable_exts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// 配置快照保留条数
    pub config_history_keep: usize,
    /// 配置快照总字节上限
    pub config_history_max_bytes: usize,
    /// 配置快照保留天数（0 = 不按天裁剪）
    pub config_history_keep_days: u64,
    /// 是否把 WAF 命中写审计日志
    pub audit_enabled: bool,
    /// 审计日志保留条数
    pub audit_keep: usize,
    /// 审计日志总字节上限
    pub audit_max_bytes: usize,
}

/// 非固化路径：所有落盘位置都能改。
///
/// 空字符串表示"跟随上一级默认值"：`data_dir` 跟随配置文件所在目录，
/// 其余跟随 `<data_dir>/<子目录>`；相对路径按 `data_dir` 解析；`~/` 会展开到家目录。
/// 这样容器里只要把 `data_dir` 指到一个挂载卷，其余全部自动跟着走。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    pub data_dir: String,
    pub config_history_dir: String,
    pub audit_file: String,
    pub tls_dir: String,
    pub error_pages_dir: String,
}

/// 解析后的绝对/相对路径集合，运行期只认这个，不再到处拼字符串。
#[derive(Debug, Clone)]
pub struct ResolvedPaths {
    pub data_dir: PathBuf,
    pub config_history: PathBuf,
    pub audit_file: PathBuf,
    pub tls_dir: PathBuf,
    pub error_pages_dir: PathBuf,
}

/// 自定义错误页：目录优先（`<status>.html`），其次内联模板，最后内置模板。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrorPagesConfig {
    pub enabled: bool,
    /// 覆盖 `paths.error_pages_dir`；目录里按 `<status>.html` 取文件
    pub dir: String,
    pub content_type: String,
    /// 内联模板，键是状态码字符串（TOML 里必须写引号："502"）
    pub bodies: std::collections::BTreeMap<String, String>,
    /// 模板里的 {{footer}} 占位
    pub footer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Top UA / IP 列表长度
    pub top_n: usize,
    /// 采集间隔（毫秒）：服务端按这个节奏记录增量。默认 15 秒。
    /// 注意"看图的粒度"不在这里——那是查询参数，见 AppState::history_query。
    pub sample_interval_ms: u64,
    /// 历史点数上限。写满后自动合并相邻点、分辨率翻倍，窗口自然变长，内存不涨。
    pub history_points: usize,
    /// 长期留存天数：每小时一个聚合点，默认 90 天。
    /// 这是"选 30 天能真看到 30 天"的前提——细粒度环再降采样也撑不到那么远。
    /// 置 0 关掉长期留存，省下 2160 个点的内存，但大范围视图就只剩最近那截。
    pub history_days: u32,
}

/// 响应压缩。默认开，但只碰"确定值得压"的东西：
/// 文本类、长度已知且落在区间内、上游没压过。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CompressionConfig {
    pub enabled: bool,
    /// 允许 brotli（`Accept-Encoding: br`）
    pub brotli: bool,
    /// 允许 gzip
    pub gzip: bool,
    /// 小于这个字节数不压：头部开销可能比省下的还多
    pub min_bytes: usize,
    /// 大于这个字节数不压：为一次响应把整块内容读进内存，是给自己开 OOM 入口
    pub max_bytes: usize,
    /// 1..9。gzip 直接用；brotli 折半使用（9 档在网关上会把 CPU 吃干净）
    pub level: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            brotli: true,
            gzip: true,
            min_bytes: 512,
            max_bytes: 1024 * 1024,
            level: 5,
        }
    }
}

/// 背压。两层，缺一不可：
///
/// - **连接级**（`conn_per_ip` / `conn_burst_per_sec`）：包刚进来就挡，最省资源。
/// - **请求级**（`max_in_flight` / `max_in_flight_per_ip`）：真正压住内存的那道。
///   每个在途请求都握着一份请求头、缓冲区和上游连接，没有上限时，
///   慢客户端 + 大响应就能把内存吃干净，而且表现为"越慢越占内存"的死循环。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackpressureConfig {
    pub enabled: bool,
    /// 全局在途请求上限，0 = 不限。按机器内存估：一个在途请求约 32~64 KB 常驻，
    /// 1 万在途大致 300~600 MB，按这个数量级设。
    pub max_in_flight: usize,
    /// 单 IP 在途请求上限，0 = 不限
    pub max_in_flight_per_ip: usize,
    /// 单 IP 并发连接上限（0 = 回落到 waf.dos.conn_per_ip）
    pub conn_per_ip: usize,
    /// 单 IP 每秒新建连接上限（0 = 回落到 waf.dos.conn_burst_per_sec）
    pub conn_burst_per_sec: u32,
    /// 被背压拒绝时建议多久后重试
    pub retry_after_secs: u64,
    /// 被背压拒绝时返回的状态码。503 是"暂时不行，稍后再来"的标准语义；
    /// 想让它更像限流可以用 429。
    pub status_code: u16,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // 默认给一个宽松的上限：不配也不能等于没闸。
            max_in_flight: 4096,
            max_in_flight_per_ip: 128,
            conn_per_ip: 0,
            conn_burst_per_sec: 0,
            retry_after_secs: 2,
            status_code: 503,
        }
    }
}

/// 维护与清理：缓存、统计数据、历史曲线。
///
/// 缓存过期条目原来只在 lookup 命中同一个键时才清——没人访问的键会一直躺着，
/// 直到容量淘汰才让位。定时扫一遍比"等它自己撞上"靠谱。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MaintenanceConfig {
    pub enabled: bool,
    /// 定时清理间隔（秒）。0 = 不做定时清理，只保留手动清理。
    pub interval_secs: u64,
    /// 缓存占用超过 max_bytes 的这个百分比就主动清理
    pub cache_high_pct: u8,
    /// 清理时压回到这个百分比
    pub cache_low_pct: u8,
    /// 触发水位时是否自动清理。关掉就只告警不动手。
    pub cache_auto_purge: bool,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
            // 90/70 是常见的水位对：留 10% 余量给"清理期间又写进来的"
            cache_high_pct: 90,
            cache_low_pct: 70,
            cache_auto_purge: true,
        }
    }
}

/// 交付形态：控制"给谁用"的面，不控制"能不能用"。
///
/// 三档对应（CLI 与数据面网关始终可用，不拆）：
/// - 档一（网关 + CLI）       ：webui=false, websocket=false
/// - 档二（全功能，默认）     ：webui=true,  websocket=true
/// - 档三（网关 + WS + CLI）  ：webui=false, websocket=true（程序化/Ops 接入，不要人看的界面）
///
/// 注意：关 WebUI 只关**静态页面**，REST API 照常服务——CLI 和 WebSocket
/// 都依赖 REST，把它们一起关掉等于把 CLI 也废了。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryConfig {
    /// 是否提供 WebUI 静态页面（`/`）。false 时返回一段提示，
    /// REST 与 WebSocket 不受影响。
    pub webui: bool,
    /// 是否提供 `/api/ws` 实时推送。false 时拒绝升级，
    /// WebUI（若开启）会自动回退到 HTTP 轮询。
    pub websocket: bool,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self { webui: true, websocket: true }
    }
}

/// 采集间隔下限：5 秒。再细就是拿 CPU 换噪点。
pub const MIN_SAMPLE_MS: u64 = 5_000;
/// 采集间隔上限：10 分钟。再粗就只剩"有没有流量"这种信息了。
pub const MAX_SAMPLE_MS: u64 = 600_000;

/// WAF 总开关与各规则族。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WafConfig {
    pub enabled: bool,
    /// block = 超阈值直接拦截；monitor = 只记命中不拦
    pub mode: WafMode,
    /// 评分阈值：单次请求累计 severity 达到即触发动作
    pub score_threshold: u32,
    pub dos: DosConfig,
    pub xml: XmlConfig,
    pub jwt: JwtConfig,
    pub sql: SqlConfig,
    pub ssrf: SsrfConfig,
    pub bola: BolaConfig,
    pub traversal: TraversalConfig,
    pub cache_deception: CacheDeceptionConfig,
    pub params: ParamsConfig,
    pub frame: FrameConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    #[default]
    Block,
    Monitor,
}

/// 常规 DoS：连接池 + 应用层异常 + 大小限制 + cookie 压缩比。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DosConfig {
    pub enabled: bool,
    /// 单个请求 header 数量上限
    pub max_header_count: usize,
    /// header 总字节上限
    pub max_header_bytes: usize,
    /// cookie 个数上限
    pub max_cookie_count: usize,
    /// cookie 头部字节上限
    pub max_cookie_bytes: usize,
    /// cookie 解压比阈值：解压后/原始 低于该值视为压缩炸弹
    pub cookie_compression_ratio: u32,
    /// 单 cookie 原始体积上限（字节）
    pub max_cookie_value_bytes: usize,
    /// URL 长度上限
    pub max_url_len: usize,
    /// 请求体大小上限（0 = 不限制）
    pub max_body_bytes: usize,
    /// 单 IP 并发连接上限
    pub conn_per_ip: usize,
    /// 单 IP 每秒新建连接上限
    pub conn_burst_per_sec: u32,
}

/// 常规 XML：DTD / 外部实体 / XInclude / 深度 / billion laughs。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct XmlConfig {
    pub enabled: bool,
    pub block_dtd: bool,
    pub block_external_entity: bool,
    pub block_xinclude: bool,
    /// 嵌套深度上限
    pub max_depth: usize,
    /// 实体引用次数上限
    pub max_entity_refs: usize,
}

/// JWT：alg=none / 算法白名单 / kid 注入 / 过期 / 体积。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    pub enabled: bool,
    pub reject_alg_none: bool,
    pub reject_kid_injection: bool,
    /// 允许的算法白名单
    pub allowed_algs: Vec<String>,
    /// 超过该体积视为异常
    pub max_token_bytes: usize,
    /// 允许的过期宽限（秒）
    pub clock_skew_secs: u64,
}

/// SQL 注入：关键字/注释/联合查询/时间盲注评分。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SqlConfig {
    pub enabled: bool,
    /// 单条 payload 命中到多少分才计入 finding
    pub threshold: u32,
}

/// SSRF：参数名 + 内网/元数据地址。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SsrfConfig {
    pub enabled: bool,
    /// 是否允许访问内网地址（false = 拦截）
    pub allow_private: bool,
    /// 需要检查的参数名
    pub param_names: Vec<String>,
}

/// BOLA：同一身份短时间遍历大量对象 ID。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BolaConfig {
    pub enabled: bool,
    /// 统计窗口（秒）
    pub window_secs: u64,
    /// 窗口内不同对象 ID 上限
    pub max_distinct_ids: u32,
}

/// 路径穿越 + 未授权重路由（开放重定向）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TraversalConfig {
    pub enabled: bool,
    /// 拦截 URL 编码的穿越（%2e%2e%2f）
    pub block_encoded: bool,
    /// 拦截开放重定向参数
    pub block_open_redirect: bool,
    /// 重定向类参数名
    pub redirect_params: Vec<String>,
}

/// 缓存欺骗：动态资源伪装成静态文件、路径段堆叠。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheDeceptionConfig {
    pub enabled: bool,
    /// 被视为静态资源的扩展名
    pub static_exts: Vec<String>,
    /// 单请求路径段上限
    pub max_path_segments: usize,
}

/// 参数污染：同名参数不同值（HPP）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ParamsConfig {
    pub enabled: bool,
    /// 同名参数允许出现的最大次数
    pub max_duplicates: usize,
    /// 单请求参数总数上限
    pub max_params: usize,
}

/// 帧限制：防点击劫持。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FrameConfig {
    pub enabled: bool,
    /// deny / sameorigin / allow-from
    pub mode: FrameMode,
    /// allow-from 模式下的允许来源
    pub allow_from: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameMode {
    #[default]
    Deny,
    Sameorigin,
    AllowFrom,
}

/// 头改写规则。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HeaderRule {
    pub enabled: bool,
    /// request | response
    pub phase: HeaderPhase,
    /// set | add | remove
    pub action: HeaderAction,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// 路径前缀条件（空 = 全部）
    #[serde(skip_serializing_if = "String::is_empty")]
    pub match_path: String,
    /// host 条件（空 = 全部）
    #[serde(skip_serializing_if = "String::is_empty")]
    pub match_host: String,
    /// 响应阶段限定状态码（0 = 不限）
    pub when_status: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl Default for HeaderRule {
    fn default() -> Self {
        Self {
            enabled: true,
            phase: HeaderPhase::Response,
            action: HeaderAction::Set,
            name: String::new(),
            value: String::new(),
            match_path: String::new(),
            match_host: String::new(),
            when_status: 0,
            note: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderPhase {
    Request,
    #[default]
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderAction {
    #[default]
    Set,
    Add,
    Remove,
}

/// 后端分组：给一组上游一个名字、一句备注和一条负载均衡策略。
///
/// 分组可以只在成员的 `group` 字段里出现（隐式分组），此时用全局策略；
/// 显式声明是为了能写备注、能单独指定策略——面板上看得懂，运维才敢动。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendGroupConfig {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub note: String,
    /// 本组专用策略；None = 跟随 server.lb
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub strategy: Option<LbStrategy>,
}

/// 后端服务（类似宝塔面板里对接的 nginx 站点上游）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BackendConfig {
    pub name: String,
    pub url: String,
    /// 分组：同一组的成员互为备份，路由引用组名即在组内做负载均衡。
    /// 空字符串 = 不参与分组，只能按 name 单独引用。
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub group: String,
    /// 备注：只给人看，不参与任何转发逻辑
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub note: String,
    pub weight: u32,
    pub enabled: bool,
    /// 健康检查路径；空则用 `GET /`
    pub health_path: String,
    /// 健康检查间隔（秒，0 = 关闭）
    pub health_interval_secs: u64,
    pub timeout_ms: u64,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: String::new(),
            group: String::new(),
            note: String::new(),
            weight: 1,
            enabled: true,
            health_path: "/".into(),
            health_interval_secs: 10,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

impl BackendConfig {
    #[allow(dead_code)] // 供测试与后续"新建后端"接口使用
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            ..Default::default()
        }
    }
}

/// 路由。`#[serde(default)]` 是必须的：用户可能只写 `backend` 不写 `upstream`，
/// 缺字段不该直接解析失败。
///
/// 注意：这里绝不能 `#[derive(Default)]`。派生会把 `host` 变成空串、
/// `rewrite_host` 变成 false；语义默认值必须手写（见下方 impl）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteConfig {
    pub name: String,
    /// 主机匹配："*" 任意；"*.example.com" 后缀；其他为精确匹配
    pub host: String,
    /// 路径前缀匹配，必须以 '/' 开头
    pub path_prefix: String,
    /// 上游基地址（与 backend 二选一，backend 优先）
    pub upstream: String,
    /// 引用 [[backends]] 里的名字（单个后端）
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub backend: String,
    /// 引用 [[backend_groups]] 里的分组名（与 backend 二选一，本字段优先）
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub backend_group: String,
    pub strip_prefix: bool,
    pub rewrite_host: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub timeout_ms: Option<u64>,
    /// 覆盖全局缓存开关（None = 跟随全局）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cache: Option<bool>,
    /// 覆盖全局负载均衡策略（None = 跟随 server.lb）
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lb: Option<LbStrategy>,
    /// 由 `[[apps]]` 推导出来的路由（不写盘、不出现在 UI 里）。
    /// 有它就能复用整套转发/统计/缓存逻辑，不必为动态项目再写一条旁路。
    #[serde(skip_serializing, default, rename = "_synthetic")]
    pub synthetic: bool,
}

/// 只序列化用户自己写的路由；合成路由（`synthetic`）留在内存里。
fn serialize_user_routes<S: serde::Serializer>(
    routes: &[RouteConfig],
    ser: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let user: Vec<&RouteConfig> = routes.iter().filter(|r| !r.synthetic).collect();
    let mut seq = ser.serialize_seq(Some(user.len()))?;
    for r in user {
        seq.serialize_element(r)?;
    }
    seq.end()
}

/// 路由目标：单个后端或一个分组。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSpec<'a> {
    Single(&'a str),
    Group(&'a str),
}

impl<'a> TargetSpec<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            TargetSpec::Single(n) | TargetSpec::Group(n) => n,
        }
    }
    pub fn is_group(&self) -> bool {
        matches!(self, TargetSpec::Group(_))
    }
}

/// 扩展点配置：过滤链由 WAF 引擎承担，filters 保留给自研插件。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionsConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_string(),
            admin_listen: DEFAULT_ADMIN_LISTEN.to_string(),
            listen_v6: String::new(),
            admin_listen_v6: String::new(),
            default_upstream: DEFAULT_UPSTREAM.to_string(),
            request_timeout_ms: DEFAULT_TIMEOUT_MS,
            log_level: "info".to_string(),
            heap_trim_secs: 5,
            max_inspect_bytes: 8192,
            lb: LbStrategy::Wrr,
            server_header: "optical".into(),
            trusted_proxies: Vec::new(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: DEFAULT_HTTPS_PORT.to_string(),
            listen_v6: String::new(),
            cert: String::new(),
            key: String::new(),
            min_version: "1.2".to_string(),
            self_signed_days: 365,
            san: Vec::new(),
            http_redirect: false,
            degrade: default_tls_degrade(),
            session_cache_size: default_tls_session_cache(),
            session_tickets: default_tls_tickets(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            username: "admin".to_string(),
            password_hash: String::new(),
            totp_enabled: false,
            totp_algorithm: TotpAlgorithm::default(),
            totp_secret: String::new(),
            session_ttl_secs: 3600,
            max_failed_attempts: 5,
            failed_window_secs: 300,
            single_session: false,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_secs: 30,
            max_bytes: 8 * 1024 * 1024,
            max_entries: 512,
            cacheable_status: vec![200],
            cacheable_exts: vec![
                ".css".into(),
                ".js".into(),
                ".png".into(),
                ".jpg".into(),
                ".jpeg".into(),
                ".gif".into(),
                ".svg".into(),
                ".woff2".into(),
            ],
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            config_history_keep: 20,
            config_history_max_bytes: 1024 * 1024,
            config_history_keep_days: 30,
            audit_enabled: true,
            audit_keep: 2000,
            audit_max_bytes: 4 * 1024 * 1024,
        }
    }
}

impl Default for ErrorPagesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: String::new(),
            content_type: "text/html; charset=utf-8".to_string(),
            bodies: std::collections::BTreeMap::new(),
            footer: "Optical".to_string(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            top_n: 8,
            sample_interval_ms: MIN_SAMPLE_MS,
            history_points: 2880,
            history_days: 90,
        }
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: WafMode::Block,
            // 4 = 单条高置信规则（SQL 联合查询、开放重定向、缓存欺骗、HPP）即可拦截；
            // 1~3 的弱信号需要叠加才会触发。
            score_threshold: 4,
            dos: DosConfig::default(),
            xml: XmlConfig::default(),
            jwt: JwtConfig::default(),
            sql: SqlConfig::default(),
            ssrf: SsrfConfig::default(),
            bola: BolaConfig::default(),
            traversal: TraversalConfig::default(),
            cache_deception: CacheDeceptionConfig::default(),
            params: ParamsConfig::default(),
            frame: FrameConfig::default(),
        }
    }
}

impl Default for DosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_header_count: 64,
            max_header_bytes: 16384,
            max_cookie_count: 24,
            max_cookie_bytes: 8192,
            cookie_compression_ratio: 40,
            max_cookie_value_bytes: 4096,
            max_url_len: 2048,
            max_body_bytes: 2 * 1024 * 1024,
            conn_per_ip: 64,
            conn_burst_per_sec: 40,
        }
    }
}

impl Default for XmlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_dtd: true,
            block_external_entity: true,
            block_xinclude: true,
            max_depth: 32,
            max_entity_refs: 16,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            reject_alg_none: true,
            reject_kid_injection: true,
            allowed_algs: vec![
                "RS256".into(),
                "RS384".into(),
                "RS512".into(),
                "ES256".into(),
                "HS256".into(),
                "HS512".into(),
            ],
            max_token_bytes: 4096,
            clock_skew_secs: 60,
        }
    }
}

impl Default for SqlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 3,
        }
    }
}

impl Default for SsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_private: false,
            param_names: vec![
                "url".into(),
                "uri".into(),
                "next".into(),
                "target".into(),
                "redirect".into(),
                "callback".into(),
                "image".into(),
                "fetch".into(),
            ],
        }
    }
}

impl Default for BolaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_secs: 10,
            max_distinct_ids: 30,
        }
    }
}

impl Default for TraversalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_encoded: true,
            block_open_redirect: true,
            redirect_params: vec![
                "next".into(),
                "redirect".into(),
                "redirect_uri".into(),
                "return".into(),
                "returnUrl".into(),
                "continue".into(),
            ],
        }
    }
}

impl Default for CacheDeceptionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            static_exts: vec![
                ".css".into(),
                ".js".into(),
                ".png".into(),
                ".jpg".into(),
                ".gif".into(),
                ".ico".into(),
                ".woff2".into(),
            ],
            max_path_segments: 8,
        }
    }
}

impl Default for ParamsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_duplicates: 1,
            max_params: 64,
        }
    }
}

impl Default for FrameConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: FrameMode::Deny,
            allow_from: Vec::new(),
        }
    }
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: "*".into(),
            path_prefix: "/".into(),
            upstream: String::new(),
            backend: String::new(),
            backend_group: String::new(),
            strip_prefix: false,
            rewrite_host: true,
            timeout_ms: None,
            cache: None,
            lb: None,
            synthetic: false,
        }
    }
}

impl RouteConfig {
    pub fn new(name: &str, host: &str, prefix: &str, upstream: &str) -> Self {
        Self {
            name: name.to_string(),
            host: if host.is_empty() { "*".into() } else { host.into() },
            path_prefix: if prefix.is_empty() { "/".into() } else { prefix.into() },
            upstream: upstream.to_string(),
            ..Default::default()
        }
    }
}

/// 首次启动写入的配置：只依赖 default_upstream，不带死路由。
pub fn demo_config() -> Config {
    Config::default()
}

impl Config {
    /// 把 `[[apps]]` 展开成普通路由（name = `app:<name>`），并前置到路由表最前面。
    /// 只要 enabled，映射就在；启停的是进程，不是路由——否则"停掉服务"会变成 502 而不是明确的 503。
    pub fn expand_apps(&mut self) {
        // 除了自己标了 synthetic 的，还要清掉「上一版把合成路由写进配置文件」留下的残渣：
        // 名字正好是 app:<某个应用名> 的，一定是展开产物，不是人手写的。
        let app_names: Vec<String> = self.apps.iter().map(|a| format!("app:{}", a.name)).collect();
        self.routes
            .retain(|r| !r.synthetic && !app_names.iter().any(|n| *n == r.name));
        let mut extra: Vec<RouteConfig> = Vec::new();
        for app in self.apps.iter().filter(|a| a.enabled) {
            for host in &app.hosts {
                extra.push(RouteConfig {
                    name: format!("app:{}", app.name),
                    host: host.clone(),
                    path_prefix: if app.path_prefix.trim().is_empty() {
                        "/".to_string()
                    } else {
                        app.path_prefix.clone()
                    },
                    upstream: app.upstream(),
                    backend: String::new(),
                    backend_group: String::new(),
                    strip_prefix: app.strip_prefix,
                    rewrite_host: true,
                    timeout_ms: None,
                    cache: Some(false),
                    lb: None,
                    synthetic: true,
                });
            }
        }
        if !extra.is_empty() {
            extra.extend(self.routes.drain(..));
            self.routes = extra;
        }
    }

    pub fn load_or_init(path: &Path) -> Result<(Self, bool)> {
        if path.exists() {
            Ok((Self::load(path)?, false))
        } else {
            let cfg = demo_config();
            cfg.save(path)?;
            Ok((cfg, true))
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&raw).with_context(|| format!("解析 TOML 失败: {}", path.display()))?;
        Ok(cfg)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// 原子写盘：先写临时文件再 rename，避免热重载读到半截内容。
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let body = self.to_toml();
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, body)
            .with_context(|| format!("写入临时配置失败: {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("替换配置文件失败: {}", path.display()))?;
        Ok(())
    }

    /// 结构 + 语义校验，返回全部错误而不是第一个。
    /// 把 `[paths]` 里的字符串解析成实际路径。
    ///
    /// 规则（从内到外，空值往下继承）：
    /// - `data_dir` 空 → 配置文件所在目录（配置文件没目录时用 `.`）
    /// - 其余空 → `<data_dir>/<默认子路径>`
    /// - 相对路径 → 相对 `data_dir`
    /// - `~/` 开头 → 展开到 HOME / USERPROFILE
    ///
    /// 之前这些路径是写死的（`config_path.parent()/conf-history`、`.with_extension("audit.jsonl")`），
    /// 容器里挂卷时只能靠改配置文件位置来间接挪动，属于典型的固化路径。
    pub fn resolve_paths(&self, config_path: &Path) -> ResolvedPaths {
        let cfg_dir = config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let data_dir = resolve_one(&self.paths.data_dir, &cfg_dir);
        let sub = |raw: &str, name: &str| {
            if raw.trim().is_empty() {
                data_dir.join(name)
            } else {
                resolve_one(raw, &data_dir)
            }
        };

        ResolvedPaths {
            data_dir: data_dir.clone(),
            config_history: sub(&self.paths.config_history_dir, "conf-history"),
            audit_file: if self.paths.audit_file.trim().is_empty() {
                data_dir.join("optical.audit.jsonl")
            } else {
                resolve_one(&self.paths.audit_file, &data_dir)
            },
            tls_dir: sub(&self.paths.tls_dir, "tls"),
            error_pages_dir: if self.error_pages.dir.trim().is_empty() {
                sub(&self.paths.error_pages_dir, "error-pages")
            } else {
                resolve_one(&self.error_pages.dir, &data_dir)
            },
        }
    }

    /// 路由里的 `backend` 字段可能指向单个后端名，也可能指向一个组名。
    fn group_has_members(&self, group: &str) -> bool {
        self.backends.iter().any(|b| b.group == group)
    }

    #[cfg(test)]
    pub fn validate(&self) -> Vec<String> {
        self.validate_in(Path::new("."))
    }

    /// 带基准目录的校验：`tls.cert` / `tls.key` 这类相对路径按配置文件所在目录解析。
    /// 之前只认绝对路径或当前工作目录，换个 cwd 启动就报"证书不存在"，属于固化路径的变体。
    pub fn validate_in(&self, base: &Path) -> Vec<String> {
        let mut errs = Vec::new();

        if self.server.listen.parse::<SocketAddr>().is_err() {
            errs.push(format!("server.listen 非法（需要 IP:PORT）: {}", self.server.listen));
        }
        if self.server.admin_listen.parse::<SocketAddr>().is_err() {
            errs.push(format!(
                "server.admin_listen 非法（需要 IP:PORT）: {}",
                self.server.admin_listen
            ));
        }
        if let Err(e) = check_upstream(&self.server.default_upstream) {
            errs.push(format!("server.default_upstream 非法: {e}"));
        }
        if self.server.request_timeout_ms == 0 {
            errs.push("server.request_timeout_ms 必须大于 0".to_string());
        }
        if !self.server.server_header.trim().is_empty()
            && http::HeaderValue::from_str(self.server.server_header.trim()).is_err()
        {
            errs.push("server.server_header 不是合法的 header 值".to_string());
        }

        if self.tls.enabled {
            if self.tls.listen.parse::<SocketAddr>().is_err() {
                errs.push(format!("tls.listen 非法（需要 IP:PORT）: {}", self.tls.listen));
            }
            // 证书路径不存在**不能**当成致命错误：这是把 443 直接弄死的头号原因，
            // 前面挂着 CDN 的话，用户看到的就是一个没有上下文的 502。
            // 只有明确要求 strict 时才拒绝启动；默认交给 build_acceptor 退回自签。
            let strict = self.tls.degrade == "strict";
            if !self.tls.cert.is_empty() && !resolve_one(&self.tls.cert, base).exists() {
                if strict {
                    errs.push(format!("tls.cert 不存在: {}", self.tls.cert));
                } else {
                    tracing::warn!(
                        cert = %self.tls.cert,
                        "tls.cert 不存在；tls.degrade = self-signed，启动时会退回自签证书"
                    );
                }
            }
            if !self.tls.key.is_empty() && !resolve_one(&self.tls.key, base).exists() {
                if strict {
                    errs.push(format!("tls.key 不存在: {}", self.tls.key));
                } else {
                    tracing::warn!(
                        key = %self.tls.key,
                        "tls.key 不存在；tls.degrade = self-signed，启动时会退回自签证书"
                    );
                }
            }
            if !matches!(self.tls.min_version.as_str(), "1.2" | "1.3") {
                errs.push("tls.min_version 只支持 1.2 / 1.3".to_string());
            }
            if self.tls.listen == self.server.listen || self.tls.listen == self.server.admin_listen {
                errs.push("tls.listen 不能和 server.listen / admin_listen 相同".to_string());
            }
        }

        if self.admin.enabled && self.admin.username.trim().is_empty() {
            errs.push("admin.enabled = true 时 admin.username 不能为空".to_string());
        }
        if self.admin.totp_enabled
            && !self.admin.totp_secret.is_empty()
            && decode_base32(&self.admin.totp_secret).is_none()
        {
            errs.push("admin.totp_secret 不是合法 Base32".to_string());
        }
        if self.admin.session_ttl_secs == 0 {
            errs.push("admin.session_ttl_secs 必须大于 0".to_string());
        }

        if self.waf.enabled {
            if self.waf.score_threshold == 0 {
                errs.push("waf.score_threshold 必须大于 0".to_string());
            }
            if self.waf.dos.enabled && self.waf.dos.conn_per_ip == 0 {
                errs.push("waf.dos.conn_per_ip 必须大于 0".to_string());
            }
            if self.waf.jwt.enabled && self.waf.jwt.allowed_algs.is_empty() {
                errs.push("waf.jwt.allowed_algs 不能为空（否则所有 JWT 都会被拒）".to_string());
            }
            if self.waf.frame.enabled
                && self.waf.frame.mode == FrameMode::AllowFrom
                && self.waf.frame.allow_from.is_empty()
            {
                errs.push("waf.frame.mode = allow-from 时 allow_from 不能为空".to_string());
            }
        }

        if self.metrics.top_n == 0 {
            errs.push("metrics.top_n 必须大于 0".to_string());
        }
        if !(240..=20_000).contains(&self.metrics.history_points) {
            errs.push("metrics.history_points 必须在 240~20000 之间".to_string());
        }

        let mut group_names = std::collections::HashSet::new();
        for (i, g) in self.backend_groups.iter().enumerate() {
            let tag = format!("backend_groups[{i}]({})", g.name);
            if g.name.trim().is_empty() {
                errs.push(format!("backend_groups[{i}]: name 不能为空"));
            } else if !group_names.insert(g.name.clone()) {
                errs.push(format!("{tag}: name 重复"));
            }
        }

        let mut backend_names = std::collections::HashSet::new();
        for (i, b) in self.backends.iter().enumerate() {
            let tag = format!("backends[{i}]({})", b.name);
            if b.name.trim().is_empty() {
                errs.push(format!("{tag}: name 不能为空"));
            } else if !backend_names.insert(b.name.clone()) {
                errs.push(format!("{tag}: name 重复"));
            }
            if let Err(e) = check_upstream(&b.url) {
                errs.push(format!("{tag}: url 非法: {e}"));
            }
            if b.weight == 0 {
                errs.push(format!("{tag}: weight 必须大于 0"));
            }
            if !b.group.is_empty() {
                let members = self
                    .backends
                    .iter()
                    .filter(|x| x.group == b.group && x.enabled)
                    .count();
                if members == 0 {
                    errs.push(format!("{tag}: 所在分组 '{}' 没有任何启用的成员", b.group));
                }
            }
        }

        let mut seen = std::collections::HashSet::new();
        for (i, r) in self.routes.iter().enumerate() {
            let tag = if r.name.is_empty() {
                format!("routes[{i}]")
            } else {
                format!("routes[{i}]({})", r.name)
            };
            if r.name.trim().is_empty() {
                errs.push(format!("{tag}: name 不能为空"));
            } else if !seen.insert(r.name.clone()) {
                errs.push(format!("{tag}: name 重复"));
            }
            if !r.path_prefix.starts_with('/') {
                errs.push(format!("{tag}: path_prefix 必须以 '/' 开头"));
            }
            if !r.backend_group.is_empty() {
                if !r.backend.is_empty() {
                    errs.push(format!(
                        "{tag}: backend 与 backend_group 只能二选一（backend='{}', backend_group='{}'）",
                        r.backend, r.backend_group
                    ));
                }
                if !self.group_has_members(&r.backend_group) {
                    if self.find_group(&r.backend_group).is_some() {
                        errs.push(format!(
                            "{tag}: 分组 '{}' 已声明但没有后端成员；给 [[backends]] 加 group = \"{}\"",
                            r.backend_group, r.backend_group
                        ));
                    } else {
                        errs.push(format!(
                            "{tag}: 分组 '{}' 不存在；先添加后端并把 group 设为 '{}'",
                            r.backend_group, r.backend_group
                        ));
                    }
                }
            } else if !r.backend.is_empty() {
                let known_backend = self.find_backend(&r.backend);
                let known_group = self.find_group(&r.backend).is_some()
                    || self.group_has_members(&r.backend);
                match known_backend {
                    Some(b) if !b.enabled => errs.push(format!(
                        "{tag}: backend '{}' 已禁用；启用它，或把路由改成别的后端/分组",
                        r.backend
                    )),
                    Some(_) => {}
                    None if known_group => {}
                    None => errs.push(format!(
                        "{tag}: backend '{}' 既不是后端名也不是分组名（先添加后端，或改用 backend_group）",
                        r.backend
                    )),
                }
            } else if let Err(e) = check_upstream(&r.upstream) {
                errs.push(format!("{tag}: upstream 非法: {e}"));
            }
        }

        for (i, h) in self.header_rules.iter().enumerate() {
            if h.name.trim().is_empty() {
                errs.push(format!("header_rules[{i}]: name 不能为空"));
            } else if http::HeaderName::from_bytes(h.name.trim().as_bytes()).is_err() {
                errs.push(format!("header_rules[{i}]: name 不是合法 header 名: {}", h.name));
            }
            if h.action != HeaderAction::Remove && h.value.is_empty() {
                errs.push(format!("header_rules[{i}]: 该动作需要 value"));
            }
        }

        for k in self.error_pages.bodies.keys() {
            match k.parse::<u16>() {
                Ok(code) if (400..=599).contains(&code) => {}
                _ => errs.push(format!(
                    "error_pages.bodies 的键必须是 400~599 的状态码（TOML 里要加引号，如 \"502\"）：{k}"
                )),
            }
        }
        if self.error_pages.enabled && self.error_pages.content_type.trim().is_empty() {
            errs.push("error_pages.content_type 不能为空".to_string());
        }

        if self.server.listen == self.server.admin_listen {
            errs.push("server.listen 与 server.admin_listen 不能相同".to_string());
        }
        for (field, value) in [
            ("server.listen_v6", &self.server.listen_v6),
            ("server.admin_listen_v6", &self.server.admin_listen_v6),
            ("tls.listen_v6", &self.tls.listen_v6),
        ] {
            if value.trim().is_empty() {
                continue;
            }
            match value.parse::<SocketAddr>() {
                Ok(addr) if addr.is_ipv6() => {}
                Ok(_) => errs.push(format!("{field} 必须是 IPv6 地址（如 [::]:8080）")),
                Err(e) => errs.push(format!("{field} 非法: {e}")),
            }
        }
        // ---- 静态站点 ----
        let mut seen_site = std::collections::HashSet::new();
        for (i, site) in self.sites.iter().enumerate() {
            if site.hosts.is_empty() {
                errs.push(format!("sites[{i}] 没有绑定任何 hosts"));
            }
            if site.root.trim().is_empty() {
                errs.push(format!("sites[{i}] ({}) 缺少 root", site.display_name()));
            } else if !resolve_one(&site.root, base).exists() {
                errs.push(format!(
                    "sites[{i}] ({}) 的 root 不存在: {}",
                    site.display_name(),
                    site.root
                ));
            }
            if !seen_site.insert(site.display_name().to_string()) {
                errs.push(format!("sites[{i}] 站点名重复: {}", site.display_name()));
            }
            if site.index.is_empty() {
                errs.push(format!("sites[{i}] index 不能为空，至少写一个默认文档"));
            }
        }

        // ---- 动态项目 ----
        let mut seen_app = std::collections::HashSet::new();
        for (i, app) in self.apps.iter().enumerate() {
            if app.name.trim().is_empty() {
                errs.push(format!("apps[{i}] 缺少 name"));
            } else if !seen_app.insert(app.name.clone()) {
                errs.push(format!("apps[{i}] 名称重复: {}", app.name));
            }
            if app.port == 0 {
                errs.push(format!("apps[{i}] ({}) 缺少 port（应用在 127.0.0.1 上的监听端口）", app.name));
            }
            if app.hosts.is_empty() {
                errs.push(format!("apps[{i}] ({}) 没有绑定任何 hosts", app.name));
            }
            if !app.path_prefix.trim().is_empty() && !app.path_prefix.starts_with('/') {
                errs.push(format!("apps[{i}] ({}) path_prefix 必须以 / 开头", app.name));
            }
            if app.command.trim().is_empty() && app.entry.trim().is_empty() {
                errs.push(format!(
                    "apps[{i}] ({}) 既没有 command 也没有 entry，不知道该怎么启动",
                    app.name
                ));
            }
            if !app.cwd.trim().is_empty() && !resolve_one(&app.cwd, base).exists() {
                errs.push(format!("apps[{i}] ({}) 的 cwd 不存在: {}", app.name, app.cwd));
            }
        }

        // ---- 防火墙联动 ----
        if self.firewall.enabled {
            let b = self.firewall.backend.trim().to_ascii_lowercase();
            if !matches!(b.as_str(), "" | "auto" | "nft" | "iptables" | "ufw" | "none" | "off") {
                errs.push(format!("firewall.backend 不认识: {b}"));
            }
        }

        // ---- 自定义规则 ----
        let mut seen = std::collections::HashSet::new();
        for (i, r) in self.rules.iter().enumerate() {
            if r.name.trim().is_empty() {
                errs.push(format!("rules[{i}] 缺少 name"));
            } else if !seen.insert(r.name.clone()) {
                errs.push(format!("rules[{i}] 名称重复: {}", r.name));
            }
            if r.matches.is_empty() {
                // 没有条件的规则会命中所有请求，几乎肯定是配错了
                errs.push(format!(
                    "rules[{i}] ({}) 没有任何匹配条件，不会生效",
                    r.name
                ));
            }
            for (j, m) in r.matches.iter().enumerate() {
                // ALL 是"对所有请求成立"，本来就没有值可填。
                // 在这里放行，前端才不用为了通过校验给 all 编一个占位值。
                if m.kind == crate::rules::MatchKind::All {
                    continue;
                }
                if m.value.trim().is_empty() {
                    errs.push(format!("rules[{i}].matches[{j}] 的 value 为空"));
                }
                if matches!(
                    m.kind,
                    crate::rules::MatchKind::Header | crate::rules::MatchKind::Cookie
                ) && m.name.trim().is_empty()
                {
                    errs.push(format!("rules[{i}].matches[{j}] 需要填 header/cookie 名"));
                }
            }
            if let Some(rd) = &r.actions.redirect {
                if !matches!(rd.status, 301 | 302 | 303 | 307 | 308) {
                    errs.push(format!(
                        "rules[{i}] ({}) 重定向状态码只能是 301/302/303/307/308",
                        r.name
                    ));
                }
                if rd.to.trim().is_empty() {
                    errs.push(format!("rules[{i}] ({}) 重定向目标为空", r.name));
                }
            }
            if let Some(c) = &r.actions.custom_response {
                if !(100..=599).contains(&c.status) {
                    errs.push(format!("rules[{i}] ({}) 自定义响应状态码非法", r.name));
                }
            }
        }

        if self.server.heap_trim_secs > 3600 {
            errs.push("server.heap_trim_secs 必须在 0~3600 之间（0 = 关闭）".to_string());
        }

        if !(MIN_SAMPLE_MS..=MAX_SAMPLE_MS).contains(&self.metrics.sample_interval_ms) {
            errs.push(format!(
                "metrics.sample_interval_ms 必须在 {MIN_SAMPLE_MS}~{MAX_SAMPLE_MS} 之间（5 秒 ~ 10 分钟）"
            ));
        }

        errs
    }

    pub fn validate_ok_in(&self, base: &Path) -> Result<()> {
        let errs = self.validate_in(base);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(errs.join("\n")))
        }
    }

    pub fn find_backend(&self, name: &str) -> Option<&BackendConfig> {
        self.backends.iter().find(|b| b.name == name)
    }

    pub fn find_group(&self, name: &str) -> Option<&BackendGroupConfig> {
        self.backend_groups.iter().find(|g| g.name == name)
    }

    /// 路由实际指向。判断顺序：backend_group > `group:` 前缀 > 后端名 > 分组名。
    ///
    /// 名字冲突时后端名优先——后端是实体，分组是集合，让人更容易预期的那个赢。
    pub fn route_target<'a>(&'a self, route: &'a RouteConfig) -> Option<TargetSpec<'a>> {
        if !route.backend_group.is_empty() {
            return Some(TargetSpec::Group(&route.backend_group));
        }
        if route.backend.is_empty() {
            return None;
        }
        if let Some(g) = route.backend.strip_prefix("group:") {
            return Some(TargetSpec::Group(g));
        }
        if self.backends.iter().any(|b| b.name == route.backend) {
            return Some(TargetSpec::Single(&route.backend));
        }
        if self.find_group(&route.backend).is_some()
            || self.backends.iter().any(|b| b.group == route.backend)
        {
            return Some(TargetSpec::Group(&route.backend));
        }
        // 不存在的名字：交给校验报错，这里按单后端处理避免 panic
        Some(TargetSpec::Single(&route.backend))
    }

    /// 策略优先级：路由 > 分组 > 全局。
    pub fn resolve_lb(&self, route: Option<&RouteConfig>, group: Option<&str>) -> LbStrategy {
        if let Some(lb) = route.and_then(|r| r.lb) {
            return lb;
        }
        if let Some(name) = group {
            if let Some(st) = self.find_group(name).and_then(|g| g.strategy) {
                return st;
            }
        }
        self.server.lb
    }

    /// 该路由是否允许缓存（跟随全局）。
    pub fn cache_allowed(&self, route: Option<&RouteConfig>) -> bool {
        match route.and_then(|r| r.cache) {
            Some(v) => v && self.cache.enabled,
            None => self.cache.enabled,
        }
    }
}

/// 单条路径解析：`~` 展开 + 相对路径按 base 走。
pub fn resolve_one(raw: &str, base: &Path) -> PathBuf {
    let raw = raw.trim();
    let expanded = if raw == "~" {
        home_dir()
    } else if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        home_dir().join(rest)
    } else {
        PathBuf::from(raw)
    };
    if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn check_upstream(raw: &str) -> Result<()> {
    let uri: http::Uri = raw
        .parse()
        .map_err(|e| anyhow::anyhow!("URI 解析失败 ({raw}): {e}"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        Some(other) => return Err(anyhow::anyhow!("不支持的 scheme: {other}")),
        None => return Err(anyhow::anyhow!("缺少 scheme，例如 http://127.0.0.1:8081")),
    }
    if uri.authority().is_none() {
        return Err(anyhow::anyhow!("缺少 host，例如 http://127.0.0.1:8081"));
    }
    Ok(())
}

/// 默认配置路径：环境变量 OPTICAL_CONFIG > 当前目录 optical.toml
pub fn resolve_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Ok(p) = std::env::var("OPTICAL_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("optical.toml")
}

/// 启动参数覆盖（对应 `optical run --listen/--admin-listen/--upstream/...`）
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub listen: Option<String>,
    pub admin_listen: Option<String>,
    pub upstream: Option<String>,
    pub timeout_ms: Option<u64>,
    pub log_level: Option<String>,
}

impl Overrides {
    pub fn apply(&self, cfg: &mut Config) {
        if let Some(v) = &self.listen {
            cfg.server.listen = v.clone();
        }
        if let Some(v) = &self.admin_listen {
            cfg.server.admin_listen = v.clone();
        }
        if let Some(v) = &self.upstream {
            cfg.server.default_upstream = v.clone();
        }
        if let Some(v) = self.timeout_ms {
            cfg.server.request_timeout_ms = v;
        }
        if let Some(v) = &self.log_level {
            cfg.server.log_level = v.clone();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.listen.is_none()
            && self.admin_listen.is_none()
            && self.upstream.is_none()
            && self.timeout_ms.is_none()
            && self.log_level.is_none()
    }

    /// 解除"行为类"覆盖（上游/超时/日志）。
    /// 监听地址不在此列：端口已经 bind 了，本次进程内无法再改，只能重启。
    pub fn clear_behavior(&mut self) {
        self.upstream = None;
        self.timeout_ms = None;
        self.log_level = None;
    }

    pub fn keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        if self.listen.is_some() {
            keys.push("listen");
        }
        if self.admin_listen.is_some() {
            keys.push("admin_listen");
        }
        if self.upstream.is_some() {
            keys.push("default_upstream");
        }
        if self.timeout_ms.is_some() {
            keys.push("request_timeout_ms");
        }
        if self.log_level.is_some() {
            keys.push("log_level");
        }
        keys
    }
}

/// Base32 解码（TOTP 密钥用），无依赖实现。
pub fn decode_base32(s: &str) -> Option<Vec<u8>> {
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.chars() {
        let up = c.to_ascii_uppercase();
        let v = match up {
            'A'..='Z' => up as u32 - 'A' as u32,
            '2'..='7' => up as u32 - '2' as u32 + 26,
            '=' | ' ' | '-' => continue,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn encode_base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for b in data {
        buf = (buf << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = Config::default();
        let errs = cfg.validate();
        assert!(errs.is_empty(), "{errs:?}");
    }

    #[test]
    fn parsing_the_example_config_is_cheap() {
        // 把"TOML 解析到底慢不慢"变成一条会红的断言，而不是靠感觉。
        // 例子里所有字段都写满，比真实配置更大；200 次取平均。
        let text = include_str!("../config.example.toml");
        let t0 = std::time::Instant::now();
        for _ in 0..200 {
            let c: Config = toml::from_str(text).expect("示例配置必须能解析");
            std::hint::black_box(&c);
        }
        let each = t0.elapsed() / 200;
        println!("TOML 解析单次耗时: {each:?}（{} 字节）", text.len());
        assert!(
            each < std::time::Duration::from_millis(20),
            "单次解析超过 20ms 就该考虑缓存了，实测 {each:?}"
        );
    }

    #[test]
    fn missing_cert_path_is_not_fatal_unless_strict() {
        // 线上踩过的坑：证书路径写错 → 配置校验直接拒启动 → 443 整个消失 →
        // 前面挂着 CDN，用户看到的就是一个没有上下文的 502。
        let mut cfg = Config::default();
        cfg.tls.enabled = true;
        cfg.tls.cert = "/nonexistent/cert.pem".into();
        cfg.tls.key = "/nonexistent/key.pem".into();
        cfg.tls.degrade = "self-signed".into();
        let errs = cfg.validate();
        assert!(
            !errs.iter().any(|e| e.contains("tls.cert") || e.contains("tls.key")),
            "默认模式不该因为证书文件缺失而拒绝启动: {errs:?}"
        );

        cfg.tls.degrade = "strict".into();
        let errs = cfg.validate();
        assert!(
            errs.iter().any(|e| e.contains("tls.cert")),
            "strict 模式必须明确报错: {errs:?}"
        );
    }

    #[test]
    fn rejects_bad_listen_and_upstream() {
        let mut cfg = Config::default();
        cfg.server.listen = "8080".into();
        cfg.server.default_upstream = "127.0.0.1:8081".into();
        let errs = cfg.validate();
        assert_eq!(errs.len(), 2, "{errs:?}");
    }

    #[test]
    fn duplicate_route_names_rejected() {
        let mut cfg = Config::default();
        cfg.routes.push(RouteConfig::new("a", "*", "/a", "http://127.0.0.1:1"));
        cfg.routes.push(RouteConfig::new("a", "*", "/b", "http://127.0.0.1:2"));
        assert!(cfg.validate().iter().any(|e| e.contains("重复")));
    }

    #[test]
    fn route_must_reference_existing_backend() {
        let mut cfg = Config::default();
        let mut r = RouteConfig::new("a", "*", "/a", "");
        r.backend = "nope".into();
        cfg.routes.push(r);
        assert!(cfg
            .validate()
            .iter()
            .any(|e| e.contains("backend 'nope'")));
    }

    #[test]
    fn header_rule_requires_value() {
        let mut cfg = Config::default();
        cfg.header_rules.push(HeaderRule {
            name: "X-Frame-Options".into(),
            ..Default::default()
        });
        assert!(cfg.validate().iter().any(|e| e.contains("需要 value")));
    }

    #[test]
    fn toml_roundtrip() {
        let mut cfg = demo_config();
        cfg.routes.push(RouteConfig::new("api", "*", "/api", "http://127.0.0.1:8082"));
        cfg.backends.push(BackendConfig::new("app", "http://127.0.0.1:8081"));
        cfg.header_rules.push(HeaderRule {
            name: "X-Frame-Options".into(),
            value: "DENY".into(),
            ..Default::default()
        });
        let text = cfg.to_toml();
        let back: Config = toml::from_str(&text).expect("roundtrip");
        assert_eq!(back.routes.len(), 1);
        assert_eq!(back.backends.len(), 1);
        assert_eq!(back.header_rules.len(), 1);
        assert!(back.waf.enabled);
        assert_eq!(back.server.listen, DEFAULT_LISTEN);
    }

    #[test]
    fn app_routes_are_memory_only_and_survive_a_roundtrip() {
        let mut c = Config::default();
        c.apps.push(crate::apps::AppConfig {
            name: "demo".into(),
            port: 18100,
            hosts: vec!["a.example.com".into()],
            path_prefix: "/demo".into(),
            command: "python3 app.py".into(),
            ..Default::default()
        });
        c.expand_apps();
        assert!(c.routes.iter().any(|r| r.synthetic), "内存里应该有合成路由");

        // 序列化必须滤掉合成路由：否则会被写进配置文件，下一次展开就重名
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("app:demo"), "合成路由不该出现在 JSON 里: {json}");
        let toml_text = c.to_toml();
        assert!(!toml_text.contains("app:demo"), "合成路由不该写进 TOML");

        // 反序列化后再展开，仍然只有一条，且不报重名
        let mut back: Config = serde_json::from_str(&json).unwrap();
        back.expand_apps();
        let n = back.routes.iter().filter(|r| r.name == "app:demo").count();
        assert_eq!(n, 1, "重复展开不该产生两条同名路由");
        assert!(back.validate().is_empty(), "{:?}", back.validate());
    }

    #[test]
    fn stale_synthetic_route_in_file_is_dropped_on_expand() {
        // 上一版把合成路由写进了配置文件：加载时必须清掉，否则和本次展开重名
        let mut c = Config::default();
        c.apps.push(crate::apps::AppConfig {
            name: "demo".into(),
            port: 18100,
            command: "x".into(),
            ..Default::default()
        });
        c.routes.push(RouteConfig {
            name: "app:demo".into(),
            host: "a.example.com".into(),
            path_prefix: "/demo".into(),
            upstream: "http://127.0.0.1:18100".into(),
            ..Default::default()
        });
        c.expand_apps();
        assert_eq!(
            c.routes.iter().filter(|r| r.name == "app:demo").count(),
            1,
            "文件里的历史合成路由应被清掉"
        );
    }

    #[test]
    fn metrics_bounds_reject_junk_intervals() {
        let mut cfg = Config::default();
        cfg.metrics.sample_interval_ms = 1;
        assert!(
            cfg.validate().iter().any(|e| e.contains("sample_interval_ms")),
            "1ms 的采集间隔必须被拒"
        );

        cfg.metrics.sample_interval_ms = MIN_SAMPLE_MS;
        cfg.metrics.history_points = 10;
        assert!(
            cfg.validate().iter().any(|e| e.contains("history_points")),
            "点数上限太小的配置必须被拒"
        );

        cfg.metrics.history_points = 2880;
        assert!(cfg.validate().is_empty(), "默认值必须是合法配置");
    }

    #[test]
    fn route_defaults_are_semantic_not_zero() {
        // 只写 backend 时，host/prefix/rewrite_host 必须拿语义默认值
        let cfg: Config = toml::from_str(
            r#"
            [[backends]]
            name = "app"
            url = "http://127.0.0.1:8081"

            [[routes]]
            name = "r"
            backend = "app"
            "#,
        )
        .expect("parse");
        let r = &cfg.routes[0];
        assert_eq!(r.host, "*");
        assert_eq!(r.path_prefix, "/");
        assert!(r.rewrite_host, "rewrite_host 必须默认为 true");
        assert!(!r.strip_prefix);
    }

    #[test]
    fn base32_roundtrip() {
        let raw = b"Hello, Optical TOTP secret!";
        let enc = encode_base32(raw);
        let dec = decode_base32(&enc).unwrap();
        assert_eq!(&dec[..], &raw[..]);
    }
}
