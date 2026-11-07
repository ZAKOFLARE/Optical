# Optical —— 跨平台网关（转发 / 路由 / WAF / TLS）

Rust 写的单进程网关：HTTP 转发与路由、命名后端池、响应缓存、九类 WAF 规则族、
TLS 1.2/1.3、WebSocket 隧道、gRPC 透传，配 CLI + WebUI 双操作面（中英双语、明暗主题）。

设计底线只有一条：**配置里出现的开关必须真的生效**，不做"选项在、逻辑是空壳"的东西。

---

## 能力矩阵

| # | 需求 | 实现方式 | 状态 |
| --- | --- | --- | --- |
| 1 | 运行概览（UA/IP/带宽/缓存命中率/规则命中率） | 每秒采样 + Top-N 计数 + 4 组图表 | ✅ 真数据 |
| 2 | 常规 DoS WAF | header/cookie/URL/body 体积闸门、**cookie 压缩比（真解压，64 KiB 上限）**、单 IP 并发与每秒新建连接双限 | ✅ |
| 3 | 常规 XML WAF | DOCTYPE / 外部实体 / XInclude / 嵌套深度 / 实体引用炸弹 | ✅ |
| 4 | 帧限制 | `X-Frame-Options` + CSP `frame-ancestors`（deny / sameorigin / allow-from） | ✅ |
| 5 | JWT WAF | alg=none、算法白名单、kid 注入、过期、超长 | ✅ |
| 6 | SQL WAF | 关键字/注释/联合查询/时间盲注/文件读写评分 | ✅ |
| 7 | SSRF WAF | 参数名匹配 + 内网/回环/元数据地址 + 危险协议 | ✅ |
| 8 | BOLA WAF | 同身份窗口内对象 ID 遍历计数 | ✅ |
| 9 | 路径穿越 / 未授权重路由 | `../`、二次编码、敏感文件、开放重定向参数 | ✅ |
| 10 | 缓存欺骗 | 动态路径伪装静态扩展名、路径段堆叠 | ✅ |
| 11 | 参数污染 (HPP) | 同名参数多值检测 + 参数总数上限 | ✅ |
| 12 | WebUI 认证 + TOTP 2FA | argon2id 口令、RFC 6238 TOTP（**摘要可配 sha1/sha256/sha512**）、内存会话、登录限速 | ✅ |
| 13 | 配置回溯 | 每次落盘存快照（毫秒级 ID），三重配额裁剪，一键回滚 | ✅ |
| 14 | 头改写 | 请求/响应两阶段，set/add/remove + 路径/Host/状态码条件 | ✅ |
| 15 | QUIC | 需要 h3 协议栈（quinn + h3 + TLS 会话票据） | ⛔ 未实现 |
| 16 | gRPC | h2 入站走 h2 出站，保留 `te: trailers` 与流式 body | ✅ 透传 |
| 17 | WS | http1 手工握手 + 双向字节隧道 | ✅ 透传 |
| 18 | TLS 1.2/1.3 | rustls 终止，可强制 1.3，无证书时自动生成自签 | ✅ |
| 19 | 后端服务管理 | 命名后端 + **分组 + 备注 + 负载均衡（wrr / rr / iphash / random）**、主动探活、路由可引用 | ✅ |
| 20 | 中英双语 + 明暗切换 | 无 CDN 依赖（全部内嵌/自托管），localStorage 记忆 | ✅ |
| 21 | 自定义错误页 | 目录 `<status>.html` → 内联模板 → 内置模板；占位符替换；`no-store` 防 CDN 缓存 5xx | ✅ |
| 22 | 非固化路径 | `[paths]` 统一解析 data/history/audit/tls/error-pages；相对路径按 data_dir，`~/` 展开 | ✅ |
| 23 | 响应 Server 头 | `server.server_header`：非空统一覆盖（含转发响应），空串删除该头，不泄露上游版本 | ✅ |

> **关于 QUIC**：它不是"加个监听器"就完事的。HTTP/3 需要 h3 帧层 + QUIC 传输 + TLS 会话票据一整套，
> 而且必须先把 TLS 栈跑稳。本轮把 TLS/WS/gRPC 三层落地了，QUIC 留作独立里程碑——
> 与其塞一个跑不起来的 `enabled=true`，不如明说没做。

---

## 项目结构

```
optical/
├── Cargo.toml
├── config.example.toml          全量配置样例（每项都带注释）
├── scripts/smoke.sh             60 项端到端断言
└── src/
    ├── main.rs                  入口
    ├── cli.rs / commands.rs     clap 命令与实现（run / config / route / passwd / status / upstream-echo）
    ├── config.rs                TOML 模型 + 校验 + 原子写盘 + 启动覆盖语义
    ├── state.rs                 共享状态：指标 / 采样 / 连接池 / 缓存 / 后端 / 认证 / 存储
    ├── route.rs                 路由匹配 + 上游选择策略
    ├── proxy.rs                 转发核心（WAF → 缓存 → 路由 → 头改写 → 上游 → 计量）
    ├── waf.rs                   九族规则引擎（评分制）
    ├── cache.rs                 响应缓存（TTL + 字节/条数双限额 LRU）
    ├── backends.rs              后端池 + 分组选路 + 四种负载均衡 + 主动探活
    ├── errors.rs                自定义错误页（文件 / 内联 / 内置三级回退）
    ├── auth.rs                  argon2id + TOTP（可配摘要）+ 会话 + 限速
    ├── storage.rs               配置快照 + 审计日志（三重配额）
    ├── tls.rs                   rustls 终止 + 自签证书生成
    ├── admin.rs                 管理面 REST + 认证中间件
    ├── echo.rs                  演示上游（含 /ws 升级端点）
    └── webui/index.html         单页控制台（7 个标签页，内嵌）
```

---

## 构建

```bash
cargo build --release          # 产物 target/release/optical
cargo test                     # 63 个单元测试
```

交叉编译（在 Linux 构建机上实测通过）：

```bash
rustup target add x86_64-pc-windows-gnu x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl   # 静态链接，扔到任何发行版都能跑
cargo build --release --target x86_64-pc-windows-gnu       # 需要 mingw-w64
```

> macOS（`aarch64-apple-darwin`）在 Linux 上**过不了**：TLS 后端 ring 需要为目标平台
> 编译 C/asm，必须有 macOS SDK + 对应 clang。这是所有带 TLS 的 Rust 项目共同的限制，
> 在 mac 上或在 CI 里用 macOS runner 构建即可，不是代码问题。
> 已验证：`x86_64-unknown-linux-gnu`（本机）、`x86_64-unknown-linux-musl`、`x86_64-pc-windows-gnu`。

---

## 启动

```bash
# 首次运行会生成配置并打印随机管理面口令（只打印一次）
./target/release/optical run

# 覆盖关键参数（只影响本次进程，不写回文件）
./target/release/optical run \
  --listen 0.0.0.0:8080 --admin-listen 127.0.0.1:9100 \
  --upstream http://127.0.0.1:8081 --timeout-ms 15000 --log-level debug
```

启动横幅会打印：网关/HTTPS/管理面地址、后端数、WAF 状态、配置路径、管理面认证状态。

### 启动覆盖 vs 文件值（四条规则）

1. 启动参数只影响本次进程的生效值，**永不写回文件**。
2. 文件被外部改动后重新加载，覆盖继续生效（否则 `--upstream` 会被一次无关热重载悄悄顶掉）。
3. 管理面显式提交视作"用户此刻的明确意图"，解除上游/超时/日志三类覆盖；
   监听地址已 bind，只能重启换端口，因此永远以实际绑定为准。
4. WebUI 保存时界面上看到什么就写什么（包括被锁定字段显示的生效值）。

被覆盖的字段在 WebUI 里会禁用并标注，`GET /api/status` 的 `overrides` 列出当前锁定项。

---

## CLI

```bash
optical run [--listen --admin-listen --upstream --timeout-ms --log-level]
optical config show | path | init [--force] | validate | set <key> <value>
optical route list | add [--backend NAME | --backend-group GROUP] | remove
optical passwd <明文口令> [--write]      # 生成 argon2 哈希；--write 直接写进配置
optical status [--json] [--admin ADDR]
optical upstream-echo --listen 127.0.0.1:8081
```

`status` 通过进程启动时写下的本地令牌（配置同目录、0600、退出即删）访问管理面，
不靠"回环免登录"这种口子。

`config set` 支持 `listen / admin-listen / default-upstream / timeout-ms / log-level / waf-mode`。

---

## WAF 语义

**评分制**：每个命中项带 severity（1~5），累计值 ≥ `waf.score_threshold`（默认 4）才处置。

- 4~5 分是"单条即可拦"的高置信信号：SQL 联合查询、开放重定向、缓存欺骗、HPP、外部实体、alg=none。
- 1~3 分是弱信号：空 UA、URL 超长、注释符，需要叠加才触发。
- `mode = "monitor"` 时只记录不拦，用于上线前的灰度验证。

**body 检查窗口**：只有 `Content-Length` 存在且 ≤ `server.max_inspect_bytes`（默认 8192）时才缓冲检查；
chunked 或超限请求直接跳过并计入 `waf_skipped`。
理由——把大文件上传整体缓冲进内存是网关自杀行为，宁可漏检也不做。

**cookie 压缩比**：cookie 值若是 base64 编码的 gzip/zlib，会用 `flate2` 真解压（**上限 64 KiB**），
解压比低于 `cookie_compression_ratio` 判定为压缩炸弹。解压有硬上限，不会被炸弹反噬。

---

## 管理面认证

- 口令用 **argon2** 哈希，明文只在登录请求里出现一次，不落盘。
- `totp_enabled = true` 时要求 6 位动态码（RFC 6238，30s，窗口 ±1）。
  `totp_algorithm` 可选 `sha1`（默认）/`sha256`/`sha512`，otpauth URI 会同步算法。
  WebUI「安全」页可一键生成 Base32 密钥与 URI。
- **关于 SHA1**：这里只为兼容验证器（RFC 6238 默认就是 HMAC-SHA1）。口令存储是 argon2id，
  会话令牌是 256 位 CSPRNG；代码里另一个 SHA1 是 WebSocket 握手的 `Sec-WebSocket-Accept`，
  由 RFC 6455 强制，且它只是握手校验和，不承担任何安全强度。
- 会话是**内存态**：进程重启全部失效。对网关管理面来说这是特性，不是缺陷。
- 登录失败按 `username@ip` 计数，超过 `max_failed_attempts` 在窗口期内直接 429。
- `admin.enabled = false` 时完全放行——只建议本机调试用。

---

## 后端与缓存

**后端池**：`[[backends]]` 定义命名上游（url / group / note / weight / health_path / interval），
`[[backend_groups]]` 给分组写备注与策略，路由用 `backend = "app-1"` 或 `backend_group = "app"` 引用。

**选路规则（硬约束）**：
- 单后端目标只会在那个后端里挑，**不会**因为别的后端健康就分过去；
- 分组目标只在本组成员里挑，绝不跨组；
- 组内全不健康时才降级为"组内按权重赌一把"并打 warn，不会去借别的组；
- 策略优先级：路由 `lb` > 分组 `strategy` > 全局 `server.lb`；
- 支持 `wrr / rr / iphash / random`。**不做 least-conn**——它要求把在飞请求数挂到响应体生命周期上，
  做不到就会系统性算错长连接，宁缺毋滥。

响应头 `x-optical-backend` 和 `x-optical-lb` 直接给出本次实际后端与策略，排查不用猜。

**缓存**：GET/HEAD + 可缓存扩展名 + 可缓存状态码才进缓存，TTL 过期，字节/条数双限额 LRU 淘汰。
缓存键含 host/path/query/accept-encoding，避免压缩内容串味。响应头 `x-optical-cache: HIT|MISS|BYPASS`
可现场验证。只有 ≤ `max_bytes/4` 的响应才缓存（超过就流式直传，不为了缓存牺牲转发）。

---

## WebUI

`http://<admin_listen>/`，7 个标签页：

| 页 | 内容 |
| --- | --- |
| 概览 | 8 格 KPI（请求/带宽入出/缓存命中率/规则命中率/时长/TLS/路由后端/上游）+ 4 组图表（请求、带宽、缓存、拦截，**带 Y 轴刻度、时间轴、十字准线与悬浮读数**）+ Top UA / Top IP / Top 规则 |
| 路由 | 行内编辑（输入框平时无边框）、backend 下拉引用、筛选、整表保存 |
| WAF | 总开关 + 模式 + 阈值 + 检查上限；10 个规则族卡片（每族独立开关与参数）；头改写表 |
| 后端 | 分组（备注 + 策略 + 实时成员健康）、后端 CRUD、状态徽标；轮询只更新徽标，不打断编辑与选区 |
| 配置 | 服务/传输、存储配额+路径、自定义错误页、原始 TOML |
| WAF | 每个字段带 `?` 解析提示（悬停显示），每个规则族有一句功能说明 |
| 历史 | 配置快照（回滚/删除）+ 审计日志 |
| 安全 | 认证开关、改口令、TOTP 生成与启用、会话数 |

顶栏：连接状态、中/EN、明/暗、热重载、退出。全部资源内嵌，**不依赖任何 CDN**。

---

## 验证

```bash
cargo build --release && ./scripts/smoke.sh
```

覆盖 60 项断言：认证（401/错误口令/登录/会话）、转发与路由、后端探活、
**分组内双后端轮询且不跨组、单后端路由不串成员**、自定义 502 错误页（占位符 + footer + no-store）、
**data_dir 迁移后 status 反映实际路径**、缓存命中、九个 WAF 族各一发、413 体积闸门、
帧限制头、自定义头改写、**转发与错误页都带统一 Server 头**、WS 101、TLS 握手与版本、
配置快照与回滚、审计日志、Top 指标、CLI status。

---

## 明确没用/没做

| 项 | 原因 |
| --- | --- |
| QUIC / HTTP3 | 需 h3 协议栈，独立里程碑（见上） |
| 上游 TLS | 上游只走明文 http；接 https 上游需要另一套连接器 |
| least-conn 负载均衡 | 需要准确的在飞请求计数（挂在响应体生命周期上），近似值会误导扩缩容 |
| 上游 5xx 替换成自定义页 | 自定义错误页目前只用于网关本地生成的错误；改上游响应要缓冲 body，与流式转发冲突 |
| header 级 body 检查 | 大 body 只流式透传不检查，是刻意的性能取舍 |
| 分布式会话 | 单机内存会话；多实例需 Redis 或共享令牌 |
| 规则热更新 | 规则是编译进二进制的常量，改规则要重新构建（配置只能调阈值与开关） |
| 慢请求检测 | 未实现。原来的 `slow_request_ms` 是从不参与判断的空开关，已删除而不是留着装样子 |
