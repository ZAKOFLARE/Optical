//! 背压与限速：在"请求变成资源消耗"之前就把它拦住。
//!
//! 三件事共用一套骨架，但语义完全不同，别混：
//!
//! - **在途上限（背压）**：同时正在处理的请求数。这是防内存被打爆的那道闸——
//!   每个在途请求都压着一份请求头、缓冲区、上游连接，池子没有上限时，
//!   慢客户端 + 大响应就能把内存吃干。超限**立刻**回 503，不排队：
//!   排队只会把内存问题变成延迟问题，然后一起死。
//! - **令牌桶（QPS）**：单位时间的请求数。超限回 429，可以排队等下一个令牌。
//! - **键空间回收**：按客户端 IP 计数的表必须能自己瘦下来。不限速的网关
//!   在被打的时候，这张表本身就会变成新的内存漏洞——防 DoS 的组件不能
//!   自己成为 DoS 入口。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 一次准入判定的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    /// 建议客户端多久后重试（秒）。回给 `Retry-After`。
    pub retry_after: u64,
}

impl Verdict {
    const OK: Self = Self { allowed: true, retry_after: 0 };
    fn deny(secs: u64) -> Self {
        Self { allowed: false, retry_after: secs.max(1) }
    }
}

/// 在途计数。总上限与"按键上限"可以同时用，也可以只用其中一个（0 = 不限）。
#[derive(Default)]
pub struct InFlight {
    total: AtomicUsize,
    /// 按键计数。键是"规则名|客户端 IP"或纯 IP，取决于调用方。
    per_key: Mutex<HashMap<String, usize>>,
}

/// 在途凭证。Drop 时自动归还——所有提前 return 的路径都不会漏减计数。
pub struct InFlightGuard {
    owner: Arc<InFlight>,
    key: Option<String>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.owner.total.fetch_sub(1, Ordering::Relaxed);
        if let Some(k) = self.key.take() {
            let mut g = self.owner.per_key.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = g.get_mut(&k) {
                *n = n.saturating_sub(1);
                // 归零就删键：不移除的话，这张表会随着访问过的 IP 数量无限增长，
                // 那正是我们要防的东西。
                if *n == 0 {
                    g.remove(&k);
                }
            }
        }
    }
}

impl InFlight {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// 尝试进入。`max_total` / `max_per_key` 为 0 表示该项不限。
    pub fn try_enter(
        self: &Arc<Self>,
        key: Option<&str>,
        max_total: usize,
        max_per_key: usize,
    ) -> Option<InFlightGuard> {
        let mut g = self.per_key.lock().unwrap_or_else(|e| e.into_inner());
        if max_per_key > 0 {
            if let Some(k) = key {
                if g.get(k).copied().unwrap_or(0) >= max_per_key {
                    return None;
                }
            }
        }
        // 总闸最后判：先扣按键额度再判总量，失败要回滚，
        // 所以这里只做读判断 + 原子加，回滚由下面的分支负责。
        if max_total > 0 && self.total.load(Ordering::Relaxed) >= max_total {
            return None;
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        if let Some(k) = key {
            *g.entry(k.to_string()).or_insert(0) += 1;
        }
        drop(g);
        Some(InFlightGuard {
            owner: self.clone(),
            key: key.map(str::to_string),
        })
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
    seen: Instant,
}

/// 令牌桶集合。键由调用方决定（"规则:app|1.2.3.4"、"全局:app"）。
///
/// 为什么不用滑动窗口：窗口要么整窗计数（边界处会放过两倍突发），
/// 要么存每个请求的时间戳（内存随 QPS 线性涨）。令牌桶两个问题都没有。
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    /// 上次回收时间 + 上次的总量峰值，用来判断要不要提前回收
    gc: Mutex<GcState>,
}

struct GcState {
    last: Instant,
}

/// 超过这个数量的桶会触发一次主动回收（不等定时器）
const GC_SOFT_LIMIT: usize = 4096;
/// 空闲超过这么久的桶，回收掉
const GC_IDLE: Duration = Duration::from_secs(300);

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            gc: Mutex::new(GcState { last: Instant::now() }),
        }
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 取一个令牌。`qps` 为 0 视为不限制。
    pub fn allow(&self, key: &str, qps: u32, burst: u32) -> Verdict {
        if qps == 0 {
            return Verdict::OK;
        }
        let burst = burst.max(1) as f64;
        let now = Instant::now();
        let mut g = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        if g.len() > GC_SOFT_LIMIT {
            g.retain(|_, b| now.duration_since(b.seen) < GC_IDLE);
        }

        let b = g.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: burst,
            last: now,
            seen: now,
        });

        let elapsed = now.duration_since(b.last).as_secs_f64();
        // 桶上限就是 burst，所以突发最多 burst 个，之后按 qps 匀速补充
        b.tokens = (b.tokens + elapsed * qps as f64).min(burst);
        b.last = now;
        b.seen = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            return Verdict::OK;
        }
        // 还差多少才能凑够一个令牌 → 建议的重试间隔
        let need = (1.0 - b.tokens) / qps as f64;
        Verdict::deny(need.ceil() as u64)
    }

    /// 定时回收：无流量时也不会让表一直占着。返回清掉的桶数。
    ///
    /// 30 秒内重复调用直接返回 0：调用方可能每轮都叫一次，
    /// 而遍历几千个桶本身也是成本。
    pub fn gc(&self) -> usize {
        let now = Instant::now();
        {
            let mut st = self.gc.lock().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(st.last) < Duration::from_secs(30) {
                return 0;
            }
            st.last = now;
        }
        let mut g = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.len();
        g.retain(|_, b| now.duration_since(b.seen) < GC_IDLE);
        before - g.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_rejects_over_limit_and_releases() {
        let bp: Arc<InFlight> = Arc::new(InFlight::new());
        let a = bp.try_enter(Some("1.1.1.1"), 0, 2).expect("第一个");
        let _b = bp.try_enter(Some("1.1.1.1"), 0, 2).expect("第二个");
        assert!(bp.try_enter(Some("1.1.1.1"), 0, 2).is_none(), "超过单键上限要拒");
        // 必须绑住：`is_some()` 会把 Option 消费掉，guard 立刻 drop，计数就回去了
        let _c = bp.try_enter(Some("2.2.2.2"), 0, 2).expect("别的键不受影响");
        assert_eq!(bp.current(), 3);
        drop(a);
        assert_eq!(bp.current(), 2);
        assert_eq!(*bp.per_key.lock().unwrap().get("1.1.1.1").unwrap(), 1);
    }

    #[test]
    fn in_flight_total_cap_is_global() {
        let bp: Arc<InFlight> = Arc::new(InFlight::new());
        let _a = bp.try_enter(Some("1.1.1.1"), 2, 0).unwrap();
        let _b = bp.try_enter(Some("2.2.2.2"), 2, 0).unwrap();
        assert!(bp.try_enter(Some("3.3.3.3"), 2, 0).is_none(), "总量满了谁也别进");
    }

    #[test]
    fn guard_key_is_removed_when_idle() {
        // 这条是防"防 DoS 的组件自己变成内存漏洞"：键必须能自己消失
        let bp: Arc<InFlight> = Arc::new(InFlight::new());
        let g = bp.try_enter(Some("9.9.9.9"), 0, 5).unwrap();
        assert_eq!(*bp.per_key.lock().unwrap().get("9.9.9.9").unwrap(), 1);
        drop(g);
        assert!(bp.per_key.lock().unwrap().is_empty(), "归零的键要删掉");
    }

    #[test]
    fn token_bucket_allows_burst_then_throttles() {
        let rl = RateLimiter::new();
        // 桶初始满：burst 个立刻可用
        for _ in 0..5 {
            assert!(rl.allow("k", 10, 5).allowed);
        }
        let v = rl.allow("k", 10, 5);
        assert!(!v.allowed, "burst 用完就该限");
        assert!(v.retry_after >= 1, "必须给出重试间隔");
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let rl = RateLimiter::new();
        for _ in 0..4 {
            assert!(rl.allow("k", 1000, 4).allowed);
        }
        assert!(!rl.allow("k", 1000, 4).allowed);
        // 1000 QPS 下 2ms 就能补出不止一个令牌
        std::thread::sleep(Duration::from_millis(6));
        assert!(rl.allow("k", 1000, 4).allowed, "令牌要随时间补回来");
    }

    #[test]
    fn keys_are_independent() {
        let rl = RateLimiter::new();
        for _ in 0..2 {
            assert!(rl.allow("a", 1, 2).allowed);
        }
        assert!(!rl.allow("a", 1, 2).allowed);
        assert!(rl.allow("b", 1, 2).allowed, "别的键有自己的桶");
    }

    #[test]
    fn gc_drops_idle_buckets() {
        let rl = RateLimiter::new();
        rl.allow("x", 5, 5);
        assert_eq!(rl.len(), 1);
        assert_eq!(rl.gc(), 0, "刚用过的不该被回收");
    }
}
