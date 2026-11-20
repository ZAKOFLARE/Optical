//! 响应缓存。
//!
//! 「缓存命中率」这个指标只有真缓存才算数，所以这里是个能用的实现：
//! GET/HEAD + 可缓存状态码 + 可缓存扩展名才进缓存，按 TTL 过期、按字节/条数双限额 LRU 淘汰。
//! 缓存键包含 host + path + query，避免 `?a=1` 和 `?a=2` 串味。

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

struct Entry {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    expires: Instant,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Entry>,
    /// 插入顺序，用于 LRU 淘汰
    order: VecDeque<String>,
    bytes: usize,
}

#[derive(Default)]
pub struct ResponseCache {
    inner: RwLock<Inner>,
    // 命中/未命中等计数器单独用原子：lookup 的读锁不用为计数升级成写锁
    hits: AtomicU64,
    misses: AtomicU64,
    stores: AtomicU64,
    evictions: AtomicU64,
}

/// 缓存写入策略（容量与 TTL 一起传，避免 store() 参数爆炸）
#[derive(Debug, Clone, Copy)]
pub struct CachePolicy {
    pub ttl: Duration,
    pub max_bytes: usize,
    pub max_entries: usize,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub bytes: usize,
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub evictions: u64,
    pub hit_rate: f64,
}

impl ResponseCache {
    pub fn key(method: &Method, host: Option<&str>, path: &str, query: Option<&str>) -> String {
        format!(
            "{}|{}|{}{}",
            method.as_str(),
            host.unwrap_or("-"),
            path,
            query.map(|q| format!("?{q}")).unwrap_or_default()
        )
    }

    pub fn lookup(&self, key: &str) -> Option<(StatusCode, HeaderMap, Bytes)> {
        // 快路径：读锁。命中未过期 / 完全未命中都只抢读锁，并发互不阻塞。
        {
            let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
            match g.map.get(key) {
                Some(e) if e.expires > Instant::now() => {
                    let out = (e.status, e.headers.clone(), e.body.clone());
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(out);
                }
                None => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                _ => {}
            }
        }
        // 慢路径：键存在但已过期，写锁清理。发生频率远低于命中/未命中。
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = g.map.remove(key) {
            g.bytes = g.bytes.saturating_sub(e.body.len());
            g.order.retain(|k| k != key);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn store(
        &self,
        key: String,
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        policy: CachePolicy,
    ) {
        let CachePolicy { ttl, max_bytes, max_entries } = policy;
        if body.is_empty() || body.len() > max_bytes / 4 {
            return;
        }
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if let Some(old) = g.map.remove(&key) {
            g.bytes = g.bytes.saturating_sub(old.body.len());
            g.order.retain(|k| k != &key);
        }
        g.bytes += body.len();
        g.map.insert(
            key.clone(),
            Entry {
                status,
                headers,
                body,
                expires: Instant::now() + ttl,
            },
        );
        g.order.push_back(key);
        self.stores.fetch_add(1, Ordering::Relaxed);

        while (g.bytes > max_bytes || g.map.len() > max_entries) && g.map.len() > 1 {
            let Some(victim) = g.order.pop_front() else { break };
            if let Some(e) = g.map.remove(&victim) {
                g.bytes = g.bytes.saturating_sub(e.body.len());
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn stats(&self) -> CacheStats {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        CacheStats {
            entries: g.map.len(),
            bytes: g.bytes,
            hits,
            misses,
            stores: self.stores.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            hit_rate: if total == 0 { 0.0 } else { hits as f64 / total as f64 * 100.0 },
        }
    }

    /// 全清。手动"清空缓存"用这个。
    pub fn purge(&self) {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        g.map.clear();
        g.order.clear();
        g.bytes = 0;
    }

    /// 只清已经过期的条目。
    ///
    /// 以前过期条目只在 lookup 命中同一个键时才被删——没人再访问的键会一直
    /// 占着内存，直到容量淘汰才让位。定时扫一遍比"等它自己撞上"靠谱。
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let before = g.map.len();
        let mut freed = 0usize;
        g.map.retain(|_, e| {
            if e.expires <= now {
                freed += e.body.len();
                false
            } else {
                true
            }
        });
        if freed > 0 {
            g.bytes = g.bytes.saturating_sub(freed);
            // 顺序表里现在混着已删的键，重建成"只含存活键"的顺序，
            // 否则 LRU 淘汰会一直弹到空键上，白转好几圈。
            let kept: Vec<String> = g
                .order
                .iter()
                .filter(|k| g.map.contains_key(*k))
                .cloned()
                .collect();
            g.order = kept.into();
        }
        before - g.map.len()
    }

    /// 按 LRU 顺序清到容量阈值以下。水位清理用这个：
    /// 一次清到底会打穿缓存命中率，压回低水位才是正常做法。
    pub fn purge_to(&self, max_bytes: usize, max_entries: usize) -> usize {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let mut removed = 0usize;
        while (g.bytes > max_bytes || g.map.len() > max_entries) && g.map.len() > 1 {
            let Some(victim) = g.order.pop_front() else { break };
            if let Some(e) = g.map.remove(&victim) {
                g.bytes = g.bytes.saturating_sub(e.body.len());
                self.evictions.fetch_add(1, Ordering::Relaxed);
                removed += 1;
            }
        }
        removed
    }
}

/// 只有静态资源才值得进缓存，动态接口一律放行。
pub fn is_cacheable_path(path: &str, exts: &[String]) -> bool {
    if exts.is_empty() {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    exts.iter().any(|e| lower.ends_with(&e.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(c: &ResponseCache, k: &str, body: &str, ttl: u64) {
        c.store(
            k.into(),
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from(body.to_string()),
            CachePolicy {
                ttl: Duration::from_secs(ttl),
                max_bytes: 1024 * 1024,
                max_entries: 16,
            },
        );
    }

    #[test]
    fn hit_and_miss_counted() {
        let c = ResponseCache::default();
        assert!(c.lookup("a").is_none());
        store(&c, "a", "hello", 30);
        assert!(c.lookup("a").is_some());
        let s = c.stats();
        assert_eq!(s.hits, 1);
        assert_eq!(s.misses, 1);
        assert!((s.hit_rate - 50.0).abs() < 0.01);
    }

    #[test]
    fn ttl_expiry() {
        let c = ResponseCache::default();
        store(&c, "a", "x", 0);
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.lookup("a").is_none());
    }

    #[test]
    fn evicts_when_over_entries() {
        let c = ResponseCache::default();
        for i in 0..20 {
            store(&c, &format!("k{i}"), "body", 60);
        }
        assert!(c.stats().entries <= 16);
        assert!(c.stats().evictions > 0);
    }

    #[test]
    fn key_includes_query() {
        let m = Method::GET;
        let a = ResponseCache::key(&m, Some("h"), "/x", Some("a=1"));
        let b = ResponseCache::key(&m, Some("h"), "/x", Some("a=2"));
        assert_ne!(a, b);
    }
}
