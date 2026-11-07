//! 响应缓存。
//!
//! 「缓存命中率」这个指标只有真缓存才算数，所以这里是个能用的实现：
//! GET/HEAD + 可缓存状态码 + 可缓存扩展名才进缓存，按 TTL 过期、按字节/条数双限额 LRU 淘汰。
//! 缓存键包含 host + path + query，避免 `?a=1` 和 `?a=2` 串味。

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
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
    hits: u64,
    misses: u64,
    stores: u64,
    evictions: u64,
}

#[derive(Default)]
pub struct ResponseCache {
    inner: Mutex<Inner>,
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
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let expired = match g.map.get(key) {
            Some(e) => e.expires <= Instant::now(),
            None => false,
        };
        if expired {
            if let Some(e) = g.map.remove(key) {
                g.bytes = g.bytes.saturating_sub(e.body.len());
            }
            g.order.retain(|k| k != key);
            g.misses += 1;
            return None;
        }
        match g.map.get(key) {
            Some(e) => {
                let out = (e.status, e.headers.clone(), e.body.clone());
                g.hits += 1;
                Some(out)
            }
            None => {
                g.misses += 1;
                None
            }
        }
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
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
        g.stores += 1;

        while (g.bytes > max_bytes || g.map.len() > max_entries) && g.map.len() > 1 {
            let Some(victim) = g.order.pop_front() else { break };
            if let Some(e) = g.map.remove(&victim) {
                g.bytes = g.bytes.saturating_sub(e.body.len());
                g.evictions += 1;
            }
        }
    }

    pub fn stats(&self) -> CacheStats {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let total = g.hits + g.misses;
        CacheStats {
            entries: g.map.len(),
            bytes: g.bytes,
            hits: g.hits,
            misses: g.misses,
            stores: g.stores,
            evictions: g.evictions,
            hit_rate: if total == 0 { 0.0 } else { g.hits as f64 / total as f64 * 100.0 },
        }
    }

    pub fn purge(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.map.clear();
        g.order.clear();
        g.bytes = 0;
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
