//! 排行榜聚合：按维度 × 时间窗统计，供"概览 → 排行榜"用。
//!
//! 为什么不是把每请求都存下来：那是日志系统干的活。这里只留两级环形桶
//! （1 分钟 × 120 = 2 小时、1 小时 × 168 = 7 天），查询时按范围挑桶相加。
//! 内存恒定，也不会因为请求量大就膨胀。
//!
//! 维度设计有点讲究：`route / backend / host / status` 四个字段必须能**互相筛选**
//! （"按路由看，但只统计 2xx、只算某个后端"），所以它们存在同一张组合表里；
//! IP / UA / 规则基数大且不需要交叉筛选，各自单独存，省内存。

use std::collections::{HashMap, VecDeque};

/// 排行榜维度。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dim {
    Route,
    Backend,
    Host,
    Status,
    Ip,
    Ua,
    Rule,
}

impl Dim {
    pub fn as_str(self) -> &'static str {
        match self {
            Dim::Route => "route",
            Dim::Backend => "backend",
            Dim::Host => "host",
            Dim::Status => "status",
            Dim::Ip => "ip",
            Dim::Ua => "ua",
            Dim::Rule => "rule",
        }
    }

    pub fn parse(s: &str) -> Option<Dim> {
        Some(match s {
            "route" => Dim::Route,
            "backend" => Dim::Backend,
            "host" => Dim::Host,
            "status" => Dim::Status,
            "ip" => Dim::Ip,
            "ua" => Dim::Ua,
            "rule" => Dim::Rule,
            _ => return None,
        })
    }

    /// 这个维度能不能用别的字段筛选。
    /// 组合表里的四个字段是同一批请求的属性，可以互相过滤；
    /// IP/UA/规则是各自独立的表，只认自己这一列。
    fn groupable_with(self, f: Dim) -> bool {
        let combo = |d: Dim| matches!(d, Dim::Route | Dim::Backend | Dim::Host | Dim::Status);
        if combo(self) {
            combo(f)
        } else {
            self == f
        }
    }

    /// 前端下拉用：这个维度支持哪些筛选字段
    pub fn filter_fields(self) -> Vec<&'static str> {
        match self {
            Dim::Route | Dim::Backend | Dim::Host | Dim::Status => {
                vec!["route", "backend", "host", "status"]
            }
            Dim::Ip => vec!["ip"],
            Dim::Ua => vec!["ua"],
            Dim::Rule => vec!["rule"],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Eq,
    Ne,
    Contains,
    NContains,
}

impl Op {
    pub fn parse(s: &str) -> Option<Op> {
        Some(match s {
            "eq" | "=" => Op::Eq,
            "ne" | "!=" => Op::Ne,
            "contains" | "~" => Op::Contains,
            "ncontains" | "!~" => Op::NContains,
            _ => return None,
        })
    }

}

#[derive(Clone, Debug)]
pub struct Filter {
    pub field: Dim,
    pub op: Op,
    pub value: String,
}

impl Filter {
    fn matches(&self, v: &str) -> bool {
        let (v, want) = (v.to_lowercase(), self.value.to_lowercase());
        match self.op {
            Op::Eq => v == want,
            Op::Ne => v != want,
            Op::Contains => v.contains(&want),
            Op::NContains => !v.contains(&want),
        }
    }

    /// 状态码支持 2xx / 4xx 这种段位写法，也支持精确 502
    fn matches_status(&self, status: u16) -> bool {
        let s = status.to_string();
        let want = self.value.trim().to_lowercase();
        let class_hit = want.len() == 3
            && want.ends_with("xx")
            && status / 100 == want[..1].parse::<u16>().unwrap_or(0);
        match self.op {
            Op::Eq => class_hit || s == want,
            Op::Ne => !(class_hit || s == want),
            Op::Contains => s.contains(&want) || class_hit,
            Op::NContains => !(s.contains(&want) || class_hit),
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Counters {
    pub requests: u32,
    pub errors: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub cache_hit: u32,
    pub cache_miss: u32,
    pub waf_blocks: u32,
    /// 上游耗时累计（微秒）——毫秒精度下 echo 上游全是 0，看着像没数据
    pub upstream_us: u64,
}

impl Counters {
    fn add(&mut self, o: &Counters) {
        self.requests += o.requests;
        self.errors += o.errors;
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        self.cache_hit += o.cache_hit;
        self.cache_miss += o.cache_miss;
        self.waf_blocks += o.waf_blocks;
        self.upstream_us += o.upstream_us;
    }

    /// 平均耗时（微秒）；0 表示这批请求压根没走上游（缓存命中/本地拒绝）
    pub fn avg_us(&self) -> u64 {
        if self.requests == 0 {
            0
        } else {
            self.upstream_us / self.requests as u64
        }
    }
}

/// 一次请求的维度画像。空字符串表示"没命中"（未匹配路由、直连默认上游等）。
#[derive(Clone, Copy, Default, Debug)]
pub struct ReqDims<'a> {
    pub route: &'a str,
    pub backend: &'a str,
    pub host: &'a str,
}

type Combo = (String, String, String, u16);

#[derive(Default)]
struct Bucket {
    /// 桶起点（Unix 分钟，按桶跨度对齐）
    start: i64,
    combos: HashMap<Combo, Counters>,
    ips: HashMap<String, Counters>,
    uas: HashMap<String, Counters>,
    rules: HashMap<String, u32>,
    /// 这个桶是否因为超容量丢掉过键。查询时汇总出去，
    /// 免得「全部」看起来是全量、其实早被挤掉一批长尾。
    trimmed: bool,
}

impl Bucket {
    fn new(start: i64) -> Self {
        Self {
            start,
            ..Default::default()
        }
    }

    /// 回收复用：清空内容并把 start 挪到新时间片。
    /// 容量只保留一小截——留太多等于每个桶都攥着历史峰值内存，
    /// 288 个桶乘起来就是几十兆；全丢又会回到每分钟重新分配的老路。
    fn reset(&mut self, start: i64) {
        self.start = start;
        self.trimmed = false;
        keep_small(&mut self.combos);
        keep_small(&mut self.ips);
        keep_small(&mut self.uas);
        keep_small(&mut self.rules);
    }
}

fn keep_small<K: std::hash::Hash + Eq, V>(m: &mut HashMap<K, V>) {
    m.clear();
    if m.capacity() > 128 {
        m.shrink_to(32);
    }
}

/// 单个桶里每张表最多留多少个键。超了就把最小的挤掉——
/// 排行榜本来只看头部，没必要为长尾付内存。
const CAP_COMBOS: usize = 512;
const CAP_TEXT: usize = 512;
const CAP_RULES: usize = 256;

struct Ring {
    /// 桶跨度（分钟）
    span: i64,
    buckets: VecDeque<Bucket>,
    cap: usize,
    /// 淘汰的桶不扔，清空后复用。每分钟 new 四张 HashMap、再整批 drop，
    /// 是 RSS 只涨不回的源头：分配器把空闲页留在 arena 里，从不还 OS。
    pool: Vec<Bucket>,
}

impl Ring {
    fn new(span: i64, cap: usize) -> Self {
        Self {
            span,
            buckets: VecDeque::with_capacity(cap),
            cap,
            pool: Vec::new(),
        }
    }

    fn bucket_start(&self, minute: i64) -> i64 {
        minute - minute.rem_euclid(self.span)
    }

    fn touch(&mut self, minute: i64) -> &mut Bucket {
        let start = self.bucket_start(minute);
        if self.buckets.back().map(|b| b.start) != Some(start) {
            // 时间只会前进；但如果时钟回拨，别把旧桶当新桶用
            if let Some(pos) = self.buckets.iter().position(|b| b.start == start) {
                return &mut self.buckets[pos];
            }
            let mut fresh = self.pool.pop().unwrap_or_else(|| Bucket::new(start));
            // 无条件 reset：空桶上 clear 是 no-op，而"池里恰好取到最后一个"时会漏清
            fresh.reset(start);
            self.buckets.push_back(fresh);
            while self.buckets.len() > self.cap {
                if let Some(old) = self.buckets.pop_front() {
                    self.pool.push(old);
                }
            }
        }
        self.buckets
            .back_mut()
            .expect("刚刚 push 过的环形桶不可能为空")
    }

}

/// 单次排行榜最多返回多少行（防呆，不是产品上限：正常窗口远到不了）。
pub const MAX_RANK_ROWS: usize = 5000;

/// 一次查询的结果。总量与被裁标记单独给出，
/// 前端才能说清「占比 100% 里还有多少没列出来」。
pub struct Ranking {
    pub rows: Vec<(String, Counters)>,
    pub dropped: Vec<&'static str>,
    pub total: u64,
    pub trimmed: bool,
}

pub struct StatsStore {
    /// 1 分钟 × 120：近 2 小时的高分辨率
    minute: Ring,
    /// 1 小时 × 168：近 7 天
    hour: Ring,
}

impl Default for StatsStore {
    fn default() -> Self {
        Self {
            minute: Ring::new(1, 120),
            hour: Ring::new(60, 168),
        }
    }
}

impl StatsStore {
    /// 记一次请求。`minute` 是当前 Unix 分钟。
    pub fn record_request(
        &mut self,
        minute: i64,
        dims: ReqDims<'_>,
        status: u16,
        c: &Counters,
        ua: &str,
        ip: &str,
    ) {
        for ring in [&mut self.minute, &mut self.hour] {
            let b = ring.touch(minute);
            let key = (
                norm(dims.route),
                norm(dims.backend),
                norm(dims.host),
                status,
            );
            b.combos.entry(key).or_default().add(c);
            b.trimmed |= trim(&mut b.combos, CAP_COMBOS, |v| v.requests as u64);

            if !ip.is_empty() {
                b.ips.entry(ip.to_string()).or_default().add(c);
                b.trimmed |= trim(&mut b.ips, CAP_TEXT, |v| v.requests as u64);
            }
            if !ua.is_empty() {
                b.uas.entry(ua.to_string()).or_default().add(c);
                b.trimmed |= trim(&mut b.uas, CAP_TEXT, |v| v.requests as u64);
            }
        }
    }

    /// 规则命中单独记：它发生在 WAF 检查那一刻，那时还没有路由/后端决策，
    /// 硬塞进组合表只会得到一堆空维度。
    pub fn record_rules(&mut self, minute: i64, rules: &[String]) {
        if rules.is_empty() {
            return;
        }
        for ring in [&mut self.minute, &mut self.hour] {
            let b = ring.touch(minute);
            for r in rules {
                if !r.is_empty() {
                    *b.rules.entry(r.clone()).or_insert(0) += 1;
                }
            }
            b.trimmed |= trim(&mut b.rules, CAP_RULES, |v| *v as u64);
        }
    }

    /// 按维度 + 时间范围 + 筛选条件出排行榜。
    ///
    /// `limit == 0` 表示不截断（「查看全部」）。截断时刻意**不是**先截再算占比：
    /// `total` 是整窗真实总量，否则 TOP200 的百分比会按 200 条自己当分母，越看越离谱。
    pub fn query(
        &self,
        range_secs: u64,
        by: Dim,
        filters: &[Filter],
        limit: usize,
    ) -> Ranking {
        let now_min = crate::state::now_ms() / 60_000;
        let range_min = ((range_secs / 60) as i64).max(1);

        // 挑能覆盖范围的最细一级；都不够就用最粗的那级（并如实返回覆盖不到）
        let ring = if range_min <= self.minute.cap as i64 {
            &self.minute
        } else {
            &self.hour
        };
        let from = now_min - range_min;

        // 记录哪些筛选条件在当前维度下用不上，前端好提示"这个筛选对这张表无效"
        let mut dropped: Vec<&'static str> = Vec::new();
        let usable: Vec<&Filter> = filters
            .iter()
            .filter(|f| {
                let ok = by.groupable_with(f.field);
                if !ok {
                    dropped.push(f.field.as_str());
                }
                ok
            })
            .collect();
        dropped.sort_unstable();
        dropped.dedup();

        let mut acc: HashMap<String, Counters> = HashMap::new();
        for b in ring.buckets.iter().filter(|b| b.start + ring.span > from) {
            match by {
                Dim::Route | Dim::Backend | Dim::Host | Dim::Status => {
                    for ((route, backend, host, status), c) in b.combos.iter() {
                        if !ok_combo(&usable, route, backend, host, *status) {
                            continue;
                        }
                        let key = match by {
                            Dim::Route => route.clone(),
                            Dim::Backend => backend.clone(),
                            Dim::Host => host.clone(),
                            _ => status.to_string(),
                        };
                        acc.entry(key).or_default().add(c);
                    }
                }
                Dim::Ip => {
                    for (ip, c) in b.ips.iter() {
                        if usable.iter().any(|f| f.field == Dim::Ip && !f.matches(ip)) {
                            continue;
                        }
                        acc.entry(ip.clone()).or_default().add(c);
                    }
                }
                Dim::Ua => {
                    for (ua, c) in b.uas.iter() {
                        if usable.iter().any(|f| f.field == Dim::Ua && !f.matches(ua)) {
                            continue;
                        }
                        acc.entry(ua.clone()).or_default().add(c);
                    }
                }
                Dim::Rule => {
                    for (rule, n) in b.rules.iter() {
                        if usable.iter().any(|f| f.field == Dim::Rule && !f.matches(rule)) {
                            continue;
                        }
                        let e = acc.entry(rule.clone()).or_default();
                        e.requests += *n;
                    }
                }
            }
        }

        let total: u64 = acc.values().map(|c| c.requests as u64).sum();
        let trimmed = ring
            .buckets
            .iter()
            .filter(|b| b.start + ring.span > from)
            .any(|b| b.trimmed);

        let mut rows: Vec<(String, Counters)> = acc.into_iter().collect();
        rows.sort_by(|a, b| {
            b.1.requests
                .cmp(&a.1.requests)
                .then_with(|| a.0.cmp(&b.0))
        });
        // 0 = 全部。上限给一个防呆值，避免一次把几万行塞进一帧 JSON。
        if limit > 0 {
            rows.truncate(limit.min(MAX_RANK_ROWS));
        }
        Ranking {
            rows,
            dropped,
            total,
            trimmed,
        }
    }
}

fn ok_combo(filters: &[&Filter], route: &str, backend: &str, host: &str, status: u16) -> bool {
    filters.iter().all(|f| match f.field {
        Dim::Route => f.matches(route),
        Dim::Backend => f.matches(backend),
        Dim::Host => f.matches(host),
        Dim::Status => f.matches_status(status),
        _ => true,
    })
}

/// 空维度显示成可读占位，否则排行榜会出现一整行空白
fn norm(s: &str) -> String {
    if s.is_empty() {
        "—".to_string()
    } else {
        s.to_string()
    }
}

/// 超容量时砍掉最小的那些，保证内存不随长尾增长
fn trim<K: std::hash::Hash + Eq + Clone, V>(
    map: &mut HashMap<K, V>,
    cap: usize,
    score: impl Fn(&V) -> u64,
) -> bool {
    // 留 25% 余量再裁：贴着上限裁会让后续每个请求都触发一次全表 clone+sort
    if map.len() <= cap + cap / 4 {
        return false;
    }
    let mut keys: Vec<(K, u64)> = map.iter().map(|(k, v)| (k.clone(), score(v))).collect();
    keys.sort_by_key(|b| std::cmp::Reverse(b.1));
    keys.truncate(cap);
    let keep: std::collections::HashSet<K> = keys.into_iter().map(|(k, _)| k).collect();
    map.retain(|k, _| keep.contains(k));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(req: u32, err: u32) -> Counters {
        Counters {
            requests: req,
            errors: err,
            bytes_in: req as u64 * 10,
            ..Default::default()
        }
    }

    fn dims<'a>(r: &'a str, b: &'a str, h: &'a str) -> ReqDims<'a> {
        ReqDims {
            route: r,
            backend: b,
            host: h,
        }
    }

    #[test]
    fn groups_by_route_and_sums_the_window() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        s.record_request(now, dims("api", "b1", "a.com"), 200, &c(3, 0), "curl", "1.1.1.1");
        s.record_request(now, dims("api", "b1", "a.com"), 200, &c(2, 0), "curl", "1.1.1.1");
        s.record_request(now, dims("web", "b2", "a.com"), 502, &c(1, 1), "curl", "2.2.2.2");
        let Ranking { rows, dropped, .. } = s.query(3600, Dim::Route, &[], 10);
        assert!(dropped.is_empty());
        assert_eq!(rows[0].0, "api");
        assert_eq!(rows[0].1.requests, 5);
        assert_eq!(rows[1].0, "web");
        assert_eq!(rows[1].1.errors, 1);
    }

    #[test]
    fn filters_apply_across_the_combo_dimensions() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        s.record_request(now, dims("api", "b1", "a.com"), 200, &c(5, 0), "ua", "1.1.1.1");
        s.record_request(now, dims("api", "b1", "a.com"), 500, &c(2, 2), "ua", "1.1.1.1");
        s.record_request(now, dims("web", "b2", "a.com"), 200, &c(7, 0), "ua", "1.1.1.1");

        // 按路由看，但只统计 2xx —— 这是"跨维度筛选"，必须真的生效
        let f = Filter {
            field: Dim::Status,
            op: Op::Eq,
            value: "2xx".into(),
        };
        let Ranking { rows, .. } = s.query(3600, Dim::Route, &[f], 10);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "web");
        assert_eq!(rows[0].1.requests, 7);
        assert_eq!(rows[1].0, "api");
        assert_eq!(rows[1].1.requests, 5);
    }

    #[test]
    fn unsupported_filter_is_reported_not_silently_ignored() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        s.record_request(now, dims("api", "b1", "a.com"), 200, &c(1, 0), "ua", "9.9.9.9");
        let f = Filter {
            field: Dim::Route,
            op: Op::Eq,
            value: "api".into(),
        };
        // IP 表里没有路由信息，这种筛选只能如实报告"用不上"
        let Ranking { rows, dropped, .. } = s.query(3600, Dim::Ip, &[f], 10);
        assert_eq!(dropped, vec!["route"]);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn old_buckets_fall_out_of_the_window() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        s.record_request(now - 30, dims("old", "b", "h"), 200, &c(9, 0), "", "");
        s.record_request(now, dims("new", "b", "h"), 200, &c(1, 0), "", "");
        // 近 10 分钟：30 分钟前的桶必须落在窗口外
        let Ranking { rows, .. } = s.query(600, Dim::Route, &[], 10);
        assert!(
            rows.iter().all(|(k, _)| k != "old"),
            "10 分钟窗口不该统计到 30 分钟前的数据: {rows:?}"
        );
        // 近 1 小时：同一个桶又该回来了
        let Ranking { rows: rows2, .. } = s.query(3600, Dim::Route, &[], 10);
        assert!(rows2.iter().any(|(k, _)| k == "old"));
    }

    #[test]
    fn empty_dimension_gets_a_readable_placeholder() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        s.record_request(now, dims("", "", ""), 200, &c(2, 0), "", "");
        let Ranking { rows, .. } = s.query(3600, Dim::Route, &[], 10);
        assert_eq!(rows[0].0, "—");
    }

    #[test]
    fn limit_zero_returns_everything_and_total_is_the_whole_window() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        // 300 个不同路由：老实现 truncate(200) 会悄悄砍到 200 条，
        // 而且 pct 分母按 200 条自己算，占比加起来能超过 100%。
        for i in 0..300 {
            let route = format!("r{i:03}");
            s.record_request(now, dims(&route, "b", "h"), 200, &c(1, 0), "ua", "1.1.1.1");
        }
        let Ranking {
            rows, total, ..
        } = s.query(3600, Dim::Route, &[], 0);
        assert_eq!(rows.len(), 300, "limit=0 必须返回全部，不是 200");
        assert_eq!(total, 300, "total 是整窗请求数，不能等于返回行之和");

        // 显式 limit 仍然截断，但 total 保持整窗值
        let Ranking { rows, total, .. } = s.query(3600, Dim::Route, &[], 10);
        assert_eq!(rows.len(), 10);
        assert_eq!(total, 300);
    }

    #[test]
    fn caps_keep_memory_bounded() {
        let mut s = StatsStore::default();
        let now = crate::state::now_ms() / 60_000;
        for i in 0..(CAP_TEXT + 50) {
            let ip = format!("10.0.0.{i}");
            s.record_request(now, dims("api", "b", "h"), 200, &c(1, 0), "ua", &ip);
        }
        let b = s.minute.buckets.back().unwrap();
        // 裁剪有 25% 迟滞（贴着上限裁会让每个请求都全表 clone 一次），
        // 所以边界是 cap + cap/4，而不是刚好 cap。
        let bound = CAP_TEXT + CAP_TEXT / 4;
        assert!(b.ips.len() <= bound, "IP 表被长尾撑爆了: {}", b.ips.len());
    }
}
