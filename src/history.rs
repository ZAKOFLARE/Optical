//! 采样历史：一条环形序列 + 自动降采样。
//!
//! 为什么不按"档位各存一份"：
//! 那样要么内存翻好几倍，要么一换档就得清历史（旧点的时间宽度不一样，混着画读数就是假的）。
//! 更关键的是——粒度属于"看的人"的选择，不该写进服务端配置，否则两个会话各切各的就会撞乐观锁。
//!
//! 这里存两条序列，各管一段时间尺度：
//!
//! - **细粒度环**：点满了就把相邻两点合并、桶宽翻倍，窗口自然变长。它负责"最近这段看细节"。
//! - **小时环**：每满一小时落一个聚合点，固定保留 `history_days` 天（默认 90 天，2160 个点）。
//!   它负责"上个月发生了什么"——细粒度环再怎么降采样也撑不到 30 天，
//!   以前选 30 天其实只看到最近十几小时，图上自然像"只剩一小时"。
//!
//! 查询时按请求的粒度/范围重新分桶：请求的桶不比一小时更细时，老数据从小时环取。

use crate::state::Sample;
use std::collections::VecDeque;

/// 一个采样点：`t` 是桶结束时刻（Unix 毫秒），`s` 是桶内增量。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Point {
    pub t: i64,
    #[serde(flatten)]
    pub s: Sample,
}

/// 查询结果。`exact=false` 表示这段数据已经被降采样到比请求更粗的桶，
/// 前端要如实提示"更早的数据按更粗粒度展示"，而不是假装时间对得上。
#[derive(Debug, Clone, serde::Serialize)]
pub struct Bucketed {
    pub bucket_ms: u64,
    pub points: Vec<Point>,
    pub exact: bool,
}

/// 小时环的固定桶宽。长期曲线的分辨率就是它，不再细分——
/// 90 天 × 每小时一个点 = 2160 个点，这点内存换"上个月到底什么样"很划算。
pub const COARSE_BUCKET_MS: u64 = 3_600_000;

pub struct History {
    /// 当前每点代表的毫秒数
    bucket_ms: u64,
    /// 点数上限：超了就降采样，绝不无限增长
    cap: usize,
    points: VecDeque<Point>,
    /// 长期环：固定 1 小时一点
    coarse: VecDeque<Point>,
    /// 长期环的保留天数（点数上限 = 天数 × 24）
    coarse_days: u32,
    /// 正在累积的那个小时：(小时序号, 未完成聚合)
    coarse_pending: Option<(i64, Point)>,
}

impl History {
    pub fn new(bucket_ms: u64, cap: usize) -> Self {
        Self {
            bucket_ms: bucket_ms.max(1000),
            cap: cap.max(32),
            points: VecDeque::new(),
            coarse: VecDeque::new(),
            coarse_days: 90,
            coarse_pending: None,
        }
    }

    /// 长期环保留天数。0 表示关掉长期留存（省内存，但又只剩最近那截）。
    pub fn set_coarse_days(&mut self, days: u32) {
        self.coarse_days = days.min(365);
        let cap = (self.coarse_days as usize).saturating_mul(24).max(24);
        while self.coarse.len() > cap {
            self.coarse.pop_front();
        }
    }

    pub fn coarse_days(&self) -> u32 {
        self.coarse_days
    }

    pub fn coarse_len(&self) -> usize {
        self.coarse.len()
    }

    pub fn bucket_ms(&self) -> u64 {
        self.bucket_ms
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    #[cfg(test)]
    pub fn points(&self) -> &VecDeque<Point> {
        &self.points
    }

    /// 套用新配置。采集间隔变了就从头来（旧点宽度不同，混着读是假数据）；
    /// 只是点数上限变了，就按新上限裁剪。
    pub fn reconfigure(&mut self, bucket_ms: u64, cap: usize) {
        let bucket_ms = bucket_ms.max(1000);
        let cap = cap.max(32);
        if bucket_ms != self.bucket_ms {
            self.points.clear();
            self.bucket_ms = bucket_ms;
            // 小时环不受采集间隔影响：它的桶宽是固定的，清掉反而白丢 90 天
        }
        self.cap = cap;
        while self.points.len() > self.cap {
            self.merge_once();
        }
    }

    /// 记录一个采样点。满了先降采样再塞，保证窗口一直往前推进。
    pub fn record(&mut self, t: i64, s: Sample) {
        if self.points.len() >= self.cap {
            self.merge_once();
        }
        self.points.push_back(Point { t, s: s.clone() });
        self.fold_coarse(t, s);
    }

    /// 把采样点折进小时环。跨小时就把上一个小时定稿，避免"当前小时"被查出来时还是半截数据。
    fn fold_coarse(&mut self, t: i64, s: Sample) {
        if self.coarse_days == 0 {
            return;
        }
        let slot = t.div_euclid(COARSE_BUCKET_MS as i64);
        let same = matches!(&self.coarse_pending, Some((cur, _)) if *cur == slot);
        if same {
            if let Some((_, p)) = self.coarse_pending.as_mut() {
                p.s.merge(&s);
            }
            return;
        }
        if let Some((_, done)) = self.coarse_pending.replace((slot, Point {
            // 桶结束时刻，和细粒度环的约定一致
            t: (slot + 1) * COARSE_BUCKET_MS as i64,
            s,
        })) {
            self.coarse.push_back(done);
            let cap = (self.coarse_days as usize).saturating_mul(24).max(24);
            while self.coarse.len() > cap {
                self.coarse.pop_front();
            }
        }
    }

    /// 相邻两点合并、桶宽翻倍。计数类是增量，直接相加；平均延迟靠 upstream_ms 除以 requests 还原。
    fn merge_once(&mut self) {
        if self.points.len() < 2 {
            self.bucket_ms = self.bucket_ms.saturating_mul(2);
            return;
        }
        let mut merged: VecDeque<Point> = VecDeque::with_capacity(self.points.len() / 2 + 1);
        let old: Vec<Point> = self.points.drain(..).collect();
        let mut it = old.into_iter();
        while let Some(mut a) = it.next() {
            if let Some(b) = it.next() {
                a.s.merge(&b.s);
                a.t = b.t;
            }
            merged.push_back(a);
        }
        self.points = merged;
        self.bucket_ms = self.bucket_ms.saturating_mul(2);
    }

    /// 按请求的粒度与范围重新分桶。
    /// `gran_ms` 小于已有分辨率时无法凭空造点，只能按已有分辨率返回（`exact=false`）。
    pub fn query(&self, gran_ms: u64, range_secs: u64, now: i64) -> Bucketed {
        let bucket = gran_ms.max(self.bucket_ms).max(1000);
        // 请求比已存数据还细，就只能按已存的分辨率给，别假装时间对得上
        let exact = gran_ms >= self.bucket_ms;
        let from = now.saturating_sub((range_secs as i64).saturating_mul(1000));
        let mut out: Vec<Point> = Vec::new();
        // 记的是"上一个点落在哪个桶"，不是上一个桶的结束时间——
        // 结束时间是 (slot+1)*bucket，拿它去算 slot 永远差一格，每个点都会被当成新桶。
        let mut last_slot: Option<i64> = None;
        let push = |p: &Point, out: &mut Vec<Point>, last_slot: &mut Option<i64>| {
            let slot = p.t.div_euclid(bucket as i64);
            if Some(slot) == *last_slot {
                if let Some(last) = out.last_mut() {
                    last.s.merge(&p.s);
                }
            } else {
                out.push(Point {
                    t: (slot + 1) * bucket as i64,
                    s: p.s.clone(),
                });
                *last_slot = Some(slot);
            }
        };

        // 老数据从小时环取。但它只有小时分辨率：请求的桶比一小时更细时不能拿它充数，
        // 否则等于把"一小时的总量"画成一个 15 分钟的点，读数直接翻四倍。
        if bucket >= COARSE_BUCKET_MS {
            let raw_oldest = self.points.front().map(|p| p.t);
            for p in self.coarse.iter() {
                if p.t <= from {
                    continue;
                }
                // 与细粒度环重叠的时段交给细粒度环：同一段时间被两边各算一次就是重复计数
                if let Some(oldest) = raw_oldest {
                    if p.t >= oldest {
                        continue;
                    }
                }
                push(p, &mut out, &mut last_slot);
            }
        }
        for p in self.points.iter() {
            if p.t <= from {
                continue;
            }
            push(p, &mut out, &mut last_slot);
        }

        Bucketed {
            bucket_ms: bucket,
            points: out,
            exact,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(req: u32) -> Sample {
        Sample {
            requests: req,
            ..Default::default()
        }
    }

    #[test]
    fn records_until_cap_then_downsamples_instead_of_dropping_the_window() {
        let mut h = History::new(1000, 32);
        for i in 0..40 {
            h.record(i as i64 * 1000, s(1));
        }
        assert!(h.len() <= 32, "点数必须被压在上限内，实际 {}", h.len());
        assert!(h.bucket_ms() > 1000, "降采样后桶宽应变大");
        // 降采样是合并，不是丢弃：总量守恒
        let total: u64 = h.points().iter().map(|p| p.s.requests as u64).sum();
        assert_eq!(total, 40, "合并必须保留计数，不能丢样本");
    }

    #[test]
    fn query_rolls_points_into_requested_buckets() {
        let mut h = History::new(1000, 600);
        // t = 0..9000，正好落在两个 5 秒桶里（0-4999 / 5000-9999）
        for i in 0..10 {
            h.record(i as i64 * 1000, s(2));
        }
        let now = 10_000;
        let b = h.query(5_000, 60, now);
        assert_eq!(b.bucket_ms, 5_000);
        assert!(b.exact);
        // 10 个 1 秒点 → 2 个 5 秒桶
        assert_eq!(b.points.len(), 2, "应合成 2 个桶，实际 {}", b.points.len());
        assert_eq!(b.points[0].s.requests, 10);
    }

    #[test]
    fn query_never_pretends_finer_resolution_than_stored() {
        let mut h = History::new(60_000, 600);
        h.record(60_000, s(1));
        let b = h.query(1_000, 3600, 60_000);
        assert_eq!(b.bucket_ms, 60_000, "存的桶就是 1 分钟，不能假装成 1 秒");
        assert!(!b.exact, "分辨率不够时必须显式告知前端");
    }

    #[test]
    fn range_filter_drops_old_points() {
        let mut h = History::new(1000, 600);
        for i in 0..10 {
            h.record((i + 1) * 1000, s(1));
        }
        let b = h.query(1000, 3, 10_000); // 只要最后 3 秒
        assert_eq!(b.points.len(), 3);
    }

    const H: i64 = 3_600_000;

    #[test]
    fn coarse_ring_keeps_one_point_per_hour() {
        let mut h = History::new(1000, 600);
        // 三小时，每小时两点
        for hour in 0..3 {
            for k in 0..2 {
                h.record(hour * H + k * 1000, s(10));
            }
        }
        // 前两小时已定稿，第三小时还在累积
        assert_eq!(h.coarse_len(), 2, "每小时一个点，当前小时未定稿");
        let b = h.query(H as u64, 4 * 3600, 3 * H);
        let req: u64 = b.points.iter().map(|p| p.s.requests as u64).sum();
        assert_eq!(req, 60, "小时环不能丢样本，实际 {req}");
    }

    #[test]
    fn coarse_ring_is_not_used_for_sub_hour_buckets() {
        let mut h = History::new(1000, 600);
        // 只有远早于一小时前的点，细粒度环里没有它们
        for hour in 0..3 {
            for k in 0..4 {
                h.record(hour * H + k * 15_000, s(100));
            }
        }
        // 请求 15 分钟桶：小时环分辨率不够，不能用它充数
        let b = h.query(900_000, 4 * 3600, 3 * H);
        let req: u64 = b.points.iter().map(|p| p.s.requests as u64).sum();
        // 12 个点 × 100 = 1200，全部来自细粒度环。
        // 如果小时环也被算进来（2 个定稿小时各 400），这里会变成 2000。
        assert_eq!(req, 1200, "15 分钟桶只能由细粒度环供给，实际 {req}");
    }

    #[test]
    fn coarse_and_fine_rings_do_not_double_count() {
        let mut h = History::new(1000, 64);
        // 细粒度环装满会被降采样，但它的时间跨度远小于一小时
        for i in 0..200 {
            h.record(i * 1000, s(1));
        }
        let now = 200 * 1000;
        // 请求 1 天、1 小时桶：细粒度点与小时环里尚未定稿的那个小时不能各算一次
        let b = h.query(H as u64, 86_400, now);
        let req: u64 = b.points.iter().map(|p| p.s.requests as u64).sum();
        assert_eq!(req, 200, "同一段时间只能算一次，实际 {req}");
    }

    #[test]
    fn coarse_ring_drops_oldest_beyond_retention() {
        let mut h = History::new(1000, 600);
        h.set_coarse_days(1); // 只留 24 个小时
        for hour in 0..30 {
            h.record(hour * H, s(1));
        }
        assert!(h.coarse_len() <= 24, "超过保留天数要丢最旧的，实际 {}", h.coarse_len());
    }

    #[test]
    fn changing_sample_interval_keeps_long_term_ring() {
        let mut h = History::new(1000, 600);
        h.record(0, s(1));
        h.record(H, s(1));
        h.record(2 * H, s(1));
        let before = h.coarse_len();
        assert!(before > 0);
        h.reconfigure(15_000, 600);
        assert_eq!(h.len(), 0, "细粒度环必须清空");
        assert_eq!(h.coarse_len(), before, "小时环的桶宽与采集间隔无关，不该被清掉");
    }

    #[test]
    fn changing_interval_clears_but_changing_cap_only_trims() {
        let mut h = History::new(1000, 600);
        for i in 0..100 {
            h.record((i + 1) * 1000, s(1));
        }
        h.reconfigure(1000, 50);
        assert!(h.len() <= 50, "收缩上限后点数应被裁到 50，实际 {}", h.len());

        assert!(h.len() > 0);
        h.reconfigure(15_000, 600);
        assert_eq!(h.len(), 0, "采集间隔变了必须清空，否则新旧点宽度不同");
    }
}
