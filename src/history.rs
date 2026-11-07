//! 采样历史：一条环形序列 + 自动降采样。
//!
//! 为什么不按"档位各存一份"：
//! 那样要么内存翻好几倍，要么一换档就得清历史（旧点的时间宽度不一样，混着画读数就是假的）。
//! 更关键的是——粒度属于"看的人"的选择，不该写进服务端配置，否则两个会话各切各的就会撞乐观锁。
//!
//! 这里只存一条序列：点满了就把相邻两点合并、桶宽翻倍，窗口自然变长。
//! 查询时按请求的粒度/范围重新分桶，所以前端换粒度只是换观察方式，数据一次都不丢。

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

pub struct History {
    /// 当前每点代表的毫秒数
    bucket_ms: u64,
    /// 点数上限：超了就降采样，绝不无限增长
    cap: usize,
    points: VecDeque<Point>,
}

impl History {
    pub fn new(bucket_ms: u64, cap: usize) -> Self {
        Self {
            bucket_ms: bucket_ms.max(1000),
            cap: cap.max(32),
            points: VecDeque::new(),
        }
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
        self.points.push_back(Point { t, s });
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
        for p in self.points.iter() {
            if p.t <= from {
                continue;
            }
            let slot = p.t / bucket as i64;
            if Some(slot) == last_slot {
                if let Some(last) = out.last_mut() {
                    last.s.merge(&p.s);
                }
            } else {
                out.push(Point {
                    t: (slot + 1) * bucket as i64,
                    s: p.s.clone(),
                });
                last_slot = Some(slot);
            }
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
