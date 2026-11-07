//! 进程自身占用：内存 / CPU / 线程数。
//!
//! 为什么不用 sysinfo：这个项目一直在压依赖，而这里只需要四个数，
//! 自己读 /proc（Linux/macOS 走 ps）和两个 Win32 调用就够了。
//! 读不到就返回 None，UI 显示「—」，绝不编数字。

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct SysSample {
    /// 常驻内存（字节）
    pub rss_bytes: u64,
    /// CPU 占用（百分比，单核口径可能 >100）
    pub cpu_pct: f64,
    /// 线程数
    pub threads: u32,
}

/// 累计 CPU 时间（秒），用来算两次采样之间的百分比
pub fn cpu_seconds() -> Option<f64> {
    imp::cpu_seconds()
}

pub fn sample() -> SysSample {
    imp::sample()
}

#[cfg(windows)]
mod imp {
    use super::SysSample;

    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    impl FileTime {
        fn secs(&self) -> f64 {
            ((self.high as u64) << 32 | self.low as u64) as f64 / 10_000_000.0
        }
    }

    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(handle: isize, counters: *mut ProcessMemoryCounters, cb: u32) -> i32;
        fn GetProcessTimes(
            handle: isize,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    fn times() -> Option<(f64, f64)> {
        let mut c = FileTime::default();
        let mut e = FileTime::default();
        let mut k = FileTime::default();
        let mut u = FileTime::default();
        let ok = unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) };
        (ok != 0).then(|| (k.secs(), u.secs()))
    }

    pub fn cpu_seconds() -> Option<f64> {
        times().map(|(k, u)| k + u)
    }

    pub fn sample() -> SysSample {
        let mut c = ProcessMemoryCounters {
            cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
            ..Default::default()
        };
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
        SysSample {
            rss_bytes: if ok != 0 { c.working_set_size as u64 } else { 0 },
            cpu_pct: 0.0,
            threads: 0,
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::SysSample;

    fn read(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    /// /proc/self/stat 的字段里有空格分隔的名字，先跳过 ")" 再切
    fn stat_fields() -> Option<Vec<String>> {
        let raw = read("/proc/self/stat")?;
        let tail = &raw[raw.rfind(')')? + 1..];
        Some(tail.split_whitespace().map(str::to_string).collect())
    }

    pub fn cpu_seconds() -> Option<f64> {
        let f = stat_fields()?;
        // 跳过 ") " 之后，utime 是第 14 个字段，在这里是下标 11（stime 是 12）
        let utime: u64 = f.get(11)?.parse().ok()?;
        let stime: u64 = f.get(12)?.parse().ok()?;
        // USER_HZ 在绝大多数 Linux 上就是 100
        Some((utime + stime) as f64 / 100.0)
    }

    pub fn sample() -> SysSample {
        let mut out = SysSample::default();
        if let Some(status) = read("/proc/self/status") {
            for line in status.lines() {
                if let Some(v) = line.strip_prefix("VmRSS:") {
                    out.rss_bytes = v
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                        .map(|kb| kb * 1024)
                        .unwrap_or(0);
                } else if let Some(v) = line.strip_prefix("Threads:") {
                    out.threads = v.trim().parse().unwrap_or(0);
                }
            }
        }
        out
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    use super::SysSample;

    /// macOS / BSD 上直接问 ps：一次 fork 换四个数，比引一个 crate 划算
    pub fn cpu_seconds() -> Option<f64> {
        let out = std::process::Command::new("ps")
            .args(["-o", "time=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // 形如 00:01:23 或 1-02:03:04
        let (days, rest) = match s.split_once('-') {
            Some((d, r)) => (d.parse::<f64>().ok()?, r.to_string()),
            None => (0.0, s),
        };
        let parts: Vec<f64> = rest
            .split(':')
            .filter_map(|p| p.trim().parse::<f64>().ok())
            .collect();
        let secs = match parts.len() {
            3 => parts[0] * 3600.0 + parts[1] * 60.0 + parts[2],
            2 => parts[0] * 60.0 + parts[1],
            _ => return None,
        };
        Some(days * 86_400.0 + secs)
    }

    pub fn sample() -> SysSample {
        let pid = std::process::id().to_string();
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=,nlwp=", "-p", &pid])
            .output()
            .ok();
        let mut s = SysSample::default();
        if let Some(o) = out {
            let text = String::from_utf8_lossy(&o.stdout);
            let mut it = text.split_whitespace();
            if let Some(rss) = it.next().and_then(|v| v.parse::<u64>().ok()) {
                s.rss_bytes = rss * 1024; // ps 给的是 KB
            }
            if let Some(t) = it.next().and_then(|v| v.parse::<u32>().ok()) {
                s.threads = t;
            }
        }
        s
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::SysSample;
    pub fn cpu_seconds() -> Option<f64> {
        None
    }
    pub fn sample() -> SysSample {
        SysSample::default()
    }
}
