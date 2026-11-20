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

/// 把分配器手里空闲的内存页还给操作系统。
///
/// Rust 释放内存只到分配器为止：glibc 会把空闲页留在 arena 里复用，
/// 于是突发流量过后 RSS 停在高水位不回落——从外面看就是"内存只涨不退"。
/// 网关本身没有持续增长的数据结构，定期 trim 一次就够。
pub fn trim_heap() {
    imp::trim_heap()
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
        fn GetCurrentProcessId() -> u32;
        fn K32GetProcessMemoryInfo(handle: isize, counters: *mut ProcessMemoryCounters, cb: u32) -> i32;
        fn GetProcessTimes(
            handle: isize,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        // 线程数走 Toolhelp 快照：从 XP 就有的稳定 API，不依赖版本相关的枚举值。
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> isize;
        fn Thread32First(snapshot: isize, entry: *mut ThreadEntry32) -> i32;
        fn Thread32Next(snapshot: isize, entry: *mut ThreadEntry32) -> i32;
        fn CloseHandle(handle: isize) -> i32;
        fn SetProcessWorkingSetSize(handle: isize, min: usize, max: usize) -> i32;
    }

    #[repr(C)]
    #[derive(Default)]
    struct ThreadEntry32 {
        dw_size: u32,
        cnt_usage: u32,
        th32_thread_id: u32,
        th32_owner_process_id: u32,
        tp_base_pri: i32,
        tp_delta_pri: i32,
        dw_flags: u32,
    }

    const TH32CS_SNAPTHREAD: u32 = 0x00000004;
    const INVALID_HANDLE_VALUE: isize = -1;

    fn thread_count() -> u32 {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snap == INVALID_HANDLE_VALUE || snap == 0 {
            return 0;
        }
        let pid = unsafe { GetCurrentProcessId() };
        let mut count = 0u32;
        let mut entry = ThreadEntry32 {
            dw_size: std::mem::size_of::<ThreadEntry32>() as u32,
            ..Default::default()
        };
        unsafe {
            if Thread32First(snap, &mut entry) != 0 {
                loop {
                    if entry.th32_owner_process_id == pid {
                        count += 1;
                    }
                    if Thread32Next(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        count
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

    pub fn trim_heap() {
        // Windows 没有 malloc_trim。SetProcessWorkingSetSize(-1,-1) 把工作集压到最小，
        // RSS 立刻回落（内存被分页出去，下次访问再换页）。这是激进的清理，
        // 只该由 server.heap_trim_secs 在低流量时低频驱动，不是每个请求都调。
        unsafe {
            SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
        }
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
            threads: thread_count(),
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

    pub fn trim_heap() {
        // glibc 的 malloc_trim 把空闲页归还 OS；musl 1.2.4+ 也有（void 返回）。
        // musl 用弱符号：旧版本缺符号时链接为 null，判空跳过，不崩也不链接失败。
        #[cfg(all(target_env = "gnu", target_pointer_width = "64"))]
        unsafe {
            unsafe extern "C" {
                fn malloc_trim(pad: usize) -> i32;
            }
            malloc_trim(0);
        }
        #[cfg(all(target_env = "musl", target_pointer_width = "64"))]
        unsafe {
            // musl 的 malloc_trim 只有 1.2.4+ 才导出，rustup 自带的 musl 可能没有，
            // 直接 extern 声明会链接失败。改用 dlsym 运行时查找：查得到就调，
            // 查不到静默跳过（老 musl 本来也没有归还空闲页的等价 API）。
            extern "C" {
                fn dlsym(
                    handle: *mut std::ffi::c_void,
                    symbol: *const std::ffi::c_char,
                ) -> *mut std::ffi::c_void;
            }
            let f = dlsym(std::ptr::null_mut(), b"malloc_trim\0".as_ptr().cast());
            if !f.is_null() {
                let malloc_trim: extern "C" fn(usize) = std::mem::transmute(f);
                malloc_trim(0);
            }
        }
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
    #[cfg(target_os = "macos")]
    pub fn trim_heap() {
        // macOS 没有 malloc_trim；malloc_zone_pressure_relief 通知分配器归还空闲页，
        // 传 NULL 作用在默认 malloc zone、goal=0 表示"能还多少还多少"。
        unsafe {
            extern "C" {
                fn malloc_zone_pressure_relief(
                    zone: *mut std::ffi::c_void,
                    goal: usize,
                ) -> usize;
            }
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
    }

    /// 其它 BSD（FreeBSD/OpenBSD…）没有等价调用，什么都不做
    #[cfg(not(target_os = "macos"))]
    pub fn trim_heap() {}

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
    pub fn trim_heap() {}
    pub fn sample() -> SysSample {
        SysSample::default()
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn thread_count_is_nonzero() {
        let s = super::sample();
        assert!(s.threads > 0, "线程数应为正数，实际 {}", s.threads);
    }
}
