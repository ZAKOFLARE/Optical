//! 存储层：配置回溯快照 + 审计日志。
//!
//! 两者都直接吃 `[storage]` 里的三重配额（条数 / 字节 / 天数），
//! 因为磁盘大小是运维的现实约束，不能写一套"只增不减"的日志。

use crate::config::StorageConfig;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapshotMeta {
    pub id: String,
    pub size: usize,
    pub created_ms: i64,
    pub reason: String,
    /// 前几行摘要，供 UI 预览
    pub preview: String,
}

pub struct ConfigHistory {
    dir: PathBuf,
}

impl ConfigHistory {
    /// 显式指定快照目录（路径由 `config.resolve_paths()` 统一算出，不再在这里猜）。
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// 便捷构造：`<配置文件目录>/conf-history`。仅测试与临时脚本用。
    #[allow(dead_code)]
    pub fn new(config_path: &Path) -> Self {
        let dir = config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("conf-history");
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 每次落盘前调用。内容与上一份相同则跳过，避免刷出一堆无意义快照。
    pub fn record(&self, toml_text: &str, reason: &str, storage: &StorageConfig) -> Result<()> {
        if storage.config_history_keep == 0 {
            return Ok(());
        }
        fs::create_dir_all(&self.dir).map_err(|e| {
            // 这个错最常见的原因不是磁盘满，而是目录落在只读位置：
            // data_dir 默认跟着配置文件走，配置在 /etc 时，systemd 的 ProtectSystem
            // 会让服务进程写不进去——报错必须点出这一层，否则人只会去查磁盘。
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "\n提示：目录不可写。若服务跑在 systemd 沙箱里，/etc 默认只读；\n     把 [paths] data_dir 指到 /var/lib/optical，或用 ReadWritePaths 放开该目录。"
            } else {
                ""
            };
            anyhow::anyhow!("创建快照目录失败: {} ({e}){hint}", self.dir.display())
        })?;

        if let Some(latest) = self.list_meta().first() {
            if let Ok(prev) = self.read(&latest.id) {
                if strip_header(&prev) == strip_header(toml_text) {
                    return Ok(());
                }
            }
        }

        let ts = timestamp();
        let hash = short_hash(toml_text);
        let id = format!("{ts}-{hash}.toml");
        let body = format!("# optical snapshot ts={ts} reason={reason}\n{toml_text}");
        fs::write(self.dir.join(&id), body)?;
        self.prune(storage);
        Ok(())
    }

    pub fn list_meta(&self) -> Vec<SnapshotMeta> {
        let Ok(rd) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<SnapshotMeta> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "toml").unwrap_or(false))
            .map(|e| {
                let id = e.file_name().to_string_lossy().to_string();
                let size = e.metadata().map(|m| m.len() as usize).unwrap_or(0);
                let created_ms = e
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let reason = id
                    .split('-')
                    .nth(2)
                    .map(|s| s.trim_end_matches(".toml").to_string())
                    .unwrap_or_default();
                let preview = fs::read_to_string(e.path())
                    .map(|s| {
                        s.lines()
                            .filter(|l| !l.starts_with('#'))
                            .take(4)
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                SnapshotMeta {
                    id,
                    size,
                    created_ms,
                    reason,
                    preview,
                }
            })
            .collect();
        out.sort_by(|a, b| b.id.cmp(&a.id)); // 文件名含时间戳，倒序即最新在前
        out
    }

    pub fn read(&self, id: &str) -> Result<String> {
        let path = self.safe_path(id)?;
        fs::read_to_string(&path).with_context(|| format!("读取快照失败: {}", path.display()))
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let path = self.safe_path(id)?;
        fs::remove_file(path)?;
        Ok(())
    }

    /// 按 条数 / 字节 / 天数 三重配额裁剪，取最严格者。
    pub fn prune(&self, storage: &StorageConfig) {
        let mut list = self.list_meta();
        if list.is_empty() {
            return;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let max_age_ms = if storage.config_history_keep_days > 0 {
            Some(storage.config_history_keep_days as i64 * 86_400_000)
        } else {
            None
        };

        let mut total = 0usize;
        let mut kept = 0usize;
        let mut victims: Vec<String> = Vec::new();
        for m in list.drain(..) {
            total += m.size;
            kept += 1;
            let too_many = storage.config_history_keep > 0 && kept > storage.config_history_keep;
            let too_big = storage.config_history_max_bytes > 0
                && total > storage.config_history_max_bytes
                && kept > 1;
            let too_old = max_age_ms
                .map(|age| now_ms - m.created_ms > age)
                .unwrap_or(false);
            if too_many || too_big || too_old {
                victims.push(m.id);
            }
        }
        for id in victims {
            if let Ok(p) = self.safe_path(&id) {
                let _ = fs::remove_file(p);
            }
        }
    }

    fn safe_path(&self, id: &str) -> Result<PathBuf> {
        let ok = !id.is_empty()
            && id.len() < 128
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            && !id.contains("..");
        if !ok {
            bail!("非法的快照 id: {id}");
        }
        Ok(self.dir.join(id))
    }
}

fn strip_header(s: &str) -> String {
    s.lines()
        .filter(|l| !l.starts_with("# optical snapshot"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn short_hash(s: &str) -> String {
    // FNV-1a：够用来去重，不引额外依赖
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}", (h & 0xffff_ffff) as u32)
}

fn timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    // 手搓 UTC 分解，避免为一个时间戳拉 chrono。
    // 必须带毫秒：同一秒内的两次保存如果只精确到秒，文件名会几乎相同，
    // 排序就只能靠哈希，回滚时可能拿到错的版本。
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant 的 civil_from_days
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------- 审计日志 ----------------

/// WAF 命中与配置变更的审计流。内存里保留最近 N 条给 UI，同时按容量滚动落盘。
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub ts_ms: i64,
    pub kind: String,
    pub detail: String,
    pub identity: String,
    pub path: String,
    pub rule: String,
}

pub struct AuditLog {
    path: PathBuf,
    recent: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
}

impl AuditLog {
    /// 显式指定审计文件路径。
    pub fn with_file(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        Self {
            path,
            recent: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(256)),
        }
    }

    /// 便捷构造：`<配置文件>.audit.jsonl`。仅测试用。
    #[allow(dead_code)]
    pub fn new(config_path: &Path) -> Self {
        Self::with_file(config_path.with_extension("audit.jsonl"))
    }

    pub fn push(&self, storage: &StorageConfig, entry: AuditEntry) {
        if !storage.audit_enabled {
            return;
        }
        {
            let mut g = self.recent.lock().unwrap_or_else(|e| e.into_inner());
            if g.len() >= storage.audit_keep.min(1000) {
                g.pop_front();
            }
            g.push_back(entry.clone());
        }
        // 落盘失败不影响转发主链路
        if let Ok(line) = serde_json::to_string(&entry) {
            use std::io::Write;
            if let Ok(mut f) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(f, "{line}");
            }
            if let Ok(meta) = fs::metadata(&self.path) {
                if storage.audit_max_bytes > 0 && meta.len() as usize > storage.audit_max_bytes {
                    self.rotate(storage);
                }
            }
        }
    }

    fn rotate(&self, storage: &StorageConfig) {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        let keep = storage.audit_keep.max(1);
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(keep);
        let body = lines[start..].join("\n");
        let _ = fs::write(&self.path, format!("{body}\n"));
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEntry> {
        let g = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        g.iter().rev().take(limit).cloned().collect()
    }

    pub fn clear(&self) {
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let _ = fs::remove_file(&self.path);
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_matches_known_value() {
        // 1970-01-01 起第 20764 天 = 2026-11-07
        let (y, m, d) = civil_from_days(20764);
        assert_eq!((y, m, d), (2026, 11, 7));
    }

    #[test]
    fn snapshot_prunes_by_count() {
        let dir = std::env::temp_dir().join(format!("optical-hist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg_path = dir.join("optical.toml");
        let h = ConfigHistory::new(&cfg_path);
        let mut storage = StorageConfig {
            config_history_keep: 3,
            ..Default::default()
        };
        for i in 0..6 {
            h.record(&format!("[server]\nlisten = \"0.0.0.0:80{i}\"\n"), "test", &storage)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        storage.config_history_keep = 3;
        h.prune(&storage);
        assert!(h.list_meta().len() <= 3, "{}", h.list_meta().len());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_snapshot_skipped() {
        let dir = std::env::temp_dir().join(format!("optical-dup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let h = ConfigHistory::new(&dir.join("optical.toml"));
        let storage = StorageConfig::default();
        h.record("a = 1\n", "x", &storage).unwrap();
        h.record("a = 1\n", "x", &storage).unwrap();
        assert_eq!(h.list_meta().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_path_traversal_id() {
        let h = ConfigHistory::new(&PathBuf::from("/tmp/optical.toml"));
        assert!(h.read("../../etc/passwd").is_err());
        assert!(h.read("ok-20260101T000000Z-abcdef12.toml").is_err()); // 不存在，但不是路径错误
    }
}
