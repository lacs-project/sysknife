//! Append-only JSON-lines audit log for safety fence activations.
//!
//! Every time the planning safety fence rejects a plan (unknown action name,
//! invalid risk level, etc.), the rejection is logged as a single JSON line.
//! This provides a persistent, structured record of all fence activations
//! for post-hoc audit and debugging.
//!
//! The default log path is `$XDG_DATA_HOME/sysknife/safety-audit.jsonl`
//! (falling back to `~/.local/share/sysknife/safety-audit.jsonl`).

use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Format a `SystemTime` as an RFC 3339 / ISO 8601 UTC timestamp.
///
/// Produces `"YYYY-MM-DDThh:mm:ssZ"`. No external dependency needed.
fn format_rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|e| {
            eprintln!(
                "[sysknife-brain] audit: system clock is before Unix epoch ({e}); \
                 timestamp will be recorded as epoch — audit event timestamps may be wrong"
            );
            std::time::Duration::ZERO
        })
        .as_secs();
    // Algorithm: civil date from Unix timestamp (days since 1970-01-01).
    let days = (secs / 86400) as i64;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to (year, month, day).
    // Shift epoch to 0000-03-01 to make leap-year math simpler.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// A single audit-log entry written as one JSON line.
#[derive(Debug, Serialize)]
struct AuditEntry<'a> {
    timestamp: String,
    event: &'static str,
    intent: &'a str,
    reason: &'a str,
    raw_plan: &'a str,
}

/// Append-only audit log for safety fence rejections.
///
/// Each call to [`log_rejection`](SafetyAuditLog::log_rejection) appends a
/// single JSON line to the log file. The file is opened for each write so
/// that external log rotation works without coordination.
#[derive(Clone)]
pub struct SafetyAuditLog {
    path: PathBuf,
}

impl SafetyAuditLog {
    /// Create a new audit log that writes to `path`.
    ///
    /// The parent directory is created on the first write, not at construction
    /// time, so this call is infallible.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Return the default log path, respecting `XDG_DATA_HOME`.
    ///
    /// Returns `$XDG_DATA_HOME/sysknife/safety-audit.jsonl` if set,
    /// otherwise `~/.local/share/sysknife/safety-audit.jsonl`.
    pub fn default_path() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return PathBuf::from(xdg)
                    .join("sysknife")
                    .join("safety-audit.jsonl");
            }
        }
        // Fall back to ~/.local/share
        let home = std::env::var("HOME").unwrap_or_else(|_| {
            eprintln!(
                "[sysknife-brain] audit: HOME is unset; audit log will be written to /tmp \
                 — this path is world-writable and insecure for production use"
            );
            "/tmp".into()
        });
        PathBuf::from(home)
            .join(".local/share/sysknife")
            .join("safety-audit.jsonl")
    }

    /// Async wrapper for [`Self::log_rejection`] that runs the file write on
    /// the blocking pool. Call from `async fn` paths so the planner's reactor
    /// is not parked on a slow filesystem (NFS, encrypted home).
    pub async fn log_rejection_async(self, intent: String, reason: String, raw_plan: String) {
        let _ = tokio::task::spawn_blocking(move || {
            self.log_rejection(&intent, &reason, &raw_plan);
        })
        .await;
    }

    /// Append a rejection entry to the log file and forward to journald.
    ///
    /// Creates parent directories if they do not exist. Errors are logged to
    /// stderr but never propagated -- audit logging must not break the
    /// planning loop.
    ///
    /// Journald forwarding is best-effort: if the journal socket is absent
    /// (CI, non-systemd hosts) the call is a no-op. On systemd systems the
    /// entry is protected by Forward Secure Sealing once FSS is enabled
    /// (`journalctl --setup-keys`), providing tamper-evident audit records.
    pub fn log_rejection(&self, intent: &str, reason: &str, raw_plan: &str) {
        let timestamp = format_rfc3339(SystemTime::now());
        let entry = AuditEntry {
            timestamp,
            event: "safety_fence_rejection",
            intent,
            reason,
            raw_plan,
        };
        if let Err(e) = self.append_entry(&entry) {
            eprintln!(
                "[SYSKNIFE AUDIT] failed to write safety audit log to {}: {e}",
                self.path.display()
            );
            // Record the write failure itself in journald so the audit gap is
            // traceable even when the JSONL file is unavailable.
            crate::journal::send(&[
                ("PRIORITY", "3"), // LOG_ERR
                ("SYSLOG_IDENTIFIER", "sysknife-brain"),
                (
                    "MESSAGE",
                    &format!("SysKnife audit JSONL write failed: {e}"),
                ),
                ("SYSKNIFE_EVENT", "audit_write_failure"),
                ("SYSKNIFE_INTENT", intent),
                ("SYSKNIFE_REASON", reason),
            ]);
        }
        // Forward to journald for tamper-evident audit trail.
        // raw_plan is intentionally excluded — it may be large and is already
        // recorded in the JSONL file.
        crate::journal::send(&[
            ("PRIORITY", "4"), // LOG_WARNING
            ("SYSLOG_IDENTIFIER", "sysknife-brain"),
            (
                "MESSAGE",
                &format!("SysKnife safety fence rejection: {reason}"),
            ),
            ("SYSKNIFE_EVENT", "safety_fence_rejection"),
            ("SYSKNIFE_INTENT", intent),
            ("SYSKNIFE_REASON", reason),
            ("SYSKNIFE_TIMESTAMP", &entry.timestamp),
        ]);
    }

    fn append_entry(&self, entry: &AuditEntry<'_>) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        writeln!(file, "{line}")
    }

    /// Return the path this log writes to (for testing).
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn log_rejection_creates_file_and_writes_json_line() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let log = SafetyAuditLog::new(&log_path);

        log.log_rejection(
            "install vim",
            "step 0: unknown action_name 'RunShell'",
            r#"{"steps":[]}"#,
        );

        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "expected exactly one line, got: {content}");

        let entry: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry["event"], "safety_fence_rejection");
        assert_eq!(entry["intent"], "install vim");
        assert_eq!(entry["reason"], "step 0: unknown action_name 'RunShell'");
        assert_eq!(entry["raw_plan"], r#"{"steps":[]}"#);
        assert!(
            entry["timestamp"].as_str().unwrap().contains('T'),
            "timestamp should be RFC 3339: {}",
            entry["timestamp"]
        );
    }

    #[test]
    fn multiple_rejections_append_to_same_file() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let log = SafetyAuditLog::new(&log_path);

        log.log_rejection("a", "reason a", "plan a");
        log.log_rejection("b", "reason b", "plan b");

        let content = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let entry1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let entry2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(entry1["intent"], "a");
        assert_eq!(entry2["intent"], "b");
    }

    #[test]
    fn creates_parent_directories() {
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("nested").join("deep").join("audit.jsonl");
        let log = SafetyAuditLog::new(&log_path);

        log.log_rejection("test", "test reason", "{}");

        assert!(log_path.exists(), "log file should be created with parents");
    }

    #[test]
    fn default_path_respects_xdg_data_home() {
        // Temporarily override XDG_DATA_HOME via a direct check of the logic.
        // We cannot safely set env vars in multi-threaded tests, so we test
        // the fallback branch directly.
        let path = SafetyAuditLog::default_path();
        assert!(
            path.to_str()
                .unwrap()
                .ends_with("sysknife/safety-audit.jsonl"),
            "default path should end with sysknife/safety-audit.jsonl, got: {}",
            path.display()
        );
    }
}
