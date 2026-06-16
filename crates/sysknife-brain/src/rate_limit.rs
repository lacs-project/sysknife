//! Sliding-window per-minute rate limiter for the planning loop.
//!
//! `RateLimiter` persists call timestamps to a file so the limit survives
//! process restarts (e.g. the shell being re-opened mid-session).
//!
//! ### Failure mode
//!
//! IO errors on the backing file emit a warning to stderr but do not block the
//! call. Availability is preferred over rate-count precision: a transient
//! filesystem error should never block the user from planning. The warning
//! ensures operators can diagnose degraded rate limiting rather than
//! discovering it only through unexpected API costs.
//!
//! ### Cross-process safety
//!
//! `check_and_consume` holds an in-process `Mutex` lock for the duration of
//! its read-modify-append. This prevents double-counting within a single
//! process but does not protect against concurrent processes writing the same
//! file. SysKnife typically runs one shell at a time per user, so this is not a
//! practical concern. For deployment scenarios that need cross-process
//! correctness, replace the `Mutex` with an advisory `flock`.

use std::fmt;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Sliding 60-second window rate limiter backed by a plain-text timestamp file.
///
/// Create via [`RateLimiter::new`]; attach to a planner with
/// [`LlmPlanner::with_rate_limiter`](crate::planner::LlmPlanner::with_rate_limiter).
///
/// ### Environment variable
///
/// `SYSKNIFE_MAX_RPM` overrides `max_per_minute` at runtime:
///
/// ```sh
/// SYSKNIFE_MAX_RPM=5 sysknife "check disk usage"
/// ```
///
/// Values that cannot be parsed as `usize`, or that parse to zero, fall back
/// to the constructor value. Setting `SYSKNIFE_MAX_RPM=0` is rejected — zero
/// would permanently block all planning calls.
pub struct RateLimiter {
    path: PathBuf,
    max_per_minute: usize,
    /// In-process lock to serialise read-modify-append.
    lock: Mutex<()>,
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("path", &self.path)
            .field("max_per_minute", &self.max_per_minute)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `path`: where timestamps are stored (created on first call if absent).
    /// - `max_per_minute`: calls allowed per 60-second sliding window. Must be
    ///   at least 1; panics otherwise.
    ///   Reads `SYSKNIFE_MAX_RPM` from the environment and uses it if parseable and
    ///   non-zero, otherwise uses `max_per_minute`.
    ///
    /// # Panics
    ///
    /// Panics if `max_per_minute` is zero.
    pub fn new(path: PathBuf, max_per_minute: usize) -> Self {
        assert!(max_per_minute >= 1, "max_per_minute must be at least 1");
        let effective = std::env::var("SYSKNIFE_MAX_RPM")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .unwrap_or(max_per_minute);
        Self {
            path,
            max_per_minute: effective,
            lock: Mutex::new(()),
        }
    }

    /// Async wrapper that runs `check_and_consume` on the blocking pool.
    ///
    /// Use this from `async fn` paths.  The body holds a `Mutex` guard while
    /// reading and writing the on-disk timestamp file; on a slow or contended
    /// filesystem (NFS, encrypted home) this can take long enough that
    /// blocking the tokio reactor would stall every other in-flight task.
    pub async fn check_and_consume_async(self: std::sync::Arc<Self>) -> Result<(), u64> {
        tokio::task::spawn_blocking(move || self.check_and_consume())
            .await
            .unwrap_or_else(|e| {
                // Join error means the blocking thread panicked. Fail open —
                // the rate limit is a soft guard, not a security boundary.
                eprintln!(
                    "[sysknife-brain] rate-limit: blocking task panicked: {e} — failing open"
                );
                Ok(())
            })
    }

    /// Check whether the caller is within the rate window and, if so, record
    /// this call.
    ///
    /// Returns `Ok(())` when the call is allowed, or `Err(retry_after_secs)`
    /// when the window is full. `retry_after_secs` is the number of seconds
    /// until the oldest call in the current window ages out (always >= 1).
    ///
    /// Prefer `check_and_consume_async` from `async fn` call sites.
    pub fn check_and_consume(&self) -> Result<(), u64> {
        let _guard = self.lock.lock().unwrap_or_else(|e| {
            eprintln!(
                "[sysknife-brain] rate-limit: Mutex was poisoned (a prior thread panicked \
                 in the critical section); recovering — timestamp file may be inconsistent"
            );
            e.into_inner()
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| {
                eprintln!(
                    "[sysknife-brain] rate-limit: system clock appears to be before \
                     Unix epoch: {e} — rate limit may behave unexpectedly"
                );
                std::time::Duration::ZERO
            })
            .as_secs();
        let window_start = now.saturating_sub(60);

        // Read and parse existing timestamps; silently ignore malformed lines.
        let raw = std::fs::read_to_string(&self.path).unwrap_or_else(|e| {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "[sysknife-brain] rate-limit: failed to read timestamp file {}: {e} \
                     — rate limiting is degraded for this call",
                    self.path.display()
                );
            }
            String::new()
        });

        // Separate in-window timestamps from expired ones.
        let (in_window, expired): (Vec<u64>, Vec<u64>) = raw
            .lines()
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .partition(|&t| t >= window_start);

        if in_window.len() >= self.max_per_minute {
            let oldest = in_window.iter().min().copied().unwrap_or(window_start);
            // How long until the oldest call exits the 60-second window.
            let retry_after = (oldest + 60).saturating_sub(now).max(1);
            return Err(retry_after);
        }

        // Write back compacted set (in-window + new timestamp) to keep the
        // file bounded. Expired entries are dropped.
        let _ = expired; // explicitly consumed above
        let mut new_content = String::with_capacity(in_window.len() * 12 + 12);
        for ts in &in_window {
            new_content.push_str(&ts.to_string());
            new_content.push('\n');
        }
        new_content.push_str(&now.to_string());
        new_content.push('\n');

        // Write via a temp file + rename for crash safety, falling back to
        // direct write if the parent directory's temp file creation fails.
        let write_result = if let Some(parent) = self.path.parent() {
            tempfile::NamedTempFile::new_in(parent).and_then(|mut tmp| {
                tmp.write_all(new_content.as_bytes())?;
                tmp.persist(&self.path).map_err(|e| e.error)?;
                Ok(())
            })
        } else {
            std::fs::write(&self.path, &new_content)
        };

        if let Err(e) = write_result {
            eprintln!(
                "[sysknife-brain] rate-limit: failed to persist call timestamp to {}: {e} \
                 — this call is allowed but the rate count may be inaccurate",
                self.path.display()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Serialise env-var mutations so parallel test threads don't interfere.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn first_call_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 10);
        assert!(rl.check_and_consume().is_ok());
    }

    #[test]
    fn calls_up_to_limit_all_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 3);
        for i in 0..3 {
            assert!(
                rl.check_and_consume().is_ok(),
                "call {i} should be within limit"
            );
        }
    }

    #[test]
    fn call_over_limit_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 2);
        rl.check_and_consume().unwrap();
        rl.check_and_consume().unwrap();
        let result = rl.check_and_consume();
        assert!(
            result.is_err(),
            "third call on limit-2 limiter must return Err"
        );
    }

    #[test]
    fn retry_after_is_at_least_one() {
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 1);
        rl.check_and_consume().unwrap();
        let retry = rl.check_and_consume().unwrap_err();
        assert!(retry >= 1, "retry_after must be >= 1, got {retry}");
    }

    #[test]
    fn absent_file_treated_as_empty() {
        // Path in temp dir but never created — should succeed as if no prior calls.
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("nonexistent.txt"), 5);
        assert!(rl.check_and_consume().is_ok());
    }

    #[test]
    fn expired_timestamps_do_not_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rl.txt");
        // Write timestamps from 90 seconds ago — all outside the 60-s window.
        let stale = now_secs().saturating_sub(90);
        let content = format!("{stale}\n{stale}\n{stale}\n");
        std::fs::write(&path, &content).unwrap();

        let rl = RateLimiter::new(path, 1);
        // The 3 stale entries must not count; first fresh call should succeed.
        assert!(
            rl.check_and_consume().is_ok(),
            "stale timestamps must not consume quota"
        );
    }

    #[test]
    fn in_window_timestamps_count_toward_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rl.txt");
        // Write 2 timestamps from 5 seconds ago — both inside the window.
        let recent = now_secs().saturating_sub(5);
        let content = format!("{recent}\n{recent}\n");
        std::fs::write(&path, &content).unwrap();

        let rl = RateLimiter::new(path, 2);
        // Already at limit — next call must fail.
        let result = rl.check_and_consume();
        assert!(
            result.is_err(),
            "pre-filled in-window timestamps must count"
        );
    }

    #[test]
    fn env_var_overrides_constructor_limit() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_MAX_RPM", "1") };
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 100);
        // Effective limit is 1 (from env), not 100.
        rl.check_and_consume().unwrap();
        let result = rl.check_and_consume();
        unsafe { std::env::remove_var("SYSKNIFE_MAX_RPM") };
        assert!(result.is_err(), "env var SYSKNIFE_MAX_RPM=1 must cap at 1");
    }

    #[test]
    fn zero_env_var_falls_back_to_constructor() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_MAX_RPM", "0") };
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 5);
        // 0 is rejected; effective limit is 5.
        unsafe { std::env::remove_var("SYSKNIFE_MAX_RPM") };
        for i in 0..5 {
            assert!(
                rl.check_and_consume().is_ok(),
                "call {i} must be within limit-5"
            );
        }
        assert!(
            rl.check_and_consume().is_err(),
            "6th call must exceed limit-5"
        );
    }

    #[test]
    fn invalid_env_var_falls_back_to_constructor() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_MAX_RPM", "not_a_number") };
        let dir = tempfile::tempdir().unwrap();
        let rl = RateLimiter::new(dir.path().join("rl.txt"), 3);
        unsafe { std::env::remove_var("SYSKNIFE_MAX_RPM") };
        // Effective limit is 3 (constructor fallback).
        for i in 0..3 {
            assert!(rl.check_and_consume().is_ok(), "call {i} within limit-3");
        }
        assert!(
            rl.check_and_consume().is_err(),
            "4th call must exceed limit-3"
        );
    }

    #[test]
    #[should_panic(expected = "max_per_minute must be at least 1")]
    fn zero_max_per_minute_panics() {
        let dir = tempfile::tempdir().unwrap();
        RateLimiter::new(dir.path().join("rl.txt"), 0);
    }
}
