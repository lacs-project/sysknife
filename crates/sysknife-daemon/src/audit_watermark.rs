//! Journald watermark sink for the audit hash chain.
//!
//! ## Purpose
//!
//! Every time a new chain entry is committed to the configured transaction
//! backend (SQLite or PostgreSQL), this module emits a structured journald log
//! line recording `(seq, chain_hash_hex)` under the syslog identifier
//! `sysknife-audit-tip`. A SIEM or audit-verifier can then compare this
//! independent stream against the stored chain tail:
//!
//! ```text
//! journalctl -t sysknife-audit-tip -o json | jq -r '.MESSAGE'
//! ```
//!
//! Each message has the form `seq=<N> chain_hash=<hex128>` — `chain_hash` is a
//! hex-encoded Ed25519 signature (64 raw bytes → 128 hex chars), not a
//! SHA-256 digest. If the journal
//! stream contains entries beyond the SQLite tail, tail truncation has occurred.
//!
//! ## Implementation
//!
//! Watermarks are emitted via `systemd-cat(1)`. This is a one-shot subprocess
//! per audit entry, with a two-second deadline for its exit. PostgreSQL runs
//! the blocking emission on Tokio's blocking pool; SQLite already emits from
//! its blocking store worker. `systemd-cat` is part of the same
//! `systemd` package as journald — its presence is guaranteed on any host that
//! runs the daemon. No new Cargo dependency is required.
//!
//! ## Failure policy
//!
//! Failure to write to journald is **non-fatal** — we never want a chain
//! mutation to roll back because journald is unavailable. Failures are logged
//! to stderr once per process via [`std::sync::OnceLock`] so the operator is
//! notified without log spam.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

const SYSTEMD_CAT_TIMEOUT: Duration = Duration::from_secs(2);

/// Syslog identifier for all watermark journal entries.
///
/// Query with: `journalctl -t sysknife-audit-tip`
pub const WATERMARK_SYSLOG_ID: &str = "sysknife-audit-tip";

/// Printed to stderr at most once per process when journald is unavailable.
static WARNED_JOURNALD_UNAVAILABLE: OnceLock<()> = OnceLock::new();

/// Emit a structured journald entry recording the latest chain tip.
///
/// `chain_hash_hex` must be the hex-encoded Ed25519 signature of the newly
/// inserted chain row — exactly as stored in the `chain_hash` column. Passing a
/// pre-encoded hex string avoids a redundant decode/re-encode at the call sites
/// (`transactions.rs` for SQLite and `store/postgres.rs` for PostgreSQL), where
/// the hash is already a `String`.
///
/// This function is non-fatal: if journald is unavailable the call returns
/// normally after logging a one-time warning to stderr.
///
/// In `#[cfg(test)]` builds, calls are intercepted by a registered
/// `WatermarkSink` instead of spawning a subprocess.
pub fn emit_chain_tip_watermark(seq: u64, chain_hash_hex: &str) {
    emit_watermark_impl(seq, chain_hash_hex);
}

/// Emit after an async store commit without parking a Tokio runtime worker.
/// A failed blocking task must not turn an already-committed write into an error.
pub(crate) async fn emit_chain_tip_watermark_async(seq: u64, chain_hash_hex: String) {
    if let Err(error) = tokio::task::spawn_blocking(move || {
        emit_chain_tip_watermark(seq, &chain_hash_hex);
    })
    .await
    {
        WARNED_JOURNALD_UNAVAILABLE.get_or_init(|| {
            eprintln!(
                "sysknife-audit-tip: watermark task failed: {error}; audit watermark skipped"
            );
        });
    }
}

/// Production implementation: shell out to `systemd-cat`.
#[cfg(not(test))]
fn emit_watermark_impl(seq: u64, hash_hex: &str) {
    emit_via_systemd_cat(seq, hash_hex);
}

/// Test implementation: push to the registered sink, falling back to the real
/// implementation when no sink is installed.
#[cfg(test)]
fn emit_watermark_impl(seq: u64, hash_hex: &str) {
    if let Some(sink) = TEST_SINK.get() {
        let mut guard = sink.lock().expect("test sink mutex poisoned");
        guard.push(WatermarkCall {
            seq,
            chain_hash_hex: hash_hex.to_string(),
        });
    } else {
        emit_via_systemd_cat(seq, hash_hex);
    }
}

/// Shell out to `systemd-cat` to write the watermark into the journal.
///
/// Message body: `seq=<N> chain_hash=<hex128>` (a hex-encoded Ed25519
/// signature — 64 raw bytes, so 128 hex chars, not a 64-char SHA-256 digest).
///
/// The fields are embedded in the human-readable message body so they survive
/// forwarding setups that strip structured journal metadata. SIEMs filter on
/// `SYSLOG_IDENTIFIER=sysknife-audit-tip` and then parse the `seq=…` /
/// `chain_hash=…` tokens.
///
/// ## Why `systemd-cat` and not `sd_journal_sendv` FFI?
///
/// No Rust crate wrapping `libsystemd` is present in the workspace, and the
/// spec forbids adding new Cargo dependencies. `systemd-cat` is part of the
/// same `systemd` package as journald itself — its presence is guaranteed on
/// any host that runs the daemon (the daemon's `.service` unit explicitly
/// `Requires=journald.service`). Spawning a process and contacting journald
/// have variable cost. After two seconds we kill and reap the child instead of
/// waiting indefinitely. Async callers must use the blocking-pool wrapper.
fn emit_via_systemd_cat(seq: u64, hash_hex: &str) {
    use std::io::Write as _;

    let message = format!("seq={seq} chain_hash={hash_hex}");

    let result = std::process::Command::new("systemd-cat")
        .args(["-t", WATERMARK_SYSLOG_ID, "-p", "info"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            let deadline = Instant::now() + SYSTEMD_CAT_TIMEOUT;
            // The write result is captured rather than propagated with `?`,
            // because `Child::drop` does not reap: an early return here would
            // leak a zombie on every audit record. This runs on every preview
            // and every execute, so a journald outage used to burn one PID per
            // chain insert until the table filled and the daemon could no
            // longer fork — i.e. could no longer execute privileged actions.
            let write_result = match child.stdin.take() {
                Some(mut stdin) => stdin.write_all(message.as_bytes()),
                // Dropping the handle signals EOF before we wait.
                None => Ok(()),
            };
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "systemd-cat timed out after 2 seconds; child killed and reaped",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            write_result.map(|()| status)
        });

    match result {
        Ok(status) if status.success() => {}
        Ok(status) => {
            WARNED_JOURNALD_UNAVAILABLE.get_or_init(|| {
                eprintln!(
                    "sysknife-audit-tip: systemd-cat exited with {status}; \
                     audit watermarks will not be written to journald"
                );
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            WARNED_JOURNALD_UNAVAILABLE.get_or_init(|| {
                eprintln!(
                    "sysknife-audit-tip: systemd-cat not found on PATH; \
                     audit watermarks will not be written to journald"
                );
            });
        }
        Err(e) => {
            WARNED_JOURNALD_UNAVAILABLE.get_or_init(|| {
                eprintln!(
                    "sysknife-audit-tip: failed to emit via systemd-cat: {e}; \
                     audit watermark skipped"
                );
            });
        }
    }
}

// ── Test infrastructure ───────────────────────────────────────────────────────

/// A single recorded call to [`emit_chain_tip_watermark`].
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkCall {
    pub seq: u64,
    pub chain_hash_hex: String,
}

/// Thread-safe collection of recorded watermark calls.
#[cfg(test)]
pub type WatermarkSink = std::sync::Arc<std::sync::Mutex<Vec<WatermarkCall>>>;

/// Process-wide test sink. Set once per test process via [`install_test_sink`].
#[cfg(test)]
static TEST_SINK: OnceLock<WatermarkSink> = OnceLock::new();

/// Install `sink` as the process-wide watermark recorder.
///
/// Must be called before any code path that invokes
/// [`emit_chain_tip_watermark`]. Because [`OnceLock`] can only be set once per
/// process, tests that use this helper must not run concurrently with each
/// other (use `#[serial_test::serial]` or run under `cargo nextest` which
/// isolates each test in its own process).
#[cfg(test)]
pub fn install_test_sink(sink: WatermarkSink) {
    TEST_SINK
        .set(sink)
        .expect("watermark test sink already installed in this process");
}

/// Drain all recorded watermark calls from `sink`.
#[cfg(test)]
pub fn take_watermarks(sink: &WatermarkSink) -> Vec<WatermarkCall> {
    sink.lock()
        .expect("test sink mutex poisoned")
        .drain(..)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn new_sink() -> WatermarkSink {
        Arc::new(Mutex::new(Vec::new()))
    }

    /// Watermark SYSLOG_ID constant must match the documented operator command.
    #[test]
    fn syslog_identifier_constant_is_correct() {
        assert_eq!(WATERMARK_SYSLOG_ID, "sysknife-audit-tip");
    }

    /// Direct push into sink captures seq and hex correctly.
    #[test]
    fn sink_records_seq_and_hex() {
        let sink = new_sink();
        {
            let mut guard = sink.lock().unwrap();
            guard.push(WatermarkCall {
                seq: 7,
                chain_hash_hex: "abcd".to_string(),
            });
        }
        let calls = take_watermarks(&sink);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].seq, 7);
        assert_eq!(calls[0].chain_hash_hex, "abcd");
    }

    /// `take_watermarks` drains the sink — a second call returns empty.
    #[test]
    fn take_watermarks_drains_sink() {
        let sink = new_sink();
        sink.lock().unwrap().push(WatermarkCall {
            seq: 1,
            chain_hash_hex: "ff".to_string(),
        });
        let first = take_watermarks(&sink);
        let second = take_watermarks(&sink);
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
    }

    #[cfg(unix)]
    mod subprocess {
        use super::*;
        use std::os::unix::{fs::PermissionsExt, process::CommandExt};
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        // Run each case in its own process: changing PATH in the test runner
        // would race unrelated tests and the process-wide watermark sink.
        fn run_with_stub(case: &str, script: &str) -> Option<(String, String)> {
            if std::env::var("SYSKNIFE_WATERMARK_TEST").as_deref() == Ok(case) {
                return None;
            }
            let dir = tempfile::tempdir().unwrap();
            let stub = dir.path().join("systemd-cat");
            std::fs::write(&stub, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700)).unwrap();
            let stderr_path = dir.path().join("stderr");
            let message_path = dir.path().join("message");
            let mut paths = vec![dir.path().to_path_buf()];
            paths.extend(std::env::split_paths(
                &std::env::var_os("PATH").unwrap_or_default(),
            ));
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("audit_watermark::tests::subprocess::{case}"),
                    "--nocapture",
                ])
                .env("SYSKNIFE_WATERMARK_TEST", case)
                .env("PATH", std::env::join_paths(paths).unwrap())
                .env("WATERMARK_MESSAGE_FILE", &message_path)
                .env("WATERMARK_PID_FILE", dir.path().join("pid"))
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&stderr_path).unwrap())
                .process_group(0)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(6);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            // Clean up the isolated runner and its stub even if the production
            // timeout is removed. The test must fail, never hang for 30 seconds.
            // SAFETY: process_group(0) gave this child its own group; no process
            // in the parent test runner's group can receive this signal.
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            child.wait().unwrap();
            let stderr = std::fs::read_to_string(stderr_path).unwrap();
            assert!(
                status.is_some(),
                "watermark exceeded the independent 6s watchdog: {stderr}"
            );
            assert!(
                status.unwrap().success(),
                "watermark subprocess failed: {stderr}"
            );
            Some((
                stderr,
                std::fs::read_to_string(message_path).unwrap_or_default(),
            ))
        }

        #[test]
        fn stalled_child_is_killed_and_reaped() {
            if let Some((stderr, _)) = run_with_stub(
                "stalled_child_is_killed_and_reaped",
                "printf '%s' \"$$\" > \"$WATERMARK_PID_FILE\"\nexec sleep 30",
            ) {
                assert!(stderr.contains("timed out"), "{stderr}");
                return;
            }
            let started = Instant::now();
            emit_via_systemd_cat(7, &"ab".repeat(64));
            assert!(started.elapsed() < Duration::from_secs(5));
            let pid: i32 = std::fs::read_to_string(std::env::var_os("WATERMARK_PID_FILE").unwrap())
                .unwrap()
                .parse()
                .unwrap();
            // SAFETY: signal 0 only probes whether the recorded child exists.
            assert_eq!(
                unsafe { libc::kill(pid, 0) },
                -1,
                "stub is still alive or unreaped"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }

        #[test]
        fn successful_child_receives_watermark_and_eof() {
            if let Some((stderr, message)) = run_with_stub(
                "successful_child_receives_watermark_and_eof",
                "[ \"$*\" = '-t sysknife-audit-tip -p info' ] || exit 2\ncat > \"$WATERMARK_MESSAGE_FILE\"",
            ) {
                assert_eq!(message, format!("seq=7 chain_hash={}", "ab".repeat(64)));
                assert!(!stderr.contains("sysknife-audit-tip:"), "{stderr}");
                return;
            }
            emit_via_systemd_cat(7, &"ab".repeat(64));
        }

        #[test]
        fn child_failure_is_nonfatal_and_warns_once() {
            if let Some((stderr, _)) = run_with_stub(
                "child_failure_is_nonfatal_and_warns_once",
                "cat > /dev/null\nexit 23",
            ) {
                assert_eq!(
                    stderr.matches("systemd-cat exited with").count(),
                    1,
                    "{stderr}"
                );
                return;
            }
            emit_via_systemd_cat(7, &"ab".repeat(64));
            emit_via_systemd_cat(8, &"cd".repeat(64));
        }

        #[tokio::test(flavor = "current_thread")]
        async fn stalled_child_does_not_block_runtime() {
            if let Some((stderr, _)) =
                run_with_stub("stalled_child_does_not_block_runtime", "exec sleep 30")
            {
                assert!(stderr.contains("timed out"), "{stderr}");
                return;
            }
            let started = Instant::now();
            let watermark = emit_chain_tip_watermark_async(7, "ab".repeat(64));
            let heartbeat = async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(
                    started.elapsed() < Duration::from_secs(1),
                    "a stalled watermark blocked the single-threaded executor"
                );
            };
            tokio::join!(watermark, heartbeat);
        }
    }
}
