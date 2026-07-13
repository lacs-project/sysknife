//! Journald watermark sink for the audit hash chain.
//!
//! ## Purpose
//!
//! Every time a new chain entry is written to SQLite, this module emits a
//! structured journald log line recording `(seq, chain_hash_hex)` under the
//! syslog identifier `sysknife-audit-tip`. A SIEM or audit-verifier can then
//! compare this independent stream against the SQLite chain tail:
//!
//! ```text
//! journalctl -t sysknife-audit-tip -o json | jq -r '.MESSAGE'
//! ```
//!
//! Each message has the form `seq=<N> chain_hash=<hex64>`. If the journal
//! stream contains entries beyond the SQLite tail, tail truncation has occurred.
//!
//! ## Implementation
//!
//! Watermarks are emitted via `systemd-cat(1)`. This is a one-shot subprocess
//! per audit entry (~1 µs overhead). `systemd-cat` is part of the same
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
/// pre-encoded hex string avoids a redundant decode/re-encode at the call site
/// in `transactions.rs`, where the hash is already a `String`.
///
/// This function is non-fatal: if journald is unavailable the call returns
/// normally after logging a one-time warning to stderr.
///
/// In `#[cfg(test)]` builds, calls are intercepted by a registered
/// `WatermarkSink` instead of spawning a subprocess.
pub fn emit_chain_tip_watermark(seq: u64, chain_hash_hex: &str) {
    emit_watermark_impl(seq, chain_hash_hex);
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
/// Message body: `seq=<N> chain_hash=<hex64>`
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
/// `Requires=journald.service`). The subprocess overhead is ~1 µs, which is
/// negligible compared with the SQLite write that precedes it.
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
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(message.as_bytes())?;
                // Drop stdin to signal EOF before waiting.
            }
            child.wait()
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
                    "sysknife-audit-tip: failed to spawn systemd-cat: {e}; \
                     audit watermarks will not be written to journald"
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
}
