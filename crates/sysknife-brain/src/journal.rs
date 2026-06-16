//! Minimal journald sender — no external dependencies.
//!
//! Sends structured log entries to systemd-journald via the native Unix
//! datagram socket protocol. Falls back silently if journald is unavailable
//! (non-systemd hosts, containers without the journal socket, unit tests, CI).
//!
//! # Protocol
//!
//! Each field is encoded as either:
//! - **Simple** (no newlines in value): `KEY=VALUE\n`
//! - **Binary** (value contains `\n`):  `KEY\n<u64-LE byte count><value bytes>\n`
//!
//! The complete message is sent as a single Unix datagram to
//! `/run/systemd/journal/socket`.
//!
//! # Tamper detection
//!
//! Once journald receives an entry it is protected by systemd's Forward Secure
//! Sealing (FSS). Enable FSS at deployment time with:
//!
//! ```text
//! journalctl --setup-keys
//! ```
//!
//! Verify log integrity with `journalctl --verify`. Forward Secure Sealing
//! is one of the mechanisms operators commonly cite when meeting their
//! tamper-evident audit-trail obligations under ISO/IEC 42001, SOC 2, and
//! similar frameworks; the standards themselves do not mandate FSS
//! specifically.

use std::os::unix::net::UnixDatagram;
use std::path::Path;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// Send a structured log entry to journald.
///
/// `fields` is a slice of `(KEY, VALUE)` pairs. Keys should be uppercase ASCII
/// with underscores (`[A-Z0-9_]+`). Any value that contains a newline is
/// encoded using the binary protocol automatically.
///
/// If the journal socket exists but the write fails (e.g. permission error,
/// datagram too large, SELinux label mismatch), a warning is printed to stderr
/// so operators can distinguish "socket absent" (expected) from "socket present
/// but write failed" (misconfiguration). The caller's own log (JSONL, SQLite)
/// remains the authoritative record.
pub fn send(fields: &[(&str, &str)]) {
    if let Err(e) = try_send(fields) {
        // Only warn when the socket is present — an absent socket is expected
        // on non-systemd hosts and in CI.
        if Path::new(JOURNAL_SOCKET).exists() {
            eprintln!(
                "[sysknife-brain] journald send failed (socket present but write \
                 errored): {e} — security events may not reach the journal"
            );
        }
    }
}

fn try_send(fields: &[(&str, &str)]) -> std::io::Result<()> {
    if !Path::new(JOURNAL_SOCKET).exists() {
        return Ok(());
    }

    let mut msg: Vec<u8> = Vec::new();
    for (key, value) in fields {
        if value.contains('\n') {
            // Binary encoding for multi-line values.
            msg.extend_from_slice(key.as_bytes());
            msg.push(b'\n');
            let len = value.len() as u64;
            msg.extend_from_slice(&len.to_le_bytes());
            msg.extend_from_slice(value.as_bytes());
            msg.push(b'\n');
        } else {
            msg.extend_from_slice(key.as_bytes());
            msg.push(b'=');
            msg.extend_from_slice(value.as_bytes());
            msg.push(b'\n');
        }
    }

    let sock = UnixDatagram::unbound()?;
    sock.send_to(&msg, JOURNAL_SOCKET)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_is_noop_when_journal_socket_absent() {
        // In most test environments (CI, non-systemd hosts) the journal socket
        // is not present. send() must complete without panicking.
        send(&[
            ("PRIORITY", "4"),
            ("SYSLOG_IDENTIFIER", "sysknife-brain"),
            ("MESSAGE", "unit test — journald not required"),
            ("SYSKNIFE_EVENT", "unit_test"),
        ]);
    }

    #[test]
    fn send_handles_multiline_value_without_panic() {
        // Even if the socket is absent, multiline encoding must not panic.
        send(&[
            ("PRIORITY", "4"),
            ("MESSAGE", "line one\nline two"),
            ("SYSKNIFE_EVENT", "unit_test"),
        ]);
    }
}
