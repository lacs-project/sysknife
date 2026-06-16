//! External audit log forwarding (RFC 5424 syslog over UDP).
//!
//! After each `transactions` row is recorded, the daemon hands a structured
//! `AuditEvent` to a per-sink forwarder task over a bounded
//! [`tokio::sync::mpsc::channel`]. The forwarder formats the event per the
//! configured wire protocol and emits it. **Forwarding is fire-and-forget**:
//! channel send failures (`try_send` returning `Full`/`Closed`) increment a
//! drop counter and emit an `eprintln!` warning after `DROP_WARN_THRESHOLD`
//! consecutive drops; the audit-log INSERT path itself never awaits or fails.
//!
//! ## Wire protocols
//!
//! Phase 1 ships **RFC 5424 syslog over UDP**, the de-facto on-host
//! log-forwarding format. Direct ingestion works with Splunk, Elastic,
//! IBM QRadar, and rsyslog; vendors that require a forwarder agent
//! (Microsoft Sentinel via the Azure Monitor Agent on a Linux VM,
//! Datadog/Chronicle via their own collectors) consume the same stream
//! through that agent. CEF and NDJSON-over-TCP are designed-for in
//! [`AuditSinkSpec`] and arrive in follow-up PRs.
//!
//! ## Reliability vs durability
//!
//! - **Local audit-log INSERT** (HMAC-SHA256 hash-chained — see
//!   [`audit_chain`](crate::audit_chain)) is the durable record.
//! - **External forwarding** is best-effort. A SIEM outage, a routing flap, or
//!   a misconfigured collector must NEVER block daemon execution.
//! - We do not retry the *send* in-process: a frame that the kernel could not
//!   hand to the SIEM is dropped and the next event continues.  Bind failures
//!   *are* retried with exponential backoff (1s → 60s) so a transient outage
//!   does not poison the socket forever, but neither path tries to replay the
//!   missed event — the SIEM is the long-lived accumulator and the local
//!   hash-chained log will catch up the operator on the next ingest.  (A
//!   future "tail watermark + replay" Phase 2 bridge can reconcile gaps from
//!   the local log.)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sysknife_types::RiskLevel;
use tokio::sync::mpsc;

/// Bounded queue depth between daemon and forwarder. Sized for ~5 minutes of
/// audit events at the daemon's sustainable record rate (well below SIEM
/// ingest); a sustained burst that overflows is a SIEM outage and we drop
/// (with counter + WARN) rather than back-pressure the audit-log writer.
pub const FORWARDER_QUEUE_DEPTH: usize = 4096;

/// Emit a single WARN to stderr after this many consecutive `try_send` drops.
/// Counter resets on a successful send.
pub const DROP_WARN_THRESHOLD: u64 = 8;

/// Configuration for one forwarding sink.
#[derive(Clone, Debug)]
pub enum AuditSinkSpec {
    /// RFC 5424 syslog over UDP. Sends each event as a single datagram.
    SyslogUdp {
        /// Host:port of the receiver, e.g. `"siem.internal:514"`.
        host: SocketAddr,
        /// Syslog facility (default `1` = user-level messages).
        facility: u8,
    },
}

/// One audit event handed to the forwarder. Mirrors the chain content
/// captured at INSERT time so SIEM rules can correlate by `transaction_id`
/// and `request_hash` against the local hash-chained log.
///
/// `final_status` is `None` for the preview-time event (no terminal state yet)
/// and `Some` for the execute-time event emitted after `update_status`. SOC
/// analysts watching the SIEM can therefore tell from the same event stream
/// whether an action ran, succeeded, failed, or was rolled back.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub seq: u64,
    pub transaction_id: String,
    pub action_name: String,
    pub risk_level: RiskLevel,
    pub summary: String,
    pub approval_id: Option<String>,
    pub created_at: String,
    pub chain_hash: String,
    pub key_id: String,
    pub caller_role: Option<String>,
    pub final_status: Option<String>,
}

/// A handle the daemon writes to. Cheap to clone (Arc-wrapped sender +
/// counter). Returns immediately on `submit`.
#[derive(Clone)]
pub struct AuditForwarder {
    sender: mpsc::Sender<AuditEvent>,
    drops: Arc<AtomicU64>,
}

impl std::fmt::Debug for AuditForwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditForwarder")
            .field("queue_capacity", &self.sender.capacity())
            .field("queue_max", &self.sender.max_capacity())
            .field("drops", &self.drops.load(Ordering::Relaxed))
            .finish()
    }
}

impl AuditForwarder {
    /// Submit an event for forwarding. Never blocks. Drops the event if the
    /// channel is full or closed; consecutive drops emit a WARN after
    /// [`DROP_WARN_THRESHOLD`].
    pub fn submit(&self, event: AuditEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {
                // Reset drop counter on a successful submit so the next
                // outage emits a fresh WARN.
                self.drops.store(0, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let prev = self.drops.fetch_add(1, Ordering::Relaxed);
                if (prev + 1) == DROP_WARN_THRESHOLD {
                    eprintln!(
                        "[sysknife-daemon] audit-forward: queue full, dropping events \
                         (>= {DROP_WARN_THRESHOLD} consecutive); is the SIEM reachable?"
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The forwarder task has shut down. One-time WARN to stderr;
                // subsequent submits silently no-op.
                let prev = self.drops.fetch_add(1, Ordering::Relaxed);
                if prev == 0 {
                    eprintln!(
                        "[sysknife-daemon] audit-forward: forwarder task is gone; \
                         further submits will be dropped silently"
                    );
                }
            }
        }
    }

    /// Total events dropped since the last successful submit. Test-only.
    #[cfg(test)]
    pub fn drop_count(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }
}

/// Spawn a forwarder task that consumes events from `rx` and sends them to
/// `spec`. Returns the [`AuditForwarder`] handle the daemon writes to.
///
/// On task exit (channel closed by all senders dropping), the task returns
/// silently. There is no graceful drain — pending events in the channel are
/// dropped at shutdown. Audit durability is guaranteed by the local
/// hash-chained log, not by the forwarder.
pub fn spawn(spec: AuditSinkSpec) -> AuditForwarder {
    let (tx, rx) = mpsc::channel(FORWARDER_QUEUE_DEPTH);
    let drops = Arc::new(AtomicU64::new(0));
    tokio::spawn(forwarder_task(spec, rx));
    AuditForwarder { sender: tx, drops }
}

async fn forwarder_task(spec: AuditSinkSpec, mut rx: mpsc::Receiver<AuditEvent>) {
    match spec {
        AuditSinkSpec::SyslogUdp { host, facility } => {
            let mut socket = open_udp(host).await;
            // Exponential backoff on consecutive bind failures so a transient
            // outage does not produce a tight retry loop that pegs a CPU.
            // See `next_backoff_secs` for the doubling sequence and
            // `MAX_BACKOFF_SECS` for why the cap lives where it does.  Reset
            // to `INITIAL_BACKOFF_SECS` on the first successful bind.
            let mut backoff_secs: u64 = INITIAL_BACKOFF_SECS;
            while let Some(event) = rx.recv().await {
                let frame = format_rfc5424(&event, facility);
                // **Event-drop semantics:** if the socket is `None` (bind has
                // never succeeded, or a previous send failed and we have not
                // yet rebound) the formatted frame is computed and then
                // dropped. The local hash-chained audit log already has a
                // durable copy of the same row, so the SIEM gap is by
                // design — a future "tail watermark + replay" Phase 2 bridge
                // can backfill from the local log.
                if let Some(s) = &socket {
                    if let Err(e) = s.send_to(frame.as_bytes(), host).await {
                        eprintln!(
                            "[sysknife-daemon] audit-forward: UDP send to {host} failed: {e} \
                             — dropping socket and reopening (current event is lost)"
                        );
                        socket = None;
                    }
                }
                if socket.is_none() {
                    socket = open_udp(host).await;
                    if socket.is_none() {
                        // Bind failure: sleep with exponential backoff before
                        // we attempt again on the next event. Without this,
                        // a misconfigured host with a packed channel would
                        // pin a CPU at 100% on `eprintln!` syscalls.
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs = next_backoff_secs(backoff_secs);
                    } else {
                        backoff_secs = 1;
                    }
                }
            }
        }
    }
}

/// Maximum wait between consecutive bind-failure retries, in seconds.
///
/// Once the exponential backoff hits this ceiling it stays there.  Without a
/// cap, a long-running SIEM outage would silently grow the retry interval
/// into hours (1h ≈ 3600s, the doubling sequence reaches that after only a
/// few minutes) — operators would think forwarding had quietly stopped
/// rather than seeing minute-by-minute reattempts. 60s is the smallest
/// value where:
///
///   1. The retry rate is well below the threshold that pegs a CPU on
///      bind/`eprintln!` syscalls in a tight loop, and
///   2. A normally-functioning SIEM coming back online recovers within one
///      ingest interval (most SIEMs ingest at ≤ 60s granularity already).
const MAX_BACKOFF_SECS: u64 = 60;

/// Initial wait after the first bind failure, in seconds.  The doubling
/// sequence resets to this value after every successful bind.
const INITIAL_BACKOFF_SECS: u64 = 1;

/// Compute the next exponential-backoff wait, capped at [`MAX_BACKOFF_SECS`].
///
/// Sequence: `1 → 2 → 4 → 8 → 16 → 32 → MAX → MAX → …`.  Extracted from
/// `forwarder_task` so the math can be unit-tested without driving a real
/// tokio runtime.
fn next_backoff_secs(prev: u64) -> u64 {
    prev.saturating_mul(2).min(MAX_BACKOFF_SECS)
}

/// Bind a fresh ephemeral UDP socket whose address family matches `host`.
///
/// IPv4 host → bind on `0.0.0.0:0`; IPv6 host → bind on `[::]:0`. Without
/// this, an operator with an IPv6-only SIEM (e.g. Sentinel at
/// `[2001:db8::5]:514`) would never receive any events because every send
/// would fail with `AddrNotAvailable`.
///
/// Returns `None` on bind failure — caller retries with backoff.
async fn open_udp(host: SocketAddr) -> Option<tokio::net::UdpSocket> {
    let bind_addr = if host.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("[sysknife-daemon] audit-forward: UDP bind on {bind_addr} failed: {e}");
            None
        }
    }
}

/// Format `event` as a single RFC 5424 syslog message.
///
/// Layout (one line, no trailing newline — UDP datagrams don't need one):
/// ```text
/// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD@32473 ...] MSG
/// ```
///
/// We hold to the spec's printable-USASCII rule for the structured-data
/// (SD) section by escaping `]`, `"`, and `\` per §6.3.3.
pub fn format_rfc5424(event: &AuditEvent, facility: u8) -> String {
    // Severity 5 = NOTICE for audit events. PRI = facility * 8 + severity.
    let severity = 5u8;
    let pri = (facility as u32) * 8 + severity as u32;

    let hostname = read_hostname();
    let app_name = "sysknife-daemon";
    let procid = std::process::id();
    let msgid = "AUDIT";

    let risk = match event.risk_level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
    };

    // RFC 5424 §6.3 structured data.
    //
    // **PEN 32473 is RFC 5612's documentation/test PEN — it MUST be replaced
    // before production deployment.** RFC 5424 §7.2.2 requires an
    // IANA-assigned Private Enterprise Number on `SD-ID`s emitted in
    // production frames. The SysKnife project does not yet hold a PEN; the
    // 32473 reservation is used here only so the formatter is bytewise
    // testable. Operators running a SIEM under a regulated framework should
    // either patch `SD@32473` to their own PEN at build time or treat this
    // as a known gap (see issue tracker).
    //
    // `terminal_status` is appended ONLY for the execute-time forward, so
    // preview frames remain byte-for-byte unchanged.
    let terminal_status_param = match &event.final_status {
        Some(s) => format!(" terminal_status=\"{}\"", sd_escape(s)),
        None => String::new(),
    };
    let sd = format!(
        "[sysknife@32473 \
         seq=\"{}\" \
         tx=\"{}\" \
         action=\"{}\" \
         risk=\"{}\" \
         approval=\"{}\" \
         role=\"{}\" \
         chain_hash=\"{}\" \
         key_id=\"{}\"{terminal_status_param}]",
        event.seq,
        sd_escape(&event.transaction_id),
        sd_escape(&event.action_name),
        risk,
        sd_escape(event.approval_id.as_deref().unwrap_or("")),
        sd_escape(event.caller_role.as_deref().unwrap_or("")),
        sd_escape(&event.chain_hash),
        sd_escape(&event.key_id),
    );

    let msg = format!("[{}] {}", event.action_name, event.summary);

    format!(
        "<{pri}>1 {ts} {host} {app} {pid} {msgid} {sd} {msg}",
        ts = event.created_at,
        host = hostname,
        app = app_name,
        pid = procid,
    )
}

/// Escape a value for inclusion inside a RFC 5424 SD-PARAM-VALUE per §6.3.3.
///
/// RFC 5424 §6 names PRINTUSASCII (`0x21..=0x7E`) as the preferred SD form;
/// UTF-8 is technically allowed but every strict SIEM ingest pipeline we
/// have surveyed (Splunk in strict mode, IBM QRadar, Microsoft Sentinel via
/// the Azure Monitor Agent) rejects non-ASCII bytes inside SD-VALUE. We
/// therefore drop **every** byte outside the printable-ASCII range and
/// escape the three characters
/// `]`, `"`, `\` per §6.3.3.
///
/// This also covers DEL (`0x7F`) and C1 controls (`0x80..=0x9F`).
fn sd_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ']' => out.push_str("\\]"),
            c if (0x20..=0x7E).contains(&(c as u32)) => out.push(c),
            // Drop everything else (C0, DEL, C1, all non-ASCII Unicode).
            _ => {}
        }
    }
    out
}

/// Read the kernel hostname and validate it against RFC 5424 §6.2.4.
///
/// HOSTNAME must be a single token: 1..=255 bytes, all `PRINTUSASCII`
/// (`0x21..=0x7E`), no embedded whitespace. Anything else (empty,
/// embedded space, non-ASCII, control char) returns the NILVALUE `"-"`
/// so the datagram remains parseable. Without this, a sysctl-set
/// hostname containing a space (e.g. `"edge node"`) would corrupt every
/// emitted frame and silently drop in strict SIEMs.
fn read_hostname() -> String {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if raw.is_empty() || raw.len() > 255 || !raw.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return "-".to_string();
    }
    raw
}

/// Test-only hostname validator that accepts an externally-provided string,
/// applies the same RFC 5424 §6.2.4 rule, and returns either the input or
/// `"-"`. Lets tests cover the validation path without mutating
/// `/proc/sys/kernel/hostname`.
#[cfg(test)]
fn validate_hostname_for_test(raw: &str) -> String {
    if raw.is_empty() || raw.len() > 255 || !raw.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return "-".to_string();
    }
    raw.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            seq: 42,
            transaction_id: "tx-abc".to_string(),
            action_name: "InstallFlatpak".to_string(),
            risk_level: RiskLevel::Medium,
            summary: "Install Firefox".to_string(),
            approval_id: Some("appr-xyz".to_string()),
            created_at: "2026-04-25T08:30:00Z".to_string(),
            chain_hash: "deadbeef".to_string(),
            key_id: "v1".to_string(),
            caller_role: Some("Dev".to_string()),
            final_status: None,
        }
    }

    // ── Hostname validation ──────────────────────────────────────────────

    #[test]
    fn hostname_with_space_is_rejected() {
        assert_eq!(validate_hostname_for_test("edge node 7"), "-");
    }

    #[test]
    fn hostname_with_control_byte_is_rejected() {
        assert_eq!(validate_hostname_for_test("edge\x01node"), "-");
    }

    #[test]
    fn hostname_with_non_ascii_is_rejected() {
        assert_eq!(validate_hostname_for_test("ëdge"), "-");
    }

    #[test]
    fn empty_hostname_falls_back_to_nilvalue() {
        assert_eq!(validate_hostname_for_test(""), "-");
    }

    #[test]
    fn legitimate_hostname_passes_through() {
        assert_eq!(
            validate_hostname_for_test("edge-node-7.example.com"),
            "edge-node-7.example.com"
        );
    }

    #[test]
    fn hostname_over_255_bytes_is_rejected() {
        let long = "a".repeat(256);
        assert_eq!(validate_hostname_for_test(&long), "-");
    }

    // ── SD-VALUE strict ASCII ────────────────────────────────────────────

    #[test]
    fn sd_escape_strips_del_and_c1_controls() {
        let raw = "before\x7Fafter\u{0085}";
        assert_eq!(sd_escape(raw), "beforeafter");
    }

    #[test]
    fn sd_escape_strips_non_ascii_to_avoid_strict_siem_rejection() {
        // Splunk/QRadar in strict mode reject non-ASCII inside SD-VALUE.
        let raw = "café";
        let escaped = sd_escape(raw);
        assert!(escaped.bytes().all(|b| (0x20..=0x7E).contains(&b)));
    }

    // ── RFC 5424 framing ──────────────────────────────────────────────────

    #[test]
    fn rfc5424_starts_with_pri_and_version() {
        let frame = format_rfc5424(&sample_event(), 1);
        // facility=1, severity=5 → PRI = 13. Version = 1.
        assert!(frame.starts_with("<13>1 "));
    }

    #[test]
    fn rfc5424_contains_sd_with_chain_hash_and_seq() {
        let frame = format_rfc5424(&sample_event(), 1);
        assert!(frame.contains("[sysknife@32473"));
        assert!(frame.contains("seq=\"42\""));
        assert!(frame.contains("chain_hash=\"deadbeef\""));
        assert!(frame.contains("key_id=\"v1\""));
        assert!(frame.contains("risk=\"medium\""));
        assert!(frame.contains("role=\"Dev\""));
    }

    #[test]
    fn rfc5424_message_section_contains_summary_and_action_tag() {
        let frame = format_rfc5424(&sample_event(), 1);
        assert!(frame.ends_with("[InstallFlatpak] Install Firefox"));
    }

    #[test]
    fn sd_escape_handles_dquote_backslash_bracket() {
        let raw = r#"name with "quotes", a \ backslash, and ] bracket"#;
        let escaped = sd_escape(raw);
        assert!(escaped.contains("\\\""));
        assert!(escaped.contains("\\\\"));
        assert!(escaped.contains("\\]"));
    }

    #[test]
    fn sd_escape_strips_control_characters() {
        // Control bytes must not appear inside SD-VALUE.
        let raw = "before\x01\x02\x1fafter";
        let escaped = sd_escape(raw);
        assert_eq!(escaped, "beforeafter");
    }

    #[test]
    fn rfc5424_missing_approval_renders_empty_string() {
        let mut e = sample_event();
        e.approval_id = None;
        let frame = format_rfc5424(&e, 1);
        assert!(frame.contains("approval=\"\""));
    }

    #[test]
    fn rfc5424_caller_role_with_quote_is_escaped() {
        let mut e = sample_event();
        e.caller_role = Some(r#"Dev"name"#.to_string());
        let frame = format_rfc5424(&e, 1);
        assert!(frame.contains("role=\"Dev\\\"name\""));
    }

    #[test]
    fn rfc5424_facility_changes_pri() {
        // facility=23 (local7), severity=5 → PRI = 189.
        let frame = format_rfc5424(&sample_event(), 23);
        assert!(frame.starts_with("<189>1 "));
    }

    #[test]
    fn terminal_status_emitted_when_present() {
        // Execute-time forward carries the terminal JobState. SOC analysts
        // need the SD-PARAM in the same frame as the chain hash so they can
        // pivot from "did the action run?" to "what happened?" without
        // joining against a second log source.
        let mut e = sample_event();
        e.final_status = Some("succeeded".to_string());
        let frame = format_rfc5424(&e, 1);
        assert!(
            frame.contains("terminal_status=\"succeeded\""),
            "frame missing terminal_status: {frame}"
        );
    }

    // ── AuditForwarder behaviour ─────────────────────────────────────────

    #[tokio::test(flavor = "current_thread")]
    async fn forwarder_drops_on_closed_channel() {
        let (tx, rx) = mpsc::channel::<AuditEvent>(1);
        // Drop the receiver to simulate a forwarder task that has exited.
        drop(rx);
        let forwarder = AuditForwarder {
            sender: tx,
            drops: Arc::new(AtomicU64::new(0)),
        };
        forwarder.submit(sample_event());
        assert_eq!(forwarder.drop_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forwarder_drops_when_full_and_warns_at_threshold() {
        // Build a channel of capacity 1 so the second submit overflows.
        let (tx, _rx) = mpsc::channel::<AuditEvent>(1);
        let forwarder = AuditForwarder {
            sender: tx,
            drops: Arc::new(AtomicU64::new(0)),
        };

        // Fill the channel.
        forwarder.submit(sample_event()); // queued — drop_count stays 0
        assert_eq!(forwarder.drop_count(), 0);

        // Now overflow DROP_WARN_THRESHOLD times.
        for _ in 0..DROP_WARN_THRESHOLD {
            forwarder.submit(sample_event());
        }
        assert_eq!(forwarder.drop_count(), DROP_WARN_THRESHOLD);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forwarder_resets_drop_counter_after_successful_submit() {
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(1);
        let forwarder = AuditForwarder {
            sender: tx,
            drops: Arc::new(AtomicU64::new(0)),
        };
        // First submit lands; second drops (full).
        forwarder.submit(sample_event());
        forwarder.submit(sample_event());
        assert_eq!(forwarder.drop_count(), 1);
        // Drain — frees a slot.
        let _ = rx.recv().await;
        // Next submit succeeds and resets the counter.
        forwarder.submit(sample_event());
        assert_eq!(forwarder.drop_count(), 0);
    }

    // ── End-to-end: spawn() actually emits over a UDP loopback ───────────

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_sends_udp_datagrams_to_listener() {
        // Bind a loopback listener first to learn the assigned port.
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let forwarder = spawn(AuditSinkSpec::SyslogUdp { host, facility: 1 });
        forwarder.submit(sample_event());

        // Receive with a generous timeout.
        let mut buf = [0u8; 2048];
        let len = tokio::time::timeout(Duration::from_secs(2), listener.recv(&mut buf))
            .await
            .expect("UDP recv timed out — forwarder did not emit")
            .expect("UDP recv succeeded");
        let frame = std::str::from_utf8(&buf[..len]).expect("frame is UTF-8");
        assert!(frame.starts_with("<13>1 "), "unexpected frame: {frame}");
        assert!(frame.contains("seq=\"42\""));
        assert!(frame.contains("[InstallFlatpak] Install Firefox"));
    }

    /// Backoff sequence regression: every consecutive bind failure must
    /// double the wait, capped at [`MAX_BACKOFF_SECS`].  The dispatcher does
    /// not currently expose a hook to drive the live `forwarder_task`
    /// deterministically (it loops on real `recv().await`), but the
    /// backoff math is extracted to `next_backoff_secs` so we can pin the
    /// sequence as a pure-function test.  A regression that turns the cap
    /// off would silently grow retry intervals into hours during a long
    /// SIEM outage; a regression that breaks doubling would peg a CPU on
    /// a tight retry loop.  Either way, this test fails first.
    #[test]
    fn next_backoff_secs_doubles_then_caps() {
        // Walk the sequence from the documented start until it has saturated
        // at the cap for two consecutive steps, so a future increase to
        // MAX_BACKOFF_SECS doesn't silently make this assertion looser.
        let mut seen = vec![INITIAL_BACKOFF_SECS];
        let mut b = INITIAL_BACKOFF_SECS;
        for _ in 0..32 {
            b = next_backoff_secs(b);
            seen.push(b);
            if seen.len() >= 2
                && seen[seen.len() - 1] == MAX_BACKOFF_SECS
                && seen[seen.len() - 2] == MAX_BACKOFF_SECS
            {
                break;
            }
        }

        // Doubling phase: every value before the cap is exactly 2× its
        // predecessor.
        for w in seen.windows(2) {
            let (prev, next) = (w[0], w[1]);
            if next == MAX_BACKOFF_SECS {
                // Either we hit the cap by doubling (prev * 2 >= cap) or we
                // are saturating (prev == cap). Both are valid.
                assert!(
                    prev.saturating_mul(2) >= MAX_BACKOFF_SECS,
                    "first cap step jumped from {prev} → {next} without doubling"
                );
            } else {
                assert_eq!(next, prev * 2, "non-cap step must double: {prev} → {next}");
            }
        }

        // Cap is reached and held — the final two entries are both at the cap.
        let n = seen.len();
        assert!(n >= 2);
        assert_eq!(seen[n - 1], MAX_BACKOFF_SECS);
        assert_eq!(seen[n - 2], MAX_BACKOFF_SECS);
        assert_eq!(seen[0], INITIAL_BACKOFF_SECS);
    }

    /// T8 — RFC 5424 round-trip through a real syslog parser.
    ///
    /// Substring `assert!(frame.contains("..."))` checks accept malformed
    /// frames as long as they happen to contain the expected substring.
    /// Round-trip the formatter's output through `syslog_loose`, which
    /// implements RFC 5424's grammar, and assert each parsed field
    /// matches the input event.  A regression that breaks PRI / VERSION /
    /// MSGID / SD-ID structure fails parsing here, not in production.
    #[test]
    fn rfc5424_round_trip_through_syslog_loose() {
        let event = sample_event();
        let facility = 1u8; // user-level
        let frame = format_rfc5424(&event, facility);

        let parsed = syslog_loose::parse_message(&frame, syslog_loose::Variant::RFC5424);

        // PRI = facility * 8 + severity. Severity for audit events is 5
        // (NOTICE) — pin both halves through the parser.
        assert_eq!(
            parsed.facility.expect("frame has a facility"),
            syslog_loose::SyslogFacility::LOG_USER,
            "facility should round-trip as user-level (1)"
        );
        assert_eq!(
            parsed.severity.expect("frame has a severity"),
            syslog_loose::SyslogSeverity::SEV_NOTICE,
            "audit events must be NOTICE-severity"
        );
        assert!(
            matches!(parsed.protocol, syslog_loose::Protocol::RFC5424(1)),
            "RFC 5424 frames carry version=1; got protocol={:?}",
            parsed.protocol
        );
        assert_eq!(parsed.msgid, Some("AUDIT"));
        assert_eq!(parsed.appname, Some("sysknife-daemon"));

        // Structured-data block: one SD element with id "sysknife@32473"
        // and the audit fields as params.
        let sd = parsed
            .structured_data
            .iter()
            .find(|s| s.id == "sysknife@32473")
            .expect("frame has the sysknife@32473 SD element");

        let get = |key: &str| -> String {
            sd.params
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_else(|| panic!("SD element missing param {key}: {sd:?}"))
        };
        assert_eq!(get("seq"), event.seq.to_string());
        assert_eq!(get("tx"), event.transaction_id);
        assert_eq!(get("action"), event.action_name);
        assert_eq!(get("risk"), "medium");
        assert_eq!(get("approval"), event.approval_id.unwrap());
        assert_eq!(get("role"), event.caller_role.unwrap());
        assert_eq!(get("chain_hash"), event.chain_hash);
        assert_eq!(get("key_id"), event.key_id);
    }

    /// IPv6 bind path: `open_udp` must select `[::]:0` for an IPv6 host so
    /// an IPv6-only SIEM (e.g. Sentinel at `[2001:db8::5]:514`) is reachable.
    /// Skipped when the kernel has IPv6 disabled (e.g. some hardened CI
    /// images with `net.ipv6.conf.all.disable_ipv6=1`); the assertion path
    /// only runs when bind genuinely succeeds.
    #[tokio::test(flavor = "current_thread")]
    async fn open_udp_ipv6_host_binds_ipv6_local_socket() {
        let host: SocketAddr = "[::1]:514".parse().unwrap();
        let Some(socket) = open_udp(host).await else {
            // IPv6 disabled in this environment — bind unavailable. The
            // production guard is exercised by the IPv4 test above.
            return;
        };
        let local = socket.local_addr().expect("bound socket has a local addr");
        assert!(
            local.is_ipv6(),
            "open_udp(IPv6 host) bound to non-IPv6 socket {local}"
        );
    }
}
