//! IPC connection handler for the daemon.
//!
//! Accepts both Unix socket and vsock connections. The caller role is resolved
//! before entering the handler:
//!
//! - **Unix**: `SO_PEERCRED` → Linux group membership → `CallerRole`
//! - **Vsock**: first frame must be `{"type":"auth","token":"<hex>"}` validated
//!   against `~/.config/sysknife/token`; valid token → configured role.
//!
//! # Security model
//!
//! - Unix role is derived from the peer process's Linux group membership
//!   via `SO_PEERCRED` + `/proc/{pid}/status` + `/etc/group`, with the peer
//!   pinned by a pidfd (`SO_PEERPIDFD`, Linux 6.5+) to guard the supplementary
//!   group read against PID reuse (see `resolve_caller`). The shell never
//!   supplies its own role.
//! - Vsock role is derived from a pre-shared token validated against a file;
//!   the token is generated at setup time and distributed out-of-band.
//! - Every `execute` request must carry a one-time receipt issued for the exact
//!   persisted preview. Receipt verification and consumption are atomic.
//! - Role is checked against the per-action allowlist (see `policy.rs`) before
//!   preview and again before execute.

use std::sync::Arc;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixStream;
use uuid::Uuid;

use sysknife_types::{CallerRole, JobState, PreviewEnvelope, RequestEnvelope};

// ---------------------------------------------------------------------------
// Credential redaction
// ---------------------------------------------------------------------------
//
// Some actions take credential parameters (e.g. `ProAttach` takes a Pro token).
// These values must NOT appear in:
//   - the `command` field of a DescribeResponse (sent over the wire)
//   - the `proposed_change` field of a PreviewEnvelope (persisted to the
//     transactions table AND returned in PreviewResponse)
//   - any tracing / debug output
//
// `credential_keys_for(action_name)` returns the per-action set of credential
// param keys. `redact_params` replaces each credential value with the literal
// string `<REDACTED>` while preserving structure. `redact_argv` walks the
// rendered argv and replaces any element that matches a known credential value
// (lookup by reading the params of the same action) with `<REDACTED>`.

/// Per-action credential param keys. Add new actions here when they take secrets.
fn credential_keys_for(action_name: &str) -> &'static [&'static str] {
    match action_name {
        "ProAttach" => &["token"],
        "ConfigureWifi" => &["password"],
        _ => &[],
    }
}

/// Return a copy of `params` with every credential value replaced by
/// the literal string `"<REDACTED>"`. Other keys are preserved unchanged.
fn redact_params(action_name: &str, params: &Value) -> Value {
    let keys = credential_keys_for(action_name);
    if keys.is_empty() {
        return params.clone();
    }
    if let Value::Object(map) = params {
        let mut out = serde_json::Map::with_capacity(map.len());
        for (k, v) in map {
            if keys.iter().any(|ck| *ck == k) {
                out.insert(k.clone(), Value::String("<REDACTED>".to_string()));
            } else {
                out.insert(k.clone(), v.clone());
            }
        }
        Value::Object(out)
    } else {
        params.clone()
    }
}

/// Per-action positional credential spec.
///
/// Returns the 0-based index of the argv element that holds a credential.
/// `usize::MAX` is a sentinel meaning "last element" (credential is always
/// the last positional argument). Returns `None` when the action carries no
/// positional credential.
///
/// Positional redaction is applied FIRST to guarantee correctness even when
/// the credential value coincidentally equals a structural argv element (e.g.
/// `token == "attach"` — red-team finding ME2).
fn credential_argv_spec(action_name: &str) -> Option<CredentialArgvSpec> {
    match action_name {
        // `sudo pro attach <token>` — the token is always the final element.
        "ProAttach" => Some(CredentialArgvSpec::Last),
        // `sudo nmcli device wifi connect <ssid> password <pw>` — the pair is
        // omitted entirely for open networks, so the credential has no fixed
        // index and is not reliably last either.
        "ConfigureWifi" => Some(CredentialArgvSpec::AfterKeyword("password")),
        _ => None,
    }
}

/// Where an action's credential sits inside its rendered argv.
///
/// A spec is authoritative: when one exists the credential lives at exactly
/// that slot, so redaction never has to match on the secret's text and can
/// therefore not clobber a structural element that happens to share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialArgvSpec {
    /// The credential is the final argv element.
    Last,
    /// The credential is the element immediately after `keyword`.
    AfterKeyword(&'static str),
}

/// Replace the credential argv element(s) with `<REDACTED>`.
///
/// Strategy (ME2 fix):
/// 1. **Positional redaction** — if `credential_argv_position` returns a spec
///    for this action, redact that exact index and return immediately. This
///    prevents the value-match pass from also clobbering structural argv
///    elements that happen to share the same text as the credential (e.g.
///    `token == "attach"` — red-team finding ME2). When a positional spec
///    exists it is authoritative: the credential is always at that slot and
///    nowhere else in the argv.
/// 2. **Value-match fallback** — for actions that have no positional spec,
///    walk argv and replace any element whose text matches a credential value.
///    This is the original behavior and remains as a safety net for future
///    actions that haven't been assigned a positional spec yet.
fn redact_argv(action_name: &str, params: &Value, args: &[String]) -> Vec<String> {
    let keys = credential_keys_for(action_name);
    if keys.is_empty() {
        return args.to_vec();
    }
    let secrets: Vec<&str> = keys
        .iter()
        .filter_map(|k| params.get(k).and_then(|v| v.as_str()))
        .collect();
    if secrets.is_empty() {
        return args.to_vec();
    }

    let mut out: Vec<String> = args.to_vec();

    // Step 1 — positional redaction (authoritative when a spec exists).
    if let Some(spec) = credential_argv_spec(action_name) {
        let idx = match spec {
            CredentialArgvSpec::Last => Some(out.len().saturating_sub(1)),
            // Take the LAST keyword occurrence that still has a successor.
            // "last" handles an SSID that is itself named `password`; the
            // successor requirement handles a password whose value is the
            // literal `password`, where the final occurrence IS the secret.
            CredentialArgvSpec::AfterKeyword(keyword) => out
                .iter()
                .enumerate()
                .rev()
                .find(|(i, arg)| arg.as_str() == keyword && i + 1 < out.len())
                .map(|(i, _)| i + 1),
        };
        if let Some(idx) = idx.filter(|i| *i < out.len()) {
            out[idx] = "<REDACTED>".to_string();
        }
        // Positional spec is authoritative — skip value-match to avoid
        // inadvertently redacting structural argv elements that share the
        // same text as the credential (ME2 fix).
        return out;
    }

    // Step 2 — value-match fallback for actions without a positional spec.
    out.iter_mut().for_each(|a| {
        if secrets.iter().any(|s| s == &a.as_str()) {
            *a = "<REDACTED>".to_string();
        }
    });

    out
}

use crate::{
    auth::{highest_role_from_groups, CallerAttribution},
    executor::{build_action_spec, rollback_spec_for, ActionExecutor},
    preview::preview_action,
    state::DaemonState,
    state_collector::{collect_state, CollectedState, CommandRunner},
    transactions::NewTransaction,
    transport::framing::{FramedStream, FramingError},
};

// ---------------------------------------------------------------------------
// Tunable constants
// ---------------------------------------------------------------------------

/// Maximum wait for the first auth frame on a vsock connection, in seconds.
///
/// A peer that opens the socket but never writes is either firewalled,
/// confused, or hostile.  Ten seconds is comfortably longer than any sane
/// auth round-trip (~ms) and short enough that a stuck guest does not
/// sit on a connection slot indefinitely under [`MAX_CONNECTIONS`] backpressure.
const VSOCK_AUTH_FRAME_TIMEOUT_SECS: u64 = 10;

/// Default number of history rows returned by `query_history` when the
/// caller does not specify `limit`.
///
/// 20 is a single-screenful of recent activity that mirrors the CLI's
/// `sysknife history` default — large enough to be useful for triage,
/// small enough to keep the response under the IPC frame budget.
const DEFAULT_HISTORY_LIMIT: u32 = 20;

/// How many leading characters of a transaction UUID to render in the
/// human-readable history listing.  UUID v4 has 122 bits of entropy; even
/// at 80,000 entries the chance of collision in the first 8 hex chars
/// (32 bits) is < 1%, which is fine for a forensic-only display where the
/// full ID is also recorded.
const TRANSACTION_ID_DISPLAY_PREFIX_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Wire types — Shell → Daemon
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct TransactionId(String);

impl TransactionId {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct ApprovalReceipt(String);

impl ApprovalReceipt {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DaemonRequest {
    QueryState {
        request_id: String,
    },
    Preview {
        request_id: String,
        action_name: String,
        params: Value,
        /// The client is running with its approval gate lifted, so no human
        /// will confirm this step.
        ///
        /// `#[serde(default)]` keeps an older client working unchanged. The
        /// daemon does not trust this to *permit* anything; it only records
        /// it, by appending [`UNATTENDED_WARNING`] to the preview warnings,
        /// which are signed into the transaction row. A client that lies by
        /// omission gains nothing, because the field grants no authority.
        #[serde(default)]
        unattended: bool,
    },
    Approve {
        request_id: String,
        transaction_id: TransactionId,
    },
    ApprovalDetails {
        request_id: String,
        transaction_id: TransactionId,
    },
    Execute {
        request_id: String,
        transaction_id: TransactionId,
        action_name: String,
        params: Value,
        approval_receipt: ApprovalReceipt,
    },
    /// Cancel a still-queued transaction (before it is claimed for execution).
    /// Identified by transaction_id — a queued transaction has no job_id yet.
    /// Option A: an in-flight (Running) action is never interrupted.
    Cancel {
        request_id: String,
        transaction_id: TransactionId,
    },
    QueryAction {
        request_id: String,
        action_name: String,
        params: Value,
    },
    /// Structured audit-log history for programmatic clients. Unlike the
    /// `ListJobHistory` action (which returns human-formatted text), this
    /// returns typed rows so the MCP `sysknife_history` tool gets `created_at`
    /// and `risk_level` without re-parsing text.
    QueryHistory {
        request_id: String,
        limit: Option<u32>,
        status_filter: Option<String>,
        action_filter: Option<String>,
        since_hours: Option<u32>,
    },
    Describe {
        request_id: String,
        action_name: String,
        params: Value,
    },
}

// ---------------------------------------------------------------------------
// Wire types — Daemon → Shell
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DaemonResponse {
    StateResponse {
        request_id: String,
        state: CollectedState,
    },
    PreviewResponse {
        request_id: String,
        preview: PreviewEnvelope,
        transaction_id: String,
    },
    ApprovalResponse {
        request_id: String,
        transaction_id: String,
        approval_receipt: String,
    },
    ApprovalDetailsResponse {
        request_id: String,
        transaction_id: String,
        action_name: String,
        preview: PreviewEnvelope,
    },
    JobStarted {
        request_id: String,
        job_id: String,
        transaction_id: String,
    },
    JobProgress {
        job_id: String,
        line: String,
    },
    JobCompleted {
        job_id: String,
        result: JobResult,
    },
    QueryActionResponse {
        request_id: String,
        action_name: String,
        output: String,
    },
    HistoryResponse {
        request_id: String,
        entries: Vec<crate::transactions::JobHistoryEntry>,
    },
    CancelResponse {
        request_id: String,
        transaction_id: String,
    },
    DescribeResponse {
        request_id: String,
        command: String,
        risk_level: String,
        reboot_required: bool,
    },
    ErrorResponse {
        request_id: String,
        category: String,
        message: String,
    },
    /// Returned when a mutating action is submitted while a High-risk
    /// reboot-required action (e.g. `UbuntuReleaseUpgrade`) is already
    /// executing. The caller should retry after the running job completes.
    ///
    /// Wire shape (JSON):
    /// ```json
    /// {
    ///   "type": "conflict_response",
    ///   "request_id": "<id>",
    ///   "message": "high-risk action in progress; retry after the current job completes",
    ///   "retry_after_seconds": null
    /// }
    /// ```
    ConflictResponse {
        request_id: String,
        message: String,
        /// Hint to the client: how long to wait before retrying. `null` when
        /// the daemon cannot estimate the remaining runtime.
        retry_after_seconds: Option<u32>,
    },
}

/// IPC payload included in `job_completed` and related response frames.
///
/// Although the type itself is private to the dispatcher module, every field
/// is serialised on the wire and parsed by the shell, the CLI, and the MCP
/// adapter — treat changes here as breaking IPC changes.
#[derive(Debug, Serialize)]
struct JobResult {
    /// Terminal job status: `"succeeded"`, `"failed"`, `"canceled"`,
    /// `"rolled_back"`, or `"needs_reboot"`. Mirrors `JobState`'s `Display`.
    status: String,
    /// One-line human-readable summary of the outcome.
    summary: String,
    /// Per-step warning strings preserved verbatim from the executor.
    warnings: Vec<String>,
    /// Daemon-assigned identifier for this job (UUID v4).
    job_id: String,
    /// `true` when the action requires a reboot to take effect.
    needs_reboot: bool,
    /// OSTree commit reference recorded for rollback, or `None` when the
    /// action is not rollbackable.
    rollback_ref: Option<String>,
    /// Audit-log transaction ID for this job — also the join key for SIEM
    /// correlation against forwarded events.
    transaction_id: String,
}

// ---------------------------------------------------------------------------
// Role resolution
// ---------------------------------------------------------------------------

/// `SO_PEERPIDFD` getsockopt option (Linux 6.5+). Value 77 is from the
/// asm-generic UAPI `socket.h`, which x86_64 and aarch64 — SysKnife's only
/// release targets — use. Defined locally so the code builds against libc
/// versions that predate the constant.
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: libc::c_int = 77;

/// Obtain a pidfd pinned to the process that opened this connection, via
/// `SO_PEERPIDFD`. Unlike `pidfd_open(pid)`, this has no PID-based lookup and so
/// no reuse race — the kernel pins the actual peer captured at `connect()`.
///
/// Returns `None` when the kernel does not support the option (e.g. Ubuntu
/// 22.04's 5.15 kernel), in which case the caller falls back to the best-effort
/// `/proc/{pid}` path.
#[cfg(target_os = "linux")]
fn peer_pidfd(stream: &UnixStream) -> Option<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `fd` (a c_int) and
    // updates `len`; we pass the true buffer size and check the return code.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 || fd < 0 {
        return None;
    }
    // SAFETY: getsockopt returned a fresh, owned fd; take sole ownership so it is
    // closed on drop.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Returns `true` while the pinned peer process has not yet been reaped — i.e.
/// its PID cannot have been recycled. Uses `pidfd_send_signal(pidfd, 0)`, whose
/// signal `0` performs an existence/permission check with no delivery: success
/// or any errno other than `ESRCH` means the process still exists; `ESRCH` means
/// it has been reaped.
#[cfg(target_os = "linux")]
fn pidfd_peer_still_live(pidfd: &OwnedFd) -> bool {
    // SAFETY: FFI call with a valid owned pidfd; signal 0 delivers nothing, and
    // NULL siginfo + 0 flags are the documented "just check" form.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if rc == 0 {
        return true;
    }
    // A reaped process reports ESRCH; anything else (e.g. EPERM) still means the
    // process exists, so its PID cannot have been recycled.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Resolve who is calling: the role that decides what they may do, and the
/// principal that records which account did it.
///
/// Uses `SO_PEERCRED` (via `peer_cred()`) to obtain the peer PID and primary
/// GID, reads `/proc/{pid}/status` for the supplementary GIDs, and resolves
/// each GID to a group name via `/etc/group`. The primary GID is included
/// explicitly because Linux's `Groups:` line in `/proc/{pid}/status` lists
/// only supplementary groups — a process whose primary group is `wheel` would
/// otherwise be misclassified as `Observer`. Falls back to `Observer` on any
/// error.
///
/// # PID-reuse hardening
///
/// The uid/gid/pid from `SO_PEERCRED` are captured by the kernel at `connect()`
/// and are race-free, but the *supplementary* group set is read from
/// `/proc/{pid}/status` after the fact. If the peer exited and its PID were
/// recycled before that read, we would read a different process's groups. On
/// Linux 6.5+ (Ubuntu 24.04 / 26.04) we pin the peer with a pidfd via
/// `peer_pidfd` and, after reading `/proc`, confirm the pinned process was not
/// reaped during the read; if it was, the supplementary set is untrustworthy and
/// is dropped, keeping only the race-free primary GID. On older kernels (e.g.
/// Ubuntu 22.04) the pidfd is unavailable and the read is best-effort, as before
/// — no worse than the previous behavior.
pub fn resolve_caller(stream: &UnixStream) -> CallerAttribution {
    let (pid, primary_gid, uid) = match stream.peer_cred() {
        Ok(cred) => {
            let pid = match cred.pid() {
                // Strictly positive: the kernel writes 0 when the peer's pid is
                // not representable in this daemon's pid namespace, and 0 is
                // never a real peer. Accepting it read as a successful
                // attribution of a process that cannot be named.
                Some(p) if p > 0 => p as u32,
                _ => {
                    eprintln!(
                        "[sysknife-daemon] WARNING: peer_cred() returned no usable pid; \
                         defaulting to Observer and recording the caller as unattributed"
                    );
                    return CallerAttribution::unattributed();
                }
            };
            (pid, cred.gid(), cred.uid())
        }
        Err(e) => {
            eprintln!(
                "[sysknife-daemon] WARNING: peer_cred() failed: {e}; defaulting to Observer \
                 and recording the caller as unattributed"
            );
            return CallerAttribution::unattributed();
        }
    };

    // Pin the connecting peer *before* the /proc read so PID reuse can be
    // detected afterward. None on kernels without SO_PEERPIDFD (< 6.5).
    #[cfg(target_os = "linux")]
    let peer_fd = peer_pidfd(stream);

    // Read /etc/group once and build a lookup map — avoids N+1 file reads when
    // a process has many supplementary groups (one read per GID in the old code).
    let gid_map = read_gid_map();
    let mut groups = groups_for_pid(pid, &gid_map);

    // If the pinned peer was reaped while we read /proc, its PID may have been
    // recycled and the supplementary groups belong to a different process — drop
    // them and fall back to the race-free primary GID only.
    #[cfg(target_os = "linux")]
    if let Some(ref fd) = peer_fd {
        if !pidfd_peer_still_live(fd) {
            eprintln!(
                "[sysknife-daemon] WARNING: peer PID {pid} was reaped while resolving its \
                 groups (possible PID reuse); ignoring supplementary groups and using the \
                 SO_PEERCRED primary GID only"
            );
            groups.clear();
        }
    }

    // Include the primary GID from SO_PEERCRED. It is not listed in the
    // supplementary Groups: line so must be resolved and added explicitly.
    if let Some(name) = gid_map.get(&primary_gid) {
        if !groups.contains(name) {
            groups.push(name.clone());
        }
    }
    if groups.is_empty() {
        eprintln!(
            "[sysknife-daemon] WARNING: could not resolve groups for PID {pid}; defaulting to Observer"
        );
    }
    // The uid comes from the same SO_PEERCRED read as the gid, captured by the
    // kernel at connect(), so it is race-free in a way the supplementary group
    // set read from /proc is not.
    //
    // It is not always a real account, though. The kernel translates `struct
    // ucred` into the *reader's* namespaces, and when the peer's uid is not
    // mappable it substitutes the overflow uid (`/proc/sys/kernel/overflowuid`,
    // 65534 / `nobody` by default) rather than failing. A socket bind-mounted
    // into a container reaches this path. Signing `uid:65534` there would make a
    // positive claim that the `nobody` account acted, when the truth is that the
    // kernel could not name the peer — exactly the false attribution
    // `CallerPrincipal::Unattributed` exists to avoid.
    if uid == overflow_uid() {
        eprintln!(
            "[sysknife-daemon] WARNING: SO_PEERCRED reported the overflow uid ({uid}) for pid \
             {pid}; the peer is not representable in this daemon's user namespace. Recording \
             the caller as unattributed rather than as uid:{uid}."
        );
        return CallerAttribution::unattributed();
    }

    CallerAttribution::from_peer_uid(uid, highest_role_from_groups(groups))
}

/// The uid the kernel substitutes when a peer's uid cannot be mapped into this
/// process's user namespace.
///
/// Read once from `/proc/sys/kernel/overflowuid`, falling back to the kernel's
/// compile-time default. The fallback is not a "just in case" branch: on a host
/// where procfs is not mounted the value is still 65534, and treating an
/// unreadable sysctl as "no overflow uid exists" would re-open the false
/// attribution this guards against.
fn overflow_uid() -> u32 {
    /// Kernel default from `include/linux/highuid.h`.
    const DEFAULT_OVERFLOW_UID: u32 = 65534;
    static CACHED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/overflowuid")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_OVERFLOW_UID)
    })
}

/// Read `/etc/group` once and return a `HashMap<gid, group_name>`.
/// Silently returns an empty map on I/O failure (falls back to Observer role).
fn read_gid_map() -> std::collections::HashMap<u32, String> {
    let content = match std::fs::read_to_string("/etc/group") {
        Ok(c) => c,
        Err(e) => {
            // Without /etc/group all callers will be resolved to Observer.
            // This is a misconfiguration or permission problem that must be visible.
            eprintln!("[sysknife-daemon] WARNING: cannot read /etc/group: {e}; all callers will be demoted to Observer");
            return std::collections::HashMap::new();
        }
    };
    let mut map = std::collections::HashMap::new();
    for (line_no, line) in content.lines().enumerate() {
        let mut parts = line.splitn(4, ':');
        let name = match parts.next() {
            Some(n) => n,
            None => {
                eprintln!("[sysknife-daemon] WARNING: malformed /etc/group line {line_no}: missing name field");
                continue;
            }
        };
        let _ = parts.next(); // password field
        let gid_str = match parts.next() {
            Some(g) => g,
            None => {
                eprintln!("[sysknife-daemon] WARNING: malformed /etc/group line {line_no} (group={name:?}): missing GID field");
                continue;
            }
        };
        match gid_str.parse::<u32>() {
            Ok(gid) => {
                map.insert(gid, name.to_string());
            }
            Err(_) => {
                eprintln!("[sysknife-daemon] WARNING: malformed /etc/group line {line_no} (group={name:?}): GID {gid_str:?} is not a number");
            }
        }
    }
    map
}

fn groups_for_pid(pid: u32, gid_map: &std::collections::HashMap<u32, String>) -> Vec<String> {
    let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "[sysknife-daemon] could not read /proc/{pid}/status: {e}; treating as no groups"
            );
            return vec![];
        }
    };
    for line in status.lines() {
        if line.starts_with("Groups:") {
            return line
                .trim_start_matches("Groups:")
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .filter_map(|gid| gid_map.get(&gid).cloned())
                .collect();
        }
    }
    // If the Groups: line is absent (unusual kernel config or namespacing),
    // the caller will be resolved to Observer via its primary GID only.
    // Log so operators can diagnose unexpected authorization failures.
    eprintln!(
        "[sysknife-daemon] WARNING: no Groups: line in /proc/{pid}/status; \
         supplementary groups unavailable — caller may be demoted to Observer"
    );
    vec![]
}

// ---------------------------------------------------------------------------
// Authorization helpers
// ---------------------------------------------------------------------------

fn authorize_action(
    policy: &crate::policy::PolicyTable,
    caller: &CallerRole,
    action_name: &str,
) -> bool {
    policy.action_allowed(caller, action_name)
}

/// The message for a refused action.
///
/// Refusals used to end at "is not allowed for Observer role", which is true and
/// unactionable. When the required role is known, name the group that grants it
/// and the command to join. The role ceiling can be raised per action via
/// `[policy.risk_overrides]`, so the effective minimum is read from the live
/// policy rather than the compile-time baseline.
fn authorization_failure_message(
    policy: &crate::policy::PolicyTable,
    caller: &CallerRole,
    action_name: &str,
) -> String {
    match policy.min_role_for_action(action_name) {
        Some(required) => crate::auth::denial_message(action_name, *caller, required),
        // No baseline entry means the action is not in the catalogue at all;
        // there is no group to recommend.
        None => format!("action '{action_name}' is not allowed for {caller:?} role"),
    }
}

/// Authorize a caller to act on an existing transaction (approve / cancel /
/// view details), keyed on the transaction's own action. Transaction IDs are
/// enumerable by any Observer-tier caller via history, so without this a
/// low-privilege caller could mint, consume, or cancel the one-time approval
/// slot of an action they are not allowed to run — defeating the human-approval
/// boundary. Only a caller authorized for the action may touch its approval.
///
/// Returns `Ok(true)` when authorized (proceed). Returns `Ok(false)` when a
/// response has already been sent (transaction missing, load error, or denied)
/// and the caller must return early.
/// Whether `caller` is the account that created `transaction_id`.
///
/// The approval receipt is documented as proof that a human confirmed one
/// specific preview. Checking only the caller's role made that proof
/// unattributed: any account permitted to reach the socket could mint a
/// receipt for a transaction it had never previewed, and the signed row would
/// still name the account that *previewed* it, so the trail blamed the wrong
/// person. `caller_principal` was already captured, stored and signed; nothing
/// read it back.
///
/// The rule is principal equality, not connection equality. `sysknife approve`
/// is deliberately a separate process from the client that previewed, and every
/// CLI call opens its own connection, so requiring one connection would break
/// the product. Requiring one account does not: both halves run as the same
/// uid, and a vsock client previews and approves over the same channel.
///
/// Two cases refuse rather than compare:
///
/// - `Unattributed`, on either side. The kernel could not name the peer, so
///   two such callers are not known to be the same account. Treating them as
///   equal would put a claim in the signed record that the daemon has no
///   evidence for, which is the thing [`CallerPrincipal::Unattributed`] exists
///   to avoid.
/// - A row with no stored principal. Only a chain imported from before the
///   `caller_principal` migration can be in that state, and such a row cannot
///   legitimately be queued for approval on a daemon running this code.
async fn caller_owns_transaction(
    state: &DaemonState,
    caller: &CallerAttribution,
    transaction_id: &str,
) -> Ownership {
    if matches!(
        caller.principal(),
        crate::auth::CallerPrincipal::Unattributed
    ) {
        return Ownership::CannotEstablish(
            "this connection could not be attributed to an account, so it cannot approve, \
             cancel, inspect or execute a transaction. The daemon reports the peer as \
             unattributed when SO_PEERCRED fails or when the peer is not representable in \
             this daemon's user namespace."
                .to_string(),
        );
    }
    let row = match state.audit.fetch_chain_row(transaction_id).await {
        Ok(row) => row,
        Err(e) => {
            return Ownership::CannotEstablish(format!(
                "failed to load transaction ownership: {e}"
            ));
        }
    };
    // A transaction that does not exist is not an ownership question. Saying
    // "that belongs to someone else" about an id nobody ever created would be
    // both wrong and a way to probe which ids exist, so this hands the case
    // back to the caller's own missing-transaction path.
    let Some(row) = row else {
        return Ownership::NoSuchTransaction;
    };
    let Some(owner) = row.caller_principal.as_deref() else {
        return Ownership::CannotEstablish(format!(
            "transaction {transaction_id} records no owning account, so ownership cannot be \
             established"
        ));
    };
    if owner == caller.principal().as_signed_str() {
        Ownership::Owned
    } else {
        Ownership::NotOwned
    }
}

/// The four answers [`caller_owns_transaction`] can give.
///
/// An enum rather than a `Result<bool, _>` because "no such transaction" and
/// "someone else's transaction" need different answers to the caller, and a
/// boolean forced them together. The first version of this check reported a
/// nonexistent id as belonging to another account, which is both untrue and a
/// way to probe the id space.
enum Ownership {
    Owned,
    NotOwned,
    NoSuchTransaction,
    CannotEstablish(String),
}

/// The refusal an operator sees when they act on someone else's transaction.
///
/// Deliberately does not name the owning account. Telling one caller which
/// other account queued a transaction would hand out exactly the cross-account
/// information this check exists to withhold.
fn not_your_transaction_message(transaction_id: &str) -> String {
    format!(
        "transaction {transaction_id} was created by a different account. An approval receipt \
         is proof that a specific account confirmed a specific preview, so only the account \
         that previewed an action can approve, cancel, inspect or execute it."
    )
}

async fn authorize_for_transaction(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    caller: &CallerAttribution,
    request_id: &str,
    transaction_id: &str,
    missing_category: &str,
    missing_message: &str,
) -> Result<bool, HandlerError> {
    match state.audit.get(transaction_id).await {
        Ok(Some(transaction)) => {
            match caller_owns_transaction(state, caller, transaction_id).await {
                Ownership::Owned | Ownership::NoSuchTransaction => {}
                Ownership::NotOwned => {
                    send_error(
                        framed,
                        request_id,
                        "authorization_failure",
                        not_your_transaction_message(transaction_id),
                    )
                    .await?;
                    return Ok(false);
                }
                Ownership::CannotEstablish(message) => {
                    send_error(framed, request_id, "authorization_failure", message).await?;
                    return Ok(false);
                }
            }
            if authorize_action(&state.policy, &caller.role(), &transaction.action_name) {
                Ok(true)
            } else {
                send_error(
                    framed,
                    request_id,
                    "authorization_failure",
                    authorization_failure_message(
                        &state.policy,
                        &caller.role(),
                        &transaction.action_name,
                    ),
                )
                .await?;
                Ok(false)
            }
        }
        Ok(None) => {
            send_error(framed, request_id, missing_category, missing_message).await?;
            Ok(false)
        }
        Err(e) => {
            send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to load transaction: {e}"),
            )
            .await?;
            Ok(false)
        }
    }
}

// Family-specific action lists come from the single source of truth in
// `sysknife-core::action_family`, shared with the CLI routing guard and the
// brain prompt so the execution fence can never drift out of parity.
use sysknife_core::action_family::{DEBIAN_ONLY_ACTIONS, FEDORA_ONLY_ACTIONS};

fn validate_action_platform(state: &DaemonState, action_name: &str) -> Result<(), String> {
    use sysknife_core::distro::DistroFamily;

    let required_family = if DEBIAN_ONLY_ACTIONS.contains(&action_name) {
        Some(DistroFamily::Debian)
    } else if FEDORA_ONLY_ACTIONS.contains(&action_name) {
        Some(DistroFamily::Fedora)
    } else {
        None
    };
    // Deliberately the compile-time baseline, not `state.policy`. Whether an
    // action mutates the system is a property of the action; whether a given
    // caller may run it is what `[policy.risk_overrides]` decides. Reading it
    // from the override-adjusted role let an operator who tightened RBAC on a
    // read-only action also make that read fail when the host distro could not
    // be detected — a distro requirement appearing as a side effect of an
    // access-control change.
    let is_mutating = crate::policy::min_role_for_action(action_name)
        .is_some_and(|role| role > CallerRole::Observer);
    if required_family.is_none() && !is_mutating {
        return Ok(());
    }

    // Both gates below apply to family-tagged actions whether or not they read.
    //
    // An earlier revision exempted read-only ones, on the reasoning that
    // docs/distro-support.md promises to refuse only *mutating* actions on an
    // ineligible host. The exemption was keyed on `is_mutating`, which is derived
    // from the RBAC role, which is derived from `risk_level` — and that proxy is
    // wrong for at least one catalogued action: `AptUpdate` is `RiskLevel::Low`,
    // so `Observer`, so "read-only" by that measure, while it runs
    // `sudo apt-get update` as root, writes under /var/lib/apt/lists and takes
    // the dpkg lock. Exempting it widened the set of hosts that can run a
    // privileged mutation.
    //
    // Fail closed until the bit lives on its owner. "Does this action change the
    // host" is a property of the ActionSpec, not of who may call it, and the fix
    // is to record it there — see the linked issue. Until then the strict gate
    // costs read-only inspection on ineligible hosts (`AptShow` on Debian), which
    // is the pre-existing behaviour and the safe direction to be wrong in.
    let distro = state.host_distro.as_ref().ok_or_else(|| {
        format!("cannot safely run {action_name}: host distribution could not be detected")
    })?;
    if !distro.is_supported() {
        return Err(format!(
            "cannot run {action_name} on unsupported host {distro}; see docs/distro-support.md"
        ));
    }
    if required_family.is_some_and(|family| distro.family() != family) {
        return Err(format!(
            "action {action_name} is incompatible with supported host {distro}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Request hash
// ---------------------------------------------------------------------------

/// Compute `SHA-256(action_name || "\x00" || canonical_json(params))`,
/// hex-encoded.
///
/// Canonical JSON serialises object keys in sorted order (recursively),
/// ensuring identical logical params always produce the same hash regardless
/// of insertion order.
pub fn compute_request_hash(action_name: &str, params: &Value) -> String {
    let canonical = canonical_json(params);
    let mut hasher = Sha256::new();
    hasher.update(action_name.as_bytes());
    hasher.update(b"\x00");
    hasher.update(canonical.as_bytes());
    let bytes = hasher.finalize();
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        // Writing to String via fmt::Write is infallible.
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Key under which a previewed `AptAutoremove` records the exact set of packages
/// `apt-get -s autoremove` would remove, so execute can bind to it (#151).
const AUTOREMOVE_REMOVALS_KEY: &str = "autoremove_removals";

/// Run `apt-get -s autoremove` and parse the set of packages it would remove.
/// The simulate is read-only (no `sudo`), so it runs through the same
/// `CommandRunner` the preview uses to collect state.
async fn simulate_autoremove_set(
    runner: &Arc<dyn CommandRunner + Send + Sync>,
) -> Result<std::collections::BTreeSet<String>, String> {
    let r = Arc::clone(runner);
    match tokio::task::spawn_blocking(move || r.run("apt-get", &["-s", "autoremove"])).await {
        Ok(Ok(out)) => Ok(crate::actions::apt::parse_autoremove_removals(&out)),
        Ok(Err(e)) => Err(format!("apt-get -s autoremove failed: {e}")),
        Err(e) => Err(format!("autoremove simulate task panicked: {e}")),
    }
}

/// A warning if the autoremove set includes kernel, driver, or bootloader
/// packages — the classes that make an unattended autoremove dangerous, so the
/// operator sees them explicitly in the preview.
fn autoremove_kernel_warning(set: &std::collections::BTreeSet<String>) -> Option<String> {
    let flagged: Vec<&str> = set
        .iter()
        .map(String::as_str)
        .filter(|n| {
            let base = n.split(':').next().unwrap_or(n);
            base.starts_with("linux-image")
                || base.starts_with("linux-modules")
                || base.starts_with("linux-headers")
                || base.starts_with("grub")
                || base.contains("nvidia")
                || base.ends_with("-dkms")
        })
        .collect();
    if flagged.is_empty() {
        None
    } else {
        Some(format!(
            "autoremove would delete kernel/driver/bootloader packages: {}. Review carefully.",
            flagged.join(", ")
        ))
    }
}

/// Confirm the live autoremove set still matches the set captured in the
/// approved preview (#151). `apt-get autoremove -y` resolves its deletion set at
/// run time, so without this the executed effect is unbound by the approval.
/// Fails closed: a preview that never captured a set (the simulate failed then)
/// cannot be executed.
fn verify_autoremove_binding(
    approved_proposed_change: &Value,
    live: &std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let Some(captured) = approved_proposed_change.get(AUTOREMOVE_REMOVALS_KEY) else {
        return Err(
            "the approved preview did not capture the autoremove deletion set; preview again"
                .to_string(),
        );
    };
    let approved: std::collections::BTreeSet<String> = serde_json::from_value(captured.clone())
        .map_err(|_| {
            "the approved preview's autoremove set is malformed; preview again".to_string()
        })?;
    if &approved == live {
        return Ok(());
    }
    let added: Vec<&str> = live.difference(&approved).map(String::as_str).collect();
    let removed: Vec<&str> = approved.difference(live).map(String::as_str).collect();
    Err(format!(
        "the set of packages autoremove would delete changed since you approved it \
         (now also removes: [{}]; no longer removes: [{}]); preview again",
        added.join(", "),
        removed.join(", ")
    ))
}

fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let pairs = keys
                .iter()
                .map(|k| {
                    // Use Value::String's Display impl to JSON-encode the key —
                    // infallible because Rust strings are always valid UTF-8.
                    format!(
                        "{}:{}",
                        Value::String((*k).to_string()),
                        canonical_json(&map[*k])
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{pairs}}}")
        }
        // Arrays preserve element order (ordering is meaningful) but recurse
        // into each element so nested objects get their keys sorted.
        Value::Array(arr) => {
            let items = arr.iter().map(canonical_json).collect::<Vec<_>>().join(",");
            format!("[{items}]")
        }
        // For scalars (null, bool, number, string) use Value's Display impl,
        // which renders valid JSON and is infallible.
        _ => format!("{v}"),
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

/// Handle a single Unix-socket (or test duplex) connection until the peer
/// closes it.
///
/// # Security — Unix/test streams only
///
/// **Do not call with a vsock stream.** The name `unix_connection_handler`
/// is the type-system gate: this function is explicitly for Unix-domain
/// sockets (where `caller_role` is resolved from `SO_PEERCRED` out-of-band)
/// and for in-process duplex streams used by integration tests (where the
/// test supplies the role directly).
///
/// Vsock connections carry an untrusted remote peer. Calling this function
/// with a vsock stream would hand the peer whatever `caller_role` was passed
/// in — bypassing token authentication entirely. Vsock connections MUST go
/// through [`vsock_connection_handler`], which validates the auth token in
/// the first frame before dispatching to the inner handler.
///
/// **Threat model note:** lying about the stream type here (e.g. passing a
/// vsock stream while pretending it is a Unix stream) constitutes a
/// privilege escalation: the caller receives the role passed in without any
/// cryptographic proof.
///
/// `caller_role` MUST be resolved before this function is called.
pub async fn unix_connection_handler<S>(
    stream: S,
    state: DaemonState,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    caller: CallerAttribution,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let executor: Arc<dyn ActionExecutor> = Arc::new(crate::executor::RealActionExecutor);
    connection_handler_with_executor(stream, state, runner, executor, caller).await;
}

/// Handle a vsock connection: validate token from first frame, then dispatch.
///
/// The first frame must be `{"type":"auth","token":"<hex>"}`. On failure the
/// connection is closed silently to prevent oracle attacks.
#[cfg(target_os = "linux")]
pub async fn vsock_connection_handler<S>(
    stream: S,
    state: DaemonState,
    runner: Arc<dyn CommandRunner + Send + Sync>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let executor: Arc<dyn ActionExecutor> = Arc::new(crate::executor::RealActionExecutor);
    vsock_connection_handler_with_executor(stream, state, runner, executor).await;
}

/// Vsock handler with explicit executor (used by integration tests).
#[cfg(target_os = "linux")]
pub async fn vsock_connection_handler_with_executor<S>(
    stream: S,
    state: DaemonState,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    executor: Arc<dyn ActionExecutor>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut framed = FramedStream::new(stream);

    let token_path = crate::auth::default_token_path();
    let caller = match authenticate_vsock_token(&mut framed, &token_path).await {
        // A pre-shared token proves possession of a file, not the identity of a
        // person. Recording it as such keeps the chain honest: any holder of
        // that token could have made this call.
        Some(role) => CallerAttribution::from_vsock_token(role),
        None => {
            eprintln!("[sysknife-daemon] vsock auth failed; closing connection");
            return;
        }
    };

    dispatch_loop(&mut framed, state, runner, executor, caller).await;
}

/// Inner handler that accepts an explicit [`ActionExecutor`].
///
/// Production code enters via [`unix_connection_handler`] or
/// [`vsock_connection_handler`]; tests call this directly with a mock executor.
pub async fn connection_handler_with_executor<S>(
    stream: S,
    state: DaemonState,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    executor: Arc<dyn ActionExecutor>,
    caller: CallerAttribution,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut framed = FramedStream::new(stream);
    dispatch_loop(&mut framed, state, runner, executor, caller).await;
}

// ---------------------------------------------------------------------------
// Vsock token authentication
// ---------------------------------------------------------------------------

/// Receive the first frame, parse the auth message, and validate the token.
///
/// Returns the granted `CallerRole` on success, or `None` if the frame is
/// malformed or the token does not match the stored value. Every rejection
/// path logs a distinct, operator-facing `eprintln!` naming the specific
/// cause (timeout, framing error, malformed JSON, wrong frame type, or a bad
/// token) so operators can diagnose vsock auth failures from server logs.
/// The response sent back to the *client* stays a uniform generic rejection
/// regardless of cause — these logs are server-side only and must never be
/// used to build a client-observable auth oracle.
///
/// RESIDUAL RISK (#152): the token is a pre-shared **bearer** credential sent in
/// the clear as this first frame. Anyone who can observe one legitimate vsock
/// connection can read it and authenticate as the configured role, then mint a
/// fresh approval receipt — the approval/claim layers stop replay of a captured
/// request, not an attacker who holds the token. This is inherent to a bearer
/// token over an unencrypted channel and cannot be closed here; the threat
/// model, operator mitigations (isolate the vsock namespace, prefer forwarding
/// the Unix socket over `ssh -L`), and the paths to fully close it (a
/// nonce/HMAC challenge, or TLS/WireGuard under vsock) are documented in
/// SECURITY.md under "vsock transport authentication".
async fn authenticate_vsock_token(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    token_path: &std::path::Path,
) -> Option<CallerRole> {
    #[derive(serde::Deserialize)]
    struct AuthFrame {
        #[serde(rename = "type")]
        msg_type: String,
        token: String,
    }

    let recv_result = tokio::time::timeout(
        std::time::Duration::from_secs(VSOCK_AUTH_FRAME_TIMEOUT_SECS),
        framed.recv(),
    )
    .await;
    let Ok(frame_result) = recv_result else {
        eprintln!(
            "[sysknife-daemon] vsock auth: timed out waiting for auth frame after {VSOCK_AUTH_FRAME_TIMEOUT_SECS}s"
        );
        return None;
    };
    let raw = match frame_result {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("[sysknife-daemon] vsock auth: framing error reading auth frame: {e}");
            return None;
        }
    };
    let auth: AuthFrame = match serde_json::from_slice(&raw) {
        Ok(auth) => auth,
        Err(e) => {
            eprintln!("[sysknife-daemon] vsock auth: malformed auth frame JSON: {e}");
            return None;
        }
    };
    if auth.msg_type != "auth" {
        eprintln!(
            "[sysknife-daemon] vsock auth: unexpected frame type {:?} (expected \"auth\")",
            auth.msg_type
        );
        return None;
    }
    let role = crate::auth::validate_token_against_file(&auth.token, token_path);
    if role.is_none() {
        eprintln!("[sysknife-daemon] vsock auth: token did not validate against token file");
    }
    role
}

// ---------------------------------------------------------------------------
// Main dispatch loop (shared by Unix and vsock paths)
// ---------------------------------------------------------------------------

/// How long a connection may wait for its next request before the daemon
/// closes it and frees the connection slot. Generous enough for an
/// interactive session (preview → read the plan → approve in another
/// terminal → execute), short enough that idle sockets cannot pin the
/// `MAX_CONNECTIONS` pool indefinitely.
const IDLE_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// How long a freshly accepted connection may stay silent before its first
/// request.
///
/// The idle bound above exists so a parked connection cannot squat a
/// `MAX_CONNECTIONS` permit forever, but 15 minutes is a generous allowance to
/// hand a peer that has not yet proved it wants anything. Every real client
/// writes its request immediately after `connect()`, so the pre-request window
/// can be short — and it is the cheapest window to abuse, because occupying it
/// needs only socket-group membership, not any mutating role.
const FIRST_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Read deadline for the next frame, given how many requests this connection
/// has already been served.
///
/// Split out as a pure function so the policy is unit-testable without driving
/// a socket through a paused clock.
fn read_deadline(requests_served: usize) -> std::time::Duration {
    if requests_served == 0 {
        FIRST_REQUEST_TIMEOUT
    } else {
        IDLE_CONNECTION_TIMEOUT
    }
}

async fn dispatch_loop<S>(
    framed: &mut FramedStream<S>,
    state: DaemonState,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    executor: Arc<dyn ActionExecutor>,
    caller: CallerAttribution,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut requests_served: usize = 0;
    loop {
        // Bound how long a connection may sit idle between requests.
        //
        // Without this, the lowest-privilege caller can open MAX_CONNECTIONS
        // sockets, never write a byte, and hold every semaphore permit
        // forever — the next connection is dropped at accept, including one
        // from an Admin trying to approve something. The pre-auth vsock path
        // already bounds its handshake for exactly this reason; the post-auth
        // loop had no equivalent on either transport.
        //
        // This is an *idle* bound: it only applies while waiting for the next
        // request. A long-running action is executing inside a handler, not
        // parked here, so a 45-minute upgrade is unaffected.
        let deadline = read_deadline(requests_served);
        let raw = match tokio::time::timeout(deadline, framed.recv()).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(FramingError::Io(_))) => break, // peer closed
            Ok(Err(FramingError::MessageTooLarge(_))) => break, // framing violation
            Err(_) => {
                if requests_served == 0 {
                    eprintln!(
                        "[sysknife-daemon] closing connection that sent no request within {}s",
                        deadline.as_secs()
                    );
                } else {
                    eprintln!(
                        "[sysknife-daemon] closing connection idle for more than {}s",
                        deadline.as_secs()
                    );
                }
                break;
            }
        };
        requests_served += 1;

        let msg: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[sysknife-daemon] malformed JSON from client, closing connection: {e}");
                break;
            }
        };

        let request: DaemonRequest = match serde_json::from_value(msg) {
            Ok(r) => r,
            Err(e) => {
                if let Err(send_err) = send_error(
                    framed,
                    "",
                    "validation_failure",
                    format!("unknown message type: {e}"),
                )
                .await
                {
                    eprintln!(
                        "[sysknife-daemon] failed to send validation error response: {send_err}"
                    );
                }
                continue;
            }
        };

        let result = match &request {
            DaemonRequest::QueryState { request_id } => {
                handle_query_state(framed, Arc::clone(&runner), request_id).await
            }
            DaemonRequest::Preview {
                request_id,
                action_name,
                params,
                unattended,
            } => {
                handle_preview(
                    framed,
                    &state,
                    Arc::clone(&runner),
                    &caller,
                    request_id,
                    action_name,
                    params,
                    *unattended,
                )
                .await
            }
            DaemonRequest::Execute {
                request_id,
                transaction_id,
                action_name,
                params,
                approval_receipt,
            } => {
                handle_execute(
                    framed,
                    &state,
                    Arc::clone(&executor),
                    Arc::clone(&runner),
                    &caller,
                    request_id,
                    transaction_id,
                    action_name,
                    params,
                    approval_receipt,
                )
                .await
            }
            DaemonRequest::Approve {
                request_id,
                transaction_id,
            } => handle_approve(framed, &state, &caller, request_id, transaction_id.as_str()).await,
            DaemonRequest::ApprovalDetails {
                request_id,
                transaction_id,
            } => {
                handle_approval_details(
                    framed,
                    &state,
                    &caller,
                    request_id,
                    transaction_id.as_str(),
                )
                .await
            }
            DaemonRequest::QueryAction {
                request_id,
                action_name,
                params,
            } => {
                handle_query_action(
                    framed,
                    Arc::clone(&executor),
                    &state,
                    action_name,
                    params,
                    request_id,
                )
                .await
            }
            DaemonRequest::QueryHistory {
                request_id,
                limit,
                status_filter,
                action_filter,
                since_hours,
            } => {
                handle_query_history(
                    framed,
                    &state,
                    request_id,
                    *limit,
                    status_filter.clone(),
                    action_filter.clone(),
                    *since_hours,
                )
                .await
            }
            DaemonRequest::Describe {
                request_id,
                action_name,
                params,
            } => handle_describe(framed, &state, &caller, action_name, params, request_id).await,
            DaemonRequest::Cancel {
                request_id,
                transaction_id,
            } => handle_cancel(framed, &state, &caller, request_id, transaction_id.as_str()).await,
        };

        if let Err(e) = result {
            // A framing error occurred while sending a response. Log it and
            // continue; the next recv() will return Err if the peer is gone.
            eprintln!("[sysknife-daemon] connection handler send error: {e}");
        }
    }
}

fn receipt_digest(receipt: &str) -> String {
    hex::encode(Sha256::digest(receipt.as_bytes()))
}

async fn handle_approve(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    caller: &CallerAttribution,
    request_id: &str,
    transaction_id: &str,
) -> Result<(), HandlerError> {
    if !authorize_for_transaction(
        framed,
        state,
        caller,
        request_id,
        transaction_id,
        "stale_approval",
        "transaction is missing, expired, already approved, or no longer queued",
    )
    .await?
    {
        return Ok(());
    }
    let receipt = match state.audit.approve_transaction(transaction_id).await {
        Ok(receipt) => receipt,
        // A `DatabaseInvariant` here means the stored approval commitment does
        // not match the signed preview (tamper / key mismatch) — a fail-closed
        // integrity signal, NOT a transient blip. Reporting it as transient
        // would falsely tell the user a retry will help; it will fail
        // identically. Surface it as a distinct, non-retryable category.
        Err(e @ crate::transactions::TransactionStoreError::DatabaseInvariant(_)) => {
            return send_error(
                framed,
                request_id,
                "integrity_failure",
                format!("approval rejected by an integrity check: {e}"),
            )
            .await;
        }
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to persist approval: {e}"),
            )
            .await;
        }
    };
    let Some(receipt) = receipt else {
        return send_error(
            framed,
            request_id,
            "stale_approval",
            "transaction is missing, expired, already approved, or no longer queued",
        )
        .await;
    };
    let response = send_response(
        framed,
        &DaemonResponse::ApprovalResponse {
            request_id: request_id.to_string(),
            transaction_id: transaction_id.to_string(),
            approval_receipt: receipt,
        },
    )
    .await;
    if response.is_err() {
        if let Err(e) = state.audit.revoke_unconsumed_approval(transaction_id).await {
            eprintln!(
                "[sysknife-daemon] failed to revoke undelivered approval for \
                 {transaction_id}: {e}"
            );
        }
    }
    response
}

async fn handle_approval_details(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    caller: &CallerAttribution,
    request_id: &str,
    transaction_id: &str,
) -> Result<(), HandlerError> {
    match caller_owns_transaction(state, caller, transaction_id).await {
        Ownership::Owned | Ownership::NoSuchTransaction => {}
        Ownership::NotOwned => {
            return send_error(
                framed,
                request_id,
                "authorization_failure",
                not_your_transaction_message(transaction_id),
            )
            .await;
        }
        Ownership::CannotEstablish(message) => {
            return send_error(framed, request_id, "authorization_failure", message).await;
        }
    }
    let transaction = match state.audit.get(transaction_id).await {
        Ok(Some(transaction)) if transaction.status == JobState::Queued => transaction,
        Ok(_) => {
            return send_error(
                framed,
                request_id,
                "stale_approval",
                "transaction is missing or no longer queued",
            )
            .await;
        }
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to load transaction: {e}"),
            )
            .await;
        }
    };
    if !authorize_action(&state.policy, &caller.role(), &transaction.action_name) {
        return send_error(
            framed,
            request_id,
            "authorization_failure",
            authorization_failure_message(&state.policy, &caller.role(), &transaction.action_name),
        )
        .await;
    }
    let preview = match state.audit.get_preview(transaction_id).await {
        Ok(Some(preview)) => preview,
        Ok(None) => {
            return send_error(
                framed,
                request_id,
                "stale_approval",
                "transaction has no persisted preview",
            )
            .await;
        }
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to load preview: {e}"),
            )
            .await;
        }
    };
    send_response(
        framed,
        &DaemonResponse::ApprovalDetailsResponse {
            request_id: request_id.to_string(),
            transaction_id: transaction_id.to_string(),
            action_name: transaction.action_name,
            preview,
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Per-request handlers
// ---------------------------------------------------------------------------

async fn handle_query_state(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    request_id: &str,
) -> Result<(), HandlerError> {
    // collect_state uses std::process::Command (blocking). Offload to the
    // blocking thread pool so the async executor is not stalled.
    let join_result = tokio::task::spawn_blocking(move || collect_state(&*runner))
        .await
        .map_err(|e| HandlerError::Internal(format!("collect_state task failed: {e}")))?;
    let collected = match join_result {
        Ok(s) => s,
        Err(e) => {
            return send_error(framed, request_id, "state_collection_failed", e.to_string()).await;
        }
    };
    send_response(
        framed,
        &DaemonResponse::StateResponse {
            request_id: request_id.to_string(),
            state: collected,
        },
    )
    .await
}

async fn handle_cancel(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    caller: &CallerAttribution,
    request_id: &str,
    transaction_id: &str,
) -> Result<(), HandlerError> {
    if !authorize_for_transaction(
        framed,
        state,
        caller,
        request_id,
        transaction_id,
        "not_cancelable",
        "transaction cannot be canceled: it is missing, already executing, or finished",
    )
    .await?
    {
        return Ok(());
    }
    match state.audit.cancel_queued(transaction_id).await {
        Ok(true) => {
            send_response(
                framed,
                &DaemonResponse::CancelResponse {
                    request_id: request_id.to_string(),
                    transaction_id: transaction_id.to_string(),
                },
            )
            .await
        }
        // Fail closed and informative: the only cancelable state is Queued.
        // A Running action is deliberately never interrupted (Option A).
        Ok(false) => {
            send_error(
                framed,
                request_id,
                "not_cancelable",
                "transaction cannot be canceled: it is missing, already executing, or finished",
            )
            .await
        }
        Err(e) => {
            send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to cancel transaction: {e}"),
            )
            .await
        }
    }
}

async fn handle_query_history(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    request_id: &str,
    limit: Option<u32>,
    status_filter: Option<String>,
    action_filter: Option<String>,
    since_hours: Option<u32>,
) -> Result<(), HandlerError> {
    // Honour the SAME `[policy.risk_overrides]` gate as the `ListJobHistory`
    // action (see handle_query_action): if an operator raised history above
    // Observer, this structured path must refuse it too, otherwise it would be
    // an authorization bypass around that policy. History is keyed on the
    // `ListJobHistory` action so a single override governs both paths.
    match state.policy.min_role_for_action("ListJobHistory") {
        Some(CallerRole::Observer) => {}
        Some(_) => {
            return send_error(
                framed,
                request_id,
                "authorization_failure",
                "history has been restricted above read-only by policy; \
                 it is not available over the structured query path",
            )
            .await;
        }
        None => {
            return send_error(
                framed,
                request_id,
                "validation_failure",
                "ListJobHistory action is not registered",
            )
            .await;
        }
    }

    let entries = match state
        .audit
        .list_history(
            limit.unwrap_or(DEFAULT_HISTORY_LIMIT),
            status_filter.as_deref(),
            action_filter.as_deref(),
            since_hours,
        )
        .await
    {
        Ok(entries) => entries,
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "execution_failure",
                format!("failed to query transaction history: {e}"),
            )
            .await;
        }
    };
    send_response(
        framed,
        &DaemonResponse::HistoryResponse {
            request_id: request_id.to_string(),
            entries,
        },
    )
    .await
}

async fn handle_query_action(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    executor: Arc<dyn ActionExecutor>,
    state: &DaemonState,
    action_name: &str,
    params: &Value,
    request_id: &str,
) -> Result<(), HandlerError> {
    let audit = &state.audit;

    // Honour `[policy.risk_overrides]`: an operator can RAISE a previously
    // Low-risk action above Observer, in which case the unprivileged query
    // path must reject it (matching the preview+execute path).
    let min_role = match state.policy.min_role_for_action(action_name) {
        Some(role) => role,
        None => {
            return send_error(
                framed,
                request_id,
                "validation_failure",
                format!("unknown action: {action_name}"),
            )
            .await;
        }
    };

    if min_role != CallerRole::Observer {
        return send_error(
            framed,
            request_id,
            "authorization_failure",
            format!("{action_name} is not a read-only action; use preview+execute instead"),
        )
        .await;
    }

    // Risk answers how much authorization an action needs; it does not prove
    // that an action is read-only. `AptUpdate`, for example, is Low/Observer but
    // runs `sudo apt-get update`, writes the root apt index and takes the dpkg
    // lock. The shared catalogue exception keeps this raw IPC path aligned with
    // the generated MCP surface instead of letting direct clients bypass the
    // preview, receipt and exclusion gates.
    if crate::actions::OBSERVER_MUTATING_ACTIONS.contains(&action_name) {
        return send_error(
            framed,
            request_id,
            "authorization_failure",
            format!(
                "{action_name} mutates the host and is not available through query_action; \
                 use preview+execute instead"
            ),
        )
        .await;
    }

    // Same fence preview and execute apply. Without it a Fedora-only read-only
    // action reached the executor on a Debian host and failed as "rpm-ostree:
    // No such file or directory" — an execution error where the other paths
    // give a clean refusal. A read-only action with no family requirement shorts
    // out inside `validate_action_platform`; one *with* a family requirement is
    // checked against the family but exempt from the eligibility and
    // detection gates, which are mutation gates by contract.
    if let Err(message) = validate_action_platform(state, action_name) {
        return send_error(framed, request_id, "unsupported_platform", message).await;
    }

    // Special case: ListJobHistory queries the daemon's own transaction
    // store rather than executing a system command. Handle it here to
    // avoid routing through the ActionSpec/executor path.
    if action_name == "ListJobHistory" {
        let limit = match params.get("limit") {
            Some(v) => match v.as_u64() {
                Some(n) => n as u32,
                None => {
                    return send_error(
                        framed,
                        request_id,
                        "validation_failure",
                        format!("'limit' must be an integer, got: {v}"),
                    )
                    .await;
                }
            },
            None => DEFAULT_HISTORY_LIMIT,
        };
        let status_filter = params
            .get("status_filter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let action_filter = params
            .get("action_filter")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let since_hours = match params.get("since_hours") {
            Some(v) => match v.as_u64() {
                Some(n) => Some(n as u32),
                None => {
                    return send_error(
                        framed,
                        request_id,
                        "validation_failure",
                        format!("'since_hours' must be an integer, got: {v}"),
                    )
                    .await;
                }
            },
            None => None,
        };

        let records = match audit
            .list_transactions(
                limit,
                status_filter.as_deref(),
                action_filter.as_deref(),
                since_hours,
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return send_error(
                    framed,
                    request_id,
                    "execution_failure",
                    format!("failed to query transaction log: {e}"),
                )
                .await;
            }
        };

        let output = if records.is_empty() {
            let mut msg = "No transactions found".to_string();
            let mut filters = Vec::new();
            if let Some(s) = &status_filter {
                filters.push(format!("status={s}"));
            }
            if let Some(a) = &action_filter {
                filters.push(format!("action={a}"));
            }
            if let Some(h) = since_hours {
                filters.push(format!("since_hours={h}"));
            }
            if !filters.is_empty() {
                msg.push_str(&format!(" (filters: {})", filters.join(", ")));
            }
            msg.push('.');
            msg
        } else {
            format_job_history(&records)
        };
        return send_response(
            framed,
            &DaemonResponse::QueryActionResponse {
                request_id: request_id.to_string(),
                action_name: action_name.to_string(),
                output,
            },
        )
        .await;
    }

    let spec = match build_action_spec(action_name, params) {
        Ok(s) => s,
        Err(e) => {
            return send_error(framed, request_id, "validation_failure", e.to_string()).await;
        }
    };

    let output = match executor.execute(&spec).await {
        Ok(out) => out,
        Err(e) => {
            return send_error(framed, request_id, "execution_failure", e.to_string()).await;
        }
    };

    // Non-zero exit codes from read-only actions must not be silently presented
    // as successful output. The LLM would receive error text as if it were valid
    // system state, leading to incorrect planning decisions.
    //
    // Some commands use non-zero exit codes as semantic signals rather than
    // error indicators.  These are whitelisted here so the informative stdout
    // is passed through to the caller instead of being discarded.
    //
    // - systemctl status <unit>: exits 1 when inactive, 3 when dead/failed, 4 when not
    //   found.  All produce informative output the planner needs for diagnosis.
    let is_informational_exit =
        matches!((action_name, output.exit_code), ("GetServiceStatus", 1..=4));

    if output.is_nonzero() && !is_informational_exit {
        return send_error(
            framed,
            request_id,
            "execution_failure",
            format!(
                "{action_name} failed with exit code {}{}",
                output.exit_code,
                if output.stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", output.stderr.trim())
                }
            ),
        )
        .await;
    }

    let output_text = if output.stderr.is_empty() {
        output.stdout
    } else {
        format!("{}\n[stderr]\n{}", output.stdout, output.stderr)
    };

    send_response(
        framed,
        &DaemonResponse::QueryActionResponse {
            request_id: request_id.to_string(),
            action_name: action_name.to_string(),
            output: output_text,
        },
    )
    .await
}

/// Return a human-readable command string for an action without executing it.
///
/// Resolves `build_action_spec(action_name, params)` and formats the
/// `ActionMechanism` as a shell-style string so callers can show the user
/// exactly what will run.
async fn handle_describe(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    caller: &CallerAttribution,
    action_name: &str,
    params: &Value,
    request_id: &str,
) -> Result<(), HandlerError> {
    use crate::actions::ActionMechanism;
    use crate::executor::build_action_spec;

    // Describe renders the exact command an action would run. It used to apply
    // neither the authorization gate nor the platform fence, so any caller
    // could enumerate the argv of every privileged action on the host and get
    // a rendered command for actions this distro cannot run. Both gates match
    // `handle_preview` so the three read paths agree on who may ask what.
    //
    // Unknown actions are rejected first: an unrecognised name is a client
    // error, and reporting it as an authorization failure would both mislead
    // the caller and make "does this action exist" indistinguishable from
    // "am I allowed to see it" — which is the wrong trade for a name the
    // catalogue is public about anyway.
    if state.policy.min_role_for_action(action_name).is_none() {
        return send_error(
            framed,
            request_id,
            "validation_failure",
            format!("unknown action: {action_name}"),
        )
        .await;
    }
    if !authorize_action(&state.policy, &caller.role(), action_name) {
        return send_error(
            framed,
            request_id,
            "authorization_failure",
            authorization_failure_message(&state.policy, &caller.role(), action_name),
        )
        .await;
    }
    if let Err(message) = validate_action_platform(state, action_name) {
        return send_error(framed, request_id, "unsupported_platform", message).await;
    }

    // ListJobHistory is handled directly in the dispatcher (SQLite query) and
    // has no ActionSpec.  Return a synthetic describe response so callers get a
    // meaningful `command` string instead of a validation_failure error.
    if action_name == "ListJobHistory" {
        return send_response(
            framed,
            &DaemonResponse::DescribeResponse {
                request_id: request_id.to_string(),
                command: "query daemon job history (SQLite)".to_string(),
                risk_level: "low".to_string(),
                reboot_required: false,
            },
        )
        .await;
    }

    let spec = match build_action_spec(action_name, params) {
        Ok(s) => s,
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "validation_failure",
                format!("unknown action: {action_name} ({e})"),
            )
            .await;
        }
    };

    let command = match &spec.mechanism {
        ActionMechanism::Command { program, args } => {
            // Redact any argv element that matches a credential param value
            // before rendering — `ProAttach` carries the token in argv and
            // this is the place a describe response would otherwise leak it.
            let display_args = redact_argv(action_name, params, args);
            if display_args.is_empty() {
                program.to_string()
            } else {
                format!("{} {}", program, display_args.join(" "))
            }
        }
        ActionMechanism::FileScan { path } => format!("read {path}"),
        ActionMechanism::FileWrite { path, .. } => format!("write {path}"),
        ActionMechanism::FilePatch { path, .. } => format!("patch {path}"),
        ActionMechanism::FileDelete { path } => format!("rm {path}"),
    };

    let risk_level = format!("{:?}", spec.risk_level).to_lowercase();

    send_response(
        framed,
        &DaemonResponse::DescribeResponse {
            request_id: request_id.to_string(),
            command,
            risk_level,
            reboot_required: spec.reboot_required,
        },
    )
    .await
}

/// Recorded in the signed transaction row when a client declares that its
/// approval gate was lifted for the run.
///
/// The exact string is part of the wire contract: the CLI looks for it in the
/// returned warnings and refuses to execute if it is absent, which is how a
/// new client detects that it is talking to a daemon too old to record the
/// fact. Changing the text breaks that check, so change it deliberately.
pub const UNATTENDED_WARNING: &str =
    "Approved without a human: this step was previewed by a client running with \
     --dangerously-skip-approval, so no operator confirmed it.";

// Eight arguments, matching `handle_execute` and `run_action_job` below. The
// alternative is a struct that exists only to carry the request body one frame
// deeper, and the frames it would cross are the ones a reader of this file
// most wants to see spelled out.
#[allow(clippy::too_many_arguments)]
async fn handle_preview(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    caller: &CallerAttribution,
    request_id: &str,
    action_name: &str,
    params: &Value,
    unattended: bool,
) -> Result<(), HandlerError> {
    let spec = match build_action_spec(action_name, params) {
        Ok(s) => s,
        Err(e) => {
            return send_error(framed, request_id, "validation_failure", e.to_string()).await;
        }
    };

    if !authorize_action(&state.policy, &caller.role(), action_name) {
        return send_error(
            framed,
            request_id,
            "authorization_failure",
            authorization_failure_message(&state.policy, &caller.role(), action_name),
        )
        .await;
    }
    if let Err(message) = validate_action_platform(state, action_name) {
        return send_error(framed, request_id, "unsupported_platform", message).await;
    }

    let request_hash = compute_request_hash(action_name, params);

    // Snapshot current state for the preview. collect_state uses
    // std::process::Command (blocking), so offload to the blocking thread pool.
    // State is best-effort: if collection fails, the preview is generated with
    // an empty state and a warning is logged rather than aborting the preview.
    let runner_for_preview = Arc::clone(&runner);
    let current_state =
        match tokio::task::spawn_blocking(move || collect_state(&*runner_for_preview)).await {
            Err(e) => {
                eprintln!(
                    "[sysknife-daemon] handle_preview: collect_state task failed ({e}); \
                 generating preview with empty state"
                );
                Value::Null
            }
            Ok(Err(e)) => {
                eprintln!(
                    "[sysknife-daemon] handle_preview: state collection failed ({e}); \
                 generating preview with empty state"
                );
                Value::Null
            }
            Ok(Ok(s)) => match serde_json::to_value(&s) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                    "[sysknife-daemon] handle_preview: failed to serialize collected state ({e}); \
                     using empty state"
                );
                    Value::Null
                }
            },
        };
    // Redact credentials before assembling the payload that gets persisted
    // to the transactions table AND returned in PreviewResponse. The
    // RequestEnvelope keeps the original params because the daemon needs the
    // real values to actually run the action — the envelope never leaves
    // this process. proposed_change DOES leave the process and must be
    // scrubbed.
    let redacted_params = redact_params(action_name, params);
    let mut proposed_change = json!({ "action": action_name, "params": redacted_params });

    // AptAutoremove resolves its deletion set at run time, so capture the exact
    // set the operator is about to approve and bind execute to it (#151). The
    // set is shown in the preview and re-checked before the real autoremove runs.
    let mut autoremove_warning: Option<String> = None;
    if action_name == "AptAutoremove" {
        match simulate_autoremove_set(&runner).await {
            Ok(set) => {
                autoremove_warning = autoremove_kernel_warning(&set);
                proposed_change[AUTOREMOVE_REMOVALS_KEY] =
                    json!(set.iter().collect::<Vec<&String>>());
            }
            Err(e) => {
                // Do NOT record a set: execute fails closed (verify_autoremove_binding
                // refuses a preview with no captured set), so a simulate failure at
                // preview cannot become an unbound autoremove at execute.
                eprintln!("[sysknife-daemon] handle_preview: autoremove simulate failed: {e}");
                autoremove_warning = Some(
                    "Could not compute which packages autoremove would delete; approving this \
                     preview will not let it run until a preview captures the set."
                        .to_string(),
                );
            }
        }
    }

    let envelope = RequestEnvelope {
        action_name: action_name.to_string(),
        request_id: request_id.to_string(),
        params: params.clone(),
        caller_role: caller.role(),
        request_hash: sysknife_types::RequestHash::new(request_hash.to_string()),
    };

    // If state collection failed above, current_state is Null (collect_state
    // never yields null on success). Surface that in the client-visible
    // warnings — not just daemon stderr — so a human approving a high-risk
    // action knows the "current state" backing this preview is missing.
    let state_unavailable = current_state.is_null();
    let mut preview = preview_action(&envelope, current_state, proposed_change);
    if let Some(w) = autoremove_warning {
        preview.warnings.push(w);
    }
    if state_unavailable {
        preview.warnings.push(
            "System state could not be collected; this preview was generated without it. \
             Review the action carefully before approving."
                .to_string(),
        );
    }
    // Recorded, not trusted. `warnings` is copied into `NewTransaction` below
    // and signed as `warnings_json`, so this sentence is inside the Ed25519
    // commitment for the row: an unattended run cannot later be presented as
    // one a human approved without the signature failing to verify.
    if unattended {
        preview.warnings.push(UNATTENDED_WARNING.to_string());
    }

    // Persist a pending transaction so execute can verify a prior preview.
    let new_tx = NewTransaction {
        request_id: request_id.to_string(),
        request_hash,
        action_name: action_name.to_string(),
        risk_level: spec.risk_level,
        summary: preview.summary.clone(),
        warnings: preview.warnings.clone(),
        // Both resolved by the daemon from the connection, never read from the
        // request body. The role says what was permitted; the principal says
        // which account asked, which is the question an audit starts with.
        caller_role: caller.role(),
        caller_principal: caller.principal(),
    };

    let recorded = match state.audit.record_previewed(new_tx, preview.clone()).await {
        Ok(r) => r,
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to record preview transaction: {e}"),
            )
            .await;
        }
    };

    // External SIEM forwarding. Best-effort, never blocks the preview
    // response — if the forwarder queue is full or its task is gone, the
    // event is dropped (with a counter + WARN). The local hash-chained log
    // is always written first; the SIEM receives a copy.
    forward_audit_event(state, &recorded.transaction.transaction_id, &caller.role());

    send_response(
        framed,
        &DaemonResponse::PreviewResponse {
            request_id: request_id.to_string(),
            preview,
            transaction_id: recorded.transaction.transaction_id,
        },
    )
    .await
}

/// Look up the just-inserted row's chain metadata and submit an
/// `AuditEvent` to the configured forwarder, if any.
///
/// Failures here are non-fatal — the local audit log is the durable record.
/// Spawned in the background so the preview response is not delayed by the
/// audit-store fetch (true fire-and-forget across both SQLite and Postgres
/// backends).
fn forward_audit_event(state: &DaemonState, transaction_id: &str, caller: &CallerRole) {
    let Some(forwarder) = state.forwarder.clone() else {
        return;
    };
    let audit = std::sync::Arc::clone(&state.audit);
    let transaction_id = transaction_id.to_string();
    let caller_label = format!("{caller:?}");
    tokio::spawn(async move {
        match audit.fetch_chain_row(&transaction_id).await {
            Ok(Some(row)) => {
                forwarder.submit(crate::audit_forward::AuditEvent {
                    seq: row.seq,
                    transaction_id: row.transaction_id,
                    action_name: row.action_name,
                    risk_level: row.risk_level,
                    summary: row.summary,
                    approval_id: row.approval_id,
                    created_at: row.created_at,
                    chain_hash: row.chain_hash,
                    key_id: row.key_id,
                    caller_role: Some(caller_label),
                    // From the row, not the connection: the SIEM should see the
                    // account the chain committed to.
                    caller_principal: row.caller_principal,
                    final_status: None,
                });
            }
            Ok(None) => {
                eprintln!(
                    "[sysknife-daemon] audit-forward: transaction {transaction_id} \
                     not found just after insert (race?)"
                );
            }
            Err(e) => {
                eprintln!(
                    "[sysknife-daemon] audit-forward: chain row fetch failed for \
                     {transaction_id}: {e}"
                );
            }
        }
    });
}

/// Submit a status-change `AuditEvent` to the configured forwarder after
/// `update_status` records the terminal `JobState`.
///
/// Without this, SOC analysts watching the SIEM see the preview event but
/// never see whether the action ran, succeeded, failed, or was rolled back —
/// the local hash-chained log carries the terminal status, but the SIEM does
/// not. Mirrors [`forward_audit_event`]: bails when no forwarder is wired,
/// looks up the chain row in a background task, and sets `final_status` to
/// the lowercase Debug rendering of the terminal `JobState` so the
/// `terminal_status` SD-PARAM appears in the emitted RFC 5424 frame.
fn forward_status_change_event(
    state: &DaemonState,
    transaction_id: &str,
    caller: &CallerRole,
    final_status: JobState,
) {
    if state.forwarder.is_none() {
        return;
    }
    let audit = std::sync::Arc::clone(&state.audit);
    let forwarder = state.forwarder.clone().expect("checked above");
    let transaction_id = transaction_id.to_string();
    let caller_label = format!("{caller:?}");
    let final_status_label = format!("{final_status:?}").to_lowercase();
    tokio::spawn(async move {
        match audit.fetch_chain_row(&transaction_id).await {
            Ok(Some(row)) => {
                forwarder.submit(crate::audit_forward::AuditEvent {
                    seq: row.seq,
                    transaction_id: row.transaction_id,
                    action_name: row.action_name,
                    risk_level: row.risk_level,
                    summary: row.summary,
                    approval_id: row.approval_id,
                    created_at: row.created_at,
                    chain_hash: row.chain_hash,
                    key_id: row.key_id,
                    caller_role: Some(caller_label),
                    caller_principal: row.caller_principal,
                    final_status: Some(final_status_label),
                });
            }
            Ok(None) => {
                eprintln!(
                    "[sysknife-daemon] audit-forward: transaction {transaction_id} \
                     not found for status-change forward (race?)"
                );
            }
            Err(e) => {
                eprintln!(
                    "[sysknife-daemon] audit-forward: chain row fetch failed for \
                     {transaction_id}: {e}"
                );
            }
        }
    });
}

/// Release every exclusion lock this request claimed.
///
/// Each entry is removed only when it still records *this* request's hash, so
/// a late release can never evict a lock a different job has since taken.
async fn release_exclusive_slots(
    state: &DaemonState,
    claimed: &[crate::actions::ExclusiveResource],
    request_hash: &str,
) {
    if claimed.is_empty() {
        return;
    }

    let mut slots = state.running_exclusive.lock().await;
    for resource in claimed {
        if slots.get(resource).map(String::as_str) == Some(request_hash) {
            slots.remove(resource);
        }
    }
}

/// Total attempts to persist a terminal transaction status before giving up.
/// Terminal writes are an audit-trail obligation, so a transient store error
/// is worth a few short retries; three keeps the worst-case latency bounded
/// (see [`TERMINAL_STATUS_RETRY_BACKOFF_MS`]) while surviving a brief blip.
const TERMINAL_STATUS_RETRY_ATTEMPTS: u32 = 3;
/// Linear backoff base between terminal-status retries. Attempt `n` waits
/// `BACKOFF_MS * (n + 1)`, i.e. 25 ms then 50 ms — long enough to let a
/// momentarily busy SQLite writer drain, short enough not to stall the client.
const TERMINAL_STATUS_RETRY_BACKOFF_MS: u64 = 25;

async fn update_terminal_status(
    state: &DaemonState,
    transaction_id: &str,
    target: JobState,
) -> Result<(), crate::transactions::TransactionStoreError> {
    for attempt in 0..TERMINAL_STATUS_RETRY_ATTEMPTS {
        match state.audit.update_status(transaction_id, target).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                // A `get` failure here collapses to `None` and is deliberately
                // swallowed: it cannot manufacture a false success, it only
                // costs one more retry before the original `error` propagates.
                if state
                    .audit
                    .get(transaction_id)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|record| record.status == target)
                {
                    return Ok(());
                }
                if attempt == TERMINAL_STATUS_RETRY_ATTEMPTS - 1 {
                    return Err(error);
                }
                tokio::time::sleep(std::time::Duration::from_millis(
                    TERMINAL_STATUS_RETRY_BACKOFF_MS * u64::from(attempt + 1),
                ))
                .await;
            }
        }
    }
    unreachable!("bounded retry loop always returns")
}

#[allow(clippy::too_many_arguments)]
async fn handle_execute(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    state: &DaemonState,
    executor: Arc<dyn ActionExecutor>,
    runner: Arc<dyn CommandRunner + Send + Sync>,
    caller: &CallerAttribution,
    request_id: &str,
    transaction_id: &TransactionId,
    action_name: &str,
    params: &Value,
    approval_receipt: &ApprovalReceipt,
) -> Result<(), HandlerError> {
    let transaction_id = transaction_id.as_str();
    let approval_receipt = approval_receipt.as_str();
    let spec = match build_action_spec(action_name, params) {
        Ok(s) => s,
        Err(e) => {
            return send_error(framed, request_id, "validation_failure", e.to_string()).await;
        }
    };

    // Checked here as well as at approve, not instead of it. A receipt is a
    // bearer token for one transaction, so an account that obtained one it was
    // never issued must still be refused at the point of execution.
    match caller_owns_transaction(state, caller, transaction_id).await {
        Ownership::Owned | Ownership::NoSuchTransaction => {}
        Ownership::NotOwned => {
            return send_error(
                framed,
                request_id,
                "authorization_failure",
                not_your_transaction_message(transaction_id),
            )
            .await;
        }
        Ownership::CannotEstablish(message) => {
            return send_error(framed, request_id, "authorization_failure", message).await;
        }
    }

    if !authorize_action(&state.policy, &caller.role(), action_name) {
        return send_error(
            framed,
            request_id,
            "authorization_failure",
            authorization_failure_message(&state.policy, &caller.role(), action_name),
        )
        .await;
    }
    if let Err(message) = validate_action_platform(state, action_name) {
        return send_error(framed, request_id, "unsupported_platform", message).await;
    }

    let submitted_hash = compute_request_hash(action_name, params);
    let prior_tx = match state.audit.get(transaction_id).await {
        Ok(tx) => tx,
        Err(e) => {
            return send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("transaction lookup failed: {e}"),
            )
            .await;
        }
    };

    let prior_tx = match prior_tx {
        Some(tx) => tx,
        None => {
            return send_error(
                framed,
                request_id,
                "stale_approval",
                "no prior preview found for this transaction; preview before executing",
            )
            .await;
        }
    };

    if prior_tx.action_name != action_name || prior_tx.request_hash != submitted_hash {
        return send_error(
            framed,
            request_id,
            "stale_approval",
            "action or parameters differ from the approved preview",
        )
        .await;
    }
    let stored_hash = prior_tx.request_hash;

    // ── Concurrency gate (ME4) ─────────────────────────────────────────────
    //
    // A High-risk reboot-required action (e.g. `UbuntuReleaseUpgrade`,
    // `AddLayeredPackage`, `RebaseSystem`) can run for 20-45 minutes and holds
    // exclusive system-wide locks (dpkg, rpm-ostree). Allowing a second
    // mutating action to interleave causes lock contention, partial-upgrade
    // corruption, or worse. Read-only (`Observer`-level) actions are never
    // mutating and skip this check entirely — they are safe to run concurrently.
    //
    // "Mutating" is defined as: the action's minimum required role is Dev or
    // higher (i.e. `min_role_for_action` returns `Dev` or `Admin`). This reuses
    // the existing policy table rather than a separate hand-maintained list.
    //
    // The slot is held for the duration of the action only when the new action
    // is itself High-risk + reboot-required; other mutating actions are blocked
    // while a high-risk action is in-flight but do not themselves set the slot.
    let is_high_risk_reboot =
        spec.risk_level == sysknife_types::RiskLevel::High && spec.reboot_required;

    let policy_says_mutating = match state.policy.min_role_for_action(action_name) {
        Some(r) => r > CallerRole::Observer,
        None => {
            // Unreachable today: `authorize_action` above rejects any action
            // the policy table does not know. Treat the miss as mutating
            // anyway — the failure direction of a lookup miss must be "gate
            // it", never "let it through ungated".
            eprintln!(
                "[sysknife-daemon] WARNING: no policy entry for {action_name:?} at the \
                 concurrency gate; treating it as mutating"
            );
            true
        }
    };

    // A High-risk reboot-required action is mutating by definition. Deriving
    // this from the spec as well as the policy table means a drift between the
    // two tables cannot silently downgrade an upgrade-class action to
    // "ungated". The previous code asserted this relationship with
    // `debug_assert!`, which is compiled out of release builds — precisely the
    // binary that ships.
    let is_mutating = policy_says_mutating || is_high_risk_reboot;
    if is_high_risk_reboot && !policy_says_mutating {
        eprintln!(
            "[sysknife-daemon] WARNING: {action_name:?} is High-risk + reboot-required but the \
             policy table does not require Dev/Admin for it; gating it as mutating anyway. \
             The risk and role tables have drifted."
        );
    }

    // Which system locks this request will hold while it runs.
    let mut to_claim: Vec<crate::actions::ExclusiveResource> = Vec::new();
    if is_high_risk_reboot {
        to_claim.push(crate::actions::ExclusiveResource::System);
    }
    let own_resource = crate::actions::exclusive_resource(&spec);
    if let Some(r) = own_resource {
        if !to_claim.contains(&r) {
            to_claim.push(r);
        }
    }
    if !is_mutating {
        to_claim.clear();
    }

    // Check the gate for any mutating action, and claim every lock it needs.
    if is_mutating {
        let mut slots = state.running_exclusive.lock().await;
        // Conflict on a system-wide job first (it excludes everything), then
        // on this action's own resource.
        let blocking = slots
            .get(&crate::actions::ExclusiveResource::System)
            .map(|h| (crate::actions::ExclusiveResource::System, h.clone()))
            .or_else(|| own_resource.and_then(|r| slots.get(&r).map(|h| (r, h.clone()))));
        if let Some((blocking_resource, running_hash)) = blocking {
            // Another mutating action already holds a lock this one needs.
            // Return a typed Conflict response so the shell can surface a
            // "wait, an upgrade is running" message rather than a generic error.
            //
            // The approval is NOT consumed by a conflict (the claim happens
            // after this gate), so it remains valid for retry — but only until
            // its TTL elapses. A high-risk reboot job can outrun that window, so
            // we tell the user up front what a long wait means, instead of
            // letting the retry fail later with a bare stale_approval.
            //
            // Re-approving the SAME transaction can never produce a "fresh"
            // receipt: the TTL check in `approve_transaction` is anchored to
            // the transaction's immutable `created_at`, not to when `approve`
            // is called, so running `sysknife approve <transaction-id>` again
            // after the window has elapsed fails identically every time. The
            // only way to get a new TTL window is a new transaction, which
            // means re-running the preview.
            let ttl = crate::transactions::APPROVAL_RECEIPT_TTL_MINUTES;
            let held = blocking_resource.label();
            let msg = format!(
                "another mutating action is already executing and holds {held} (request_hash \
                 {running_hash}); retry after the current job completes. This approval \
                 expires {ttl} minutes after it was issued, and that window is anchored to \
                 when the preview was created — re-running `sysknife approve` on this same \
                 transaction will not renew it. If the running job is still going once the \
                 window has passed, re-run the preview (which mints a fresh transaction) and \
                 approve that new transaction instead"
            );
            drop(slots); // release before I/O
            return send_response(
                framed,
                &DaemonResponse::ConflictResponse {
                    request_id: request_id.to_string(),
                    message: msg,
                    retry_after_seconds: None,
                },
            )
            .await;
        }
        // Claim every lock before releasing the mutex so no other connection
        // can race between the check and the set.
        for resource in &to_claim {
            slots.insert(*resource, stored_hash.clone());
        }
        // Lock drops here via RAII, releasing for other read-only actions.
    }

    let claimed = match state
        .audit
        .claim_approved_for_execution(transaction_id, &receipt_digest(approval_receipt))
        .await
    {
        Ok(c) => c,
        Err(e) => {
            release_exclusive_slots(state, &to_claim, &stored_hash).await;
            return send_error(
                framed,
                request_id,
                "transient_infrastructure_failure",
                format!("failed to claim transaction: {e}"),
            )
            .await;
        }
    };
    if !claimed {
        release_exclusive_slots(state, &to_claim, &stored_hash).await;
        return send_error(
            framed,
            request_id,
            "stale_approval",
            "transaction is not approved for this receipt, expired, or already consumed",
        )
        .await;
    }

    // Bind AptAutoremove to the deletion set the operator approved (#151). The
    // request hash covers only the (empty) params, so re-simulate now and refuse
    // if the set apt would remove has drifted from what the approved preview
    // captured. Placed AFTER the concurrency gate and claim (both of which can
    // block — the gate can wait minutes on a long high-risk action) and just
    // BEFORE `JobStarted`, so the verified answer is as close to execution as it
    // can cleanly be reported (a drift here is still a plain error_response) and
    // the gate wait is not part of the verified-to-executed window. This shrinks
    // that window to request handling; it cannot eliminate it, because
    // `apt-get autoremove -y` re-resolves the set itself at run time and cannot
    // be pinned to a package list — see the residual note in the CHANGELOG.
    if action_name == "AptAutoremove" {
        let approved_preview = match state.audit.get_preview(transaction_id).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                release_exclusive_slots(state, &to_claim, &stored_hash).await;
                return send_error(
                    framed,
                    request_id,
                    "stale_approval",
                    "no persisted preview for this transaction; preview before executing",
                )
                .await;
            }
            Err(e) => {
                release_exclusive_slots(state, &to_claim, &stored_hash).await;
                return send_error(
                    framed,
                    request_id,
                    "transient_infrastructure_failure",
                    format!("preview lookup failed: {e}"),
                )
                .await;
            }
        };
        let live = match simulate_autoremove_set(&runner).await {
            Ok(s) => s,
            Err(e) => {
                release_exclusive_slots(state, &to_claim, &stored_hash).await;
                return send_error(
                    framed,
                    request_id,
                    "execution_failure",
                    format!("could not confirm the autoremove set before executing: {e}"),
                )
                .await;
            }
        };
        if let Err(reason) = verify_autoremove_binding(&approved_preview.proposed_change, &live) {
            release_exclusive_slots(state, &to_claim, &stored_hash).await;
            return send_error(framed, request_id, "stale_approval", reason).await;
        }
    }

    let job_id = Uuid::new_v4().to_string();

    if let Err(send_error) = send_response(
        framed,
        &DaemonResponse::JobStarted {
            request_id: request_id.to_string(),
            job_id: job_id.clone(),
            transaction_id: transaction_id.to_string(),
        },
    )
    .await
    {
        release_exclusive_slots(state, &to_claim, &stored_hash).await;
        if let Err(status_error) =
            update_terminal_status(state, transaction_id, JobState::Failed).await
        {
            eprintln!(
                "[sysknife-daemon] failed to mark disconnected transaction {transaction_id} \
                 as Failed: {status_error}"
            );
        }
        return Err(send_error);
    }

    let _ = send_response(
        framed,
        &DaemonResponse::JobProgress {
            job_id: job_id.clone(),
            line: format!("Authorization passed for {action_name}"),
        },
    )
    .await;

    let _ = send_response(
        framed,
        &DaemonResponse::JobProgress {
            job_id: job_id.clone(),
            line: format!("Executing {action_name}..."),
        },
    )
    .await;

    // All process execution goes through ActionExecutor. This is a security
    // and testability boundary: injected executors must never fall through to
    // real privileged commands merely because an action streams output.
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
    let execution = executor.execute_with_progress(&spec, progress_tx);
    tokio::pin!(execution);
    let mut progress_open = true;
    let output = loop {
        tokio::select! {
            result = &mut execution => break result,
            line = progress_rx.recv(), if progress_open => {
                let Some(line) = line else {
                    progress_open = false;
                    continue;
                };
                if let Err(e) = send_response(
                    framed,
                    &DaemonResponse::JobProgress {
                        job_id: job_id.clone(),
                        line,
                    },
                ).await {
                    eprintln!(
                        "[sysknife-daemon] progress send failed (client disconnected?): {e}"
                    );
                }
            }
        }
    };

    // The executor may enqueue its final stdout lines and complete in the same
    // scheduler turn. Drain the closed channel so those lines are not lost when
    // `select!` observes completion first.
    while let Ok(line) = progress_rx.try_recv() {
        if let Err(e) = send_response(
            framed,
            &DaemonResponse::JobProgress {
                job_id: job_id.clone(),
                line,
            },
        )
        .await
        {
            eprintln!("[sysknife-daemon] final progress send failed: {e}");
        }
    }

    let (initial_status, initial_summary) = match &output {
        Ok(out) if out.is_success() => {
            if spec.reboot_required {
                (
                    JobState::NeedsReboot,
                    format!("{action_name} completed; reboot required"),
                )
            } else {
                (
                    JobState::Succeeded,
                    format!("{action_name} completed successfully"),
                )
            }
        }
        Ok(out) => (
            JobState::Failed,
            format!("{action_name} failed with exit code {}", out.exit_code),
        ),
        Err(e) => (JobState::Failed, format!("{action_name} failed: {e}")),
    };

    let completion_line = match &output {
        Ok(out) => format!("{action_name} completed with exit code {}", out.exit_code),
        Err(e) => format!("{action_name} completed with error: {e}"),
    };
    let _ = send_response(
        framed,
        &DaemonResponse::JobProgress {
            job_id: job_id.clone(),
            line: completion_line,
        },
    )
    .await;

    // Attempt automatic rollback if the action failed and rollback is available.
    // A deadline that could not stop the work is the one failure that must not
    // trigger one: the original action may still be running.
    let action_may_still_be_running = matches!(
        &output,
        Err(crate::executor::ExecutorError::ActionNotStopped { .. })
    );
    let (final_status, summary, rollback_ref) = attempt_rollback_if_needed(
        framed,
        &executor,
        &job_id,
        action_name,
        &spec,
        initial_status,
        initial_summary,
        action_may_still_be_running,
    )
    .await;

    // Clear the exclusion slot now that the action has finished, EXCEPT when it
    // could not be confirmed stopped. If a privileged transaction may still be
    // running, its resource is still in use, and releasing the slot would admit
    // a second mutating action to race it — the exact concurrent-transaction
    // state the rollback veto above refuses to create itself. Holding the slot
    // makes the veto binding against the operator too, not just the daemon. The
    // slot lives in memory, so a daemon restart clears it, which is the same
    // "inspect the host before retrying" recovery the error already names.
    if action_may_still_be_running {
        if !to_claim.is_empty() {
            eprintln!(
                "[sysknife-daemon] holding the exclusion slot for {action_name}: the action \
                 could not be confirmed stopped, so no other mutating action may start until \
                 the daemon is restarted"
            );
        }
    } else {
        release_exclusive_slots(state, &to_claim, &stored_hash).await;
    }

    // Update the transaction record. A failure here is an audit-trail loss —
    // log it and surface it as a warning in the job result so the client is
    // aware of the gap.
    let mut warnings = Vec::new();
    match update_terminal_status(state, transaction_id, final_status).await {
        Ok(()) => {
            // Forward a status-change event to the SIEM so analysts see the
            // terminal outcome of the action, not just the preview. Best-effort
            // and fire-and-forget — the local hash-chained log is the durable
            // record.
            forward_status_change_event(state, transaction_id, &caller.role(), final_status);
        }
        Err(e) => {
            eprintln!(
                "[sysknife-daemon] failed to update transaction {transaction_id} to \
                 {final_status:?}: {e}"
            );
            warnings.push(format!("audit trail update failed: {e}"));
        }
    }

    send_response(
        framed,
        &DaemonResponse::JobCompleted {
            job_id: job_id.clone(),
            result: JobResult {
                status: job_state_str(&final_status).to_string(),
                summary,
                warnings,
                job_id: job_id.clone(),
                needs_reboot: matches!(final_status, JobState::NeedsReboot),
                rollback_ref,
                transaction_id: transaction_id.to_string(),
            },
        },
    )
    .await
}

/// If `status` is `Failed` and `spec.rollback_available`, attempt an
/// automatic rollback. Returns the updated `(JobState, summary, rollback_ref)`.
///
/// Sends `JobProgress` frames announcing the attempt and its outcome.
/// Send failures are logged but do not abort the rollback.
///
/// `action_may_still_be_running` vetoes the rollback. A failed action normally
/// means the host is where it was, so reverting is the safe move; but a deadline
/// that could not stop the work means the original transaction may still be
/// live, and `rpm-ostree rollback` on top of a running upgrade puts two package
/// transactions on one host. Doing nothing is recoverable, doing both is not.
/// See issue #140.
#[allow(clippy::too_many_arguments)]
async fn attempt_rollback_if_needed(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    executor: &Arc<dyn ActionExecutor>,
    job_id: &str,
    action_name: &str,
    spec: &crate::actions::ActionSpec,
    status: JobState,
    summary: String,
    action_may_still_be_running: bool,
) -> (JobState, String, Option<String>) {
    if !matches!(status, JobState::Failed) || !spec.rollback_available {
        return (status, summary, None);
    }
    if action_may_still_be_running {
        eprintln!(
            "[sysknife-daemon] {action_name} could not be confirmed stopped; \
             skipping automatic rollback"
        );
        let line = format!(
            "{action_name} could not be confirmed stopped, so automatic rollback was \
             skipped: rolling back over a running transaction would be worse than \
             leaving it. Inspect the host before retrying."
        );
        let _ = send_response(
            framed,
            &DaemonResponse::JobProgress {
                job_id: job_id.to_string(),
                line: line.clone(),
            },
        )
        .await;
        return (
            status,
            format!("{summary} (automatic rollback skipped)"),
            None,
        );
    }
    let Some(rb_spec) = rollback_spec_for(action_name) else {
        return (status, summary, None);
    };

    eprintln!("[sysknife-daemon] {action_name} failed; attempting automatic rollback");

    let _ = send_response(
        framed,
        &DaemonResponse::JobProgress {
            job_id: job_id.to_string(),
            line: format!(
                "{action_name} failed — attempting automatic rollback via rpm-ostree rollback"
            ),
        },
    )
    .await;

    match executor.execute(&rb_spec).await {
        Ok(rb_out) if rb_out.is_success() => {
            let _ = send_response(
                framed,
                &DaemonResponse::JobProgress {
                    job_id: job_id.to_string(),
                    line: "Rollback succeeded — previous deployment restored".to_string(),
                },
            )
            .await;
            (
                JobState::RolledBack,
                format!(
                    "{action_name} failed and was automatically rolled back to the previous deployment"
                ),
                Some("rpm-ostree rollback".to_string()),
            )
        }
        other => {
            let detail = match &other {
                Ok(o) => format!("exit code {}", o.exit_code),
                Err(e) => e.to_string(),
            };
            eprintln!("[sysknife-daemon] rollback also failed: {detail}");
            let _ = send_response(
                framed,
                &DaemonResponse::JobProgress {
                    job_id: job_id.to_string(),
                    line: format!(
                        "Rollback also failed ({detail}) — system may need manual intervention"
                    ),
                },
            )
            .await;
            (status, summary, None)
        }
    }
}

fn job_state_str(state: &JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Canceled => "canceled",
        JobState::RolledBack => "rolled_back",
        JobState::NeedsReboot => "needs_reboot",
    }
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum HandlerError {
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

fn format_job_history(records: &[sysknife_types::TransactionRecord]) -> String {
    if records.is_empty() {
        return "No transactions found.".to_string();
    }

    let mut output = format!("Transaction history ({} entries):\n\n", records.len());
    for r in records {
        output.push_str(&format!(
            "  {}  {:30}  {:12}  {}\n",
            r.transaction_id
                .chars()
                .take(TRANSACTION_ID_DISPLAY_PREFIX_LEN)
                .collect::<String>(),
            r.action_name,
            format!("{:?}", r.status).to_lowercase(),
            r.summary,
        ));
    }
    output
}

async fn send_response(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    response: &DaemonResponse,
) -> Result<(), HandlerError> {
    let json = serde_json::to_vec(response)?;
    framed.send(&json).await.map_err(HandlerError::Framing)
}

async fn send_error(
    framed: &mut FramedStream<impl AsyncRead + AsyncWrite + Unpin>,
    request_id: &str,
    category: &str,
    message: impl Into<String>,
) -> Result<(), HandlerError> {
    send_response(
        framed,
        &DaemonResponse::ErrorResponse {
            request_id: request_id.to_string(),
            category: category.to_string(),
            message: message.into(),
        },
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CallerPrincipal;

    /// A uid-attributed caller, the shape a Unix-socket connection produces.
    fn uid_caller(role: CallerRole) -> CallerAttribution {
        uid_caller_with(1000, role)
    }

    /// A uid-attributed caller with an explicit uid, for tests that need to tell
    /// one account from another.
    fn uid_caller_with(uid: u32, role: CallerRole) -> CallerAttribution {
        CallerAttribution::from_peer_uid(uid, role)
    }
    use crate::{
        state::{DaemonConfig, DaemonState},
        transport::listen::ListenTarget,
    };
    use std::io;
    use tempfile::tempdir;

    // ------------------------------------------------------------------
    // Automatic rollback is vetoed when the action may still be running
    // ------------------------------------------------------------------

    /// Records whether a rollback was ever attempted, so a test can assert on
    /// the absence of one. Counting the calls is the only way to tell "rollback
    /// ran and failed" from "rollback never ran".
    #[derive(Default)]
    struct CountingRollbackExecutor {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ActionExecutor for CountingRollbackExecutor {
        async fn execute(
            &self,
            _spec: &crate::actions::ActionSpec,
        ) -> Result<crate::executor::ExecutionOutput, crate::executor::ExecutorError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::executor::ExecutionOutput {
                stdout: "rolled back\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }

    /// `UpdateSystem`'s spec: rollback-eligible and High risk, the exact shape
    /// this veto exists to protect.
    fn rollback_eligible_spec() -> crate::actions::ActionSpec {
        let spec = crate::executor::build_action_spec("UpdateSystem", &serde_json::json!({}))
            .expect("UpdateSystem builds without params");
        assert!(
            spec.rollback_available,
            "this test is meaningless unless the action is rollback-eligible"
        );
        spec
    }

    async fn rollback_outcome(
        may_still_be_running: bool,
    ) -> (JobState, String, Option<String>, usize) {
        let (a, _b) = UnixStream::pair().unwrap();
        let mut framed = FramedStream::new(a);
        let counting = Arc::new(CountingRollbackExecutor::default());
        let executor: Arc<dyn ActionExecutor> = counting.clone();
        let (status, summary, rollback_ref) = attempt_rollback_if_needed(
            &mut framed,
            &executor,
            "job-1",
            "UpdateSystem",
            &rollback_eligible_spec(),
            JobState::Failed,
            "UpdateSystem failed".to_string(),
            may_still_be_running,
        )
        .await;
        let calls = counting.calls.load(std::sync::atomic::Ordering::SeqCst);
        (status, summary, rollback_ref, calls)
    }

    /// The control: an ordinary failure still rolls back, so the veto below
    /// cannot pass by disabling rollback entirely.
    #[tokio::test]
    async fn an_ordinary_failure_still_rolls_back() {
        let (status, _summary, rollback_ref, calls) = rollback_outcome(false).await;
        assert_eq!(calls, 1, "the rollback action must have been executed");
        assert!(matches!(status, JobState::RolledBack));
        assert!(rollback_ref.is_some());
    }

    /// A deadline that could not stop the work must not start a second
    /// privileged transaction on top of the first. Rolling back over a live
    /// `rpm-ostree upgrade` is worse than leaving it alone: doing nothing is
    /// recoverable, doing both is not. See issue #140.
    #[tokio::test]
    async fn an_action_that_could_not_be_stopped_is_never_rolled_back_over() {
        let (status, summary, rollback_ref, calls) = rollback_outcome(true).await;
        assert_eq!(
            calls, 0,
            "no rollback may be executed while the original action may still be running"
        );
        assert!(
            matches!(status, JobState::Failed),
            "the job stays failed rather than claiming it was rolled back"
        );
        assert!(rollback_ref.is_none());
        assert!(
            summary.contains("rollback skipped"),
            "the operator must be told why nothing was reverted, got: {summary}"
        );
    }

    // ------------------------------------------------------------------
    // PID-reuse hardening (SO_PEERPIDFD)
    // ------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn peer_pidfd_reports_live_self() {
        let (a, _b) = UnixStream::pair().unwrap();
        // On kernels with SO_PEERPIDFD the pinned peer is this very test process,
        // which is obviously still alive, so the liveness check must return true.
        // On older kernels peer_pidfd returns None and there is nothing to assert
        // (the fallback path is exercised by `resolve_caller` below).
        if let Some(fd) = peer_pidfd(&a) {
            assert!(
                pidfd_peer_still_live(&fd),
                "the connecting (self) process must read as live"
            );
        }
    }

    /// The uid must come from the kernel, not from anything the peer says. A
    /// socketpair peer is this test process, so the expected value is knowable
    /// and the assertion pins the wiring rather than merely the absence of a
    /// panic.
    #[tokio::test]
    async fn resolve_caller_attributes_a_unix_peer_to_its_kernel_reported_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        let caller = resolve_caller(&a);

        assert_eq!(
            caller.principal(),
            CallerPrincipal::Uid(unsafe { libc::geteuid() }),
            "a Unix-socket caller must be attributed to the peer uid SO_PEERCRED reports"
        );
        assert_eq!(
            caller.principal().as_signed_str(),
            format!("uid:{}", unsafe { libc::geteuid() }),
            "and the signed form must carry the uid scheme"
        );
    }

    /// A vsock caller presents a shared secret, so the chain must not imply an
    /// account. `token:vsock` says exactly what was proven: possession of a file
    /// that any holder could have read.
    #[test]
    fn a_vsock_principal_does_not_claim_an_account() {
        assert_eq!(CallerPrincipal::VsockToken.as_signed_str(), "token:vsock");
        assert!(
            !CallerPrincipal::VsockToken
                .as_signed_str()
                .starts_with("uid:"),
            "a token must never render as a uid; that would overstate the evidence"
        );
    }

    #[tokio::test]
    async fn resolve_caller_matches_the_peers_actual_groups() {
        // An earlier version discarded the resolved value and asserted only that nothing panicked,
        // asserting only "no panic" — it would have passed just as happily if
        // the function returned Boot for everyone.
        //
        // The role is environment-dependent, so rather than hardcoding one we
        // derive the expectation from the same inputs the daemon uses and
        // compare. That pins the whole wiring — SO_PEERCRED → pid →
        // /proc/<pid>/status → /etc/group → role — instead of only its absence
        // of panics.
        let (a, _b) = UnixStream::pair().unwrap();
        let role = resolve_caller(&a).role();

        let gid_map = read_gid_map();
        let expected =
            crate::auth::highest_role_from_groups(groups_for_pid(std::process::id(), &gid_map));

        assert_eq!(
            role, expected,
            "the resolved role must be exactly what this process's groups justify"
        );
    }

    #[tokio::test]
    async fn resolve_caller_never_exceeds_observer_without_a_privileged_group() {
        // The direction that actually matters for safety: privilege must come
        // from group membership, never from the mere act of connecting.
        let (a, _b) = UnixStream::pair().unwrap();
        let role = resolve_caller(&a).role();

        let gid_map = read_gid_map();
        let groups = groups_for_pid(std::process::id(), &gid_map);
        let privileged = groups.iter().any(|g| {
            matches!(
                g.as_str(),
                crate::auth::DEV_GROUP
                    | crate::auth::ADMIN_GROUP
                    | crate::auth::BOOT_GROUP
                    | crate::auth::WHEEL_GROUP
            )
        });

        if !privileged {
            assert_eq!(
                role,
                CallerRole::Observer,
                "a process in no privileged group must resolve to Observer"
            );
        }
    }

    // ------------------------------------------------------------------
    // Connection read deadlines
    // ------------------------------------------------------------------

    /// A caller that connects and never sends anything must be cut loose
    /// quickly. It holds one of MAX_CONNECTIONS semaphore permits while it
    /// waits, so the pre-request window is the cheap-denial window: a member of
    /// the socket group needs no role at all to occupy every slot.
    #[test]
    fn first_request_deadline_is_much_tighter_than_the_idle_deadline() {
        let first = read_deadline(0);
        let idle = read_deadline(1);
        assert!(
            first < idle,
            "pre-request deadline {first:?} must be tighter than the between-request \
             deadline {idle:?}; otherwise a silent connection squats a permit for the \
             full idle window"
        );
        assert_eq!(idle, IDLE_CONNECTION_TIMEOUT);
    }

    /// Once a caller has been served, idling is legitimate: an MCP server holds
    /// its connection open between tool calls. The tighter bound must apply to
    /// the first request only.
    #[test]
    fn served_connections_keep_the_full_idle_allowance() {
        for served in 1..5 {
            assert_eq!(
                read_deadline(served),
                IDLE_CONNECTION_TIMEOUT,
                "request {served} must not be held to the pre-request deadline"
            );
        }
    }

    // Credential redaction
    // ------------------------------------------------------------------

    #[test]
    fn redact_params_replaces_pro_attach_token() {
        let params = json!({"token": "super-secret-test-only", "extra": "kept"});
        let r = redact_params("ProAttach", &params);
        // Token replaced with sentinel.
        assert_eq!(r["token"].as_str(), Some("<REDACTED>"));
        // Other keys preserved verbatim.
        assert_eq!(r["extra"].as_str(), Some("kept"));
        // Sanity: the literal token value is nowhere in the rendered JSON.
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            !s.contains("super-secret-test-only"),
            "token leaked into proposed_change JSON: {s}"
        );
    }

    #[test]
    fn redact_params_replaces_configure_wifi_password() {
        let params = json!({"ssid": "HomeNet", "password": "correct-horse-test-only"});
        let r = redact_params("ConfigureWifi", &params);
        assert_eq!(r["password"].as_str(), Some("<REDACTED>"));
        // The SSID is not a secret and must survive for the preview to be useful.
        assert_eq!(r["ssid"].as_str(), Some("HomeNet"));
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            !s.contains("correct-horse-test-only"),
            "wifi password leaked into proposed_change JSON: {s}"
        );
    }

    /// `nmcli device wifi connect <ssid> password <pw>` — the secret is the
    /// element after the `password` keyword, not a fixed index, because the
    /// keyword pair is absent for open networks.
    #[test]
    fn redact_argv_replaces_wifi_password_after_keyword() {
        let params = json!({"ssid": "HomeNet", "password": "correct-horse-test-only"});
        let argv = wifi_argv(&["HomeNet", "password", "correct-horse-test-only"]);
        let r = redact_argv("ConfigureWifi", &params, &argv);
        assert_eq!(r.last().map(String::as_str), Some("<REDACTED>"));
        assert!(
            !r.iter().any(|a| a == "correct-horse-test-only"),
            "wifi password survived argv redaction: {r:?}"
        );
    }

    /// Open network: there is no password pair, so nothing may be redacted —
    /// in particular the SSID must not be mistaken for the credential.
    #[test]
    fn redact_argv_leaves_open_network_argv_intact() {
        let params = json!({"ssid": "CafeWifi"});
        let argv = wifi_argv(&["CafeWifi"]);
        let r = redact_argv("ConfigureWifi", &params, &argv);
        assert_eq!(r, argv, "open-network argv must be unchanged");
    }

    /// An SSID that is literally `password` must not shift redaction onto the
    /// keyword and leave the secret in place.
    #[test]
    fn redact_argv_handles_ssid_named_password() {
        let params = json!({"ssid": "password", "password": "s3cret-test-only"});
        let argv = wifi_argv(&["password", "password", "s3cret-test-only"]);
        let r = redact_argv("ConfigureWifi", &params, &argv);
        assert!(
            !r.iter().any(|a| a == "s3cret-test-only"),
            "secret leaked when the SSID is named 'password': {r:?}"
        );
        // The SSID itself is not secret and is still shown.
        assert_eq!(r.iter().filter(|a| *a == "password").count(), 2);
    }

    /// A password whose value is the literal keyword `password` is the mirror
    /// case: the last keyword occurrence IS the secret, so anchoring must use
    /// the last occurrence that still has a successor.
    #[test]
    fn redact_argv_handles_password_valued_password() {
        let params = json!({"ssid": "HomeNet", "password": "password"});
        let argv = wifi_argv(&["HomeNet", "password", "password"]);
        let r = redact_argv("ConfigureWifi", &params, &argv);
        assert_eq!(r.last().map(String::as_str), Some("<REDACTED>"));
    }

    /// Build the argv `network::configure_wifi` produces, so these tests stay
    /// honest about the real command shape.
    fn wifi_argv(tail: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = ["nmcli", "device", "wifi", "connect"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        argv.extend(tail.iter().map(|s| (*s).to_string()));
        argv
    }

    #[test]
    fn redact_params_passes_through_for_actions_with_no_credentials() {
        let params = json!({"package": "vim"});
        let r = redact_params("AptInstall", &params);
        assert_eq!(r["package"].as_str(), Some("vim"));
    }

    #[test]
    fn redact_argv_replaces_argv_element_matching_token_value() {
        // ProAttach's argv is `pro attach <token>`. The redactor finds the
        // element by value-match and replaces it without positional knowledge.
        let params = json!({"token": "super-secret-test-only"});
        let argv = vec![
            "pro".to_string(),
            "attach".to_string(),
            "super-secret-test-only".to_string(),
        ];
        let r = redact_argv("ProAttach", &params, &argv);
        assert_eq!(r, vec!["pro", "attach", "<REDACTED>"]);
    }

    #[test]
    fn redact_argv_passes_through_when_no_credentials() {
        let params = json!({"package": "vim"});
        let argv = vec![
            "apt-get".to_string(),
            "install".to_string(),
            "vim".to_string(),
        ];
        let r = redact_argv("AptInstall", &params, &argv);
        assert_eq!(r, argv);
    }

    // ME2 regression — token equal to structural element "attach".
    //
    // If token == "attach", value-match-only redaction would replace BOTH
    // the structural "attach" and the token position, producing:
    //   `sudo pro <REDACTED> <REDACTED>`
    // instead of the correct:
    //   `sudo pro attach <REDACTED>`
    //
    // Positional redaction (last element) must be applied first so that
    // "attach" is preserved as a structural element.
    #[test]
    fn redact_argv_token_equal_to_attach_preserves_structural_attach() {
        let params = json!({"token": "attach"});
        // Typical ProAttach argv shape: sudo pro attach <token>
        let argv = vec![
            "sudo".to_string(),
            "pro".to_string(),
            "attach".to_string(),
            "attach".to_string(), // token value == "attach"
        ];
        let r = redact_argv("ProAttach", &params, &argv);
        // Positional pass redacts last element.
        // Value-match fallback then redacts any remaining "attach" — but the
        // only remaining "attach" at index 2 is structural and should be kept.
        // The net result: last element is redacted; "attach" at index 2 is NOT.
        assert_eq!(
            r,
            vec!["sudo", "pro", "attach", "<REDACTED>"],
            "structural 'attach' must survive; only the positional token gets redacted"
        );
    }

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    struct MockRunner;
    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
            match program {
                "hostname" => Ok("testhost\n".to_string()),
                _ => Ok(String::new()),
            }
        }
    }

    fn test_state(dir: &tempfile::TempDir) -> DaemonState {
        let db_path = dir.path().join("sysknife-test.db");
        let sock_path = dir.path().join("sysknife-test.sock");
        let config = DaemonConfig::new(ListenTarget::Unix(sock_path), db_path);
        DaemonState::open(config).unwrap()
    }

    fn runner() -> Arc<dyn CommandRunner + Send + Sync> {
        Arc::new(MockRunner)
    }

    fn str_set<const N: usize>(items: [&str; N]) -> std::collections::BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn autoremove_binding_accepts_the_same_set() {
        let pc = json!({ AUTOREMOVE_REMOVALS_KEY: ["a", "b"] });
        assert!(verify_autoremove_binding(&pc, &str_set(["a", "b"])).is_ok());
    }

    #[test]
    fn autoremove_binding_rejects_a_newly_added_package() {
        let pc = json!({ AUTOREMOVE_REMOVALS_KEY: ["a"] });
        let err = verify_autoremove_binding(&pc, &str_set(["a", "linux-image-6.1"]))
            .expect_err("a package apt would now remove but the operator did not approve");
        assert!(err.contains("linux-image-6.1"), "{err}");
    }

    #[test]
    fn autoremove_binding_rejects_a_no_longer_removed_package() {
        let pc = json!({ AUTOREMOVE_REMOVALS_KEY: ["a", "b"] });
        let err = verify_autoremove_binding(&pc, &str_set(["a"]))
            .expect_err("the approved set no longer matches");
        assert!(err.contains('b'), "{err}");
    }

    #[test]
    fn autoremove_binding_refuses_a_preview_that_captured_no_set() {
        // A preview whose simulate failed records no set; execute must fail closed.
        let pc = json!({ "action": "AptAutoremove" });
        assert!(verify_autoremove_binding(&pc, &str_set([])).is_err());
    }

    #[test]
    fn autoremove_kernel_warning_flags_kernel_and_driver_packages() {
        let set = str_set([
            "linux-image-6.1",
            "nvidia-driver-535",
            "libfoo:amd64",
            "vim",
        ]);
        let w = autoremove_kernel_warning(&set).expect("kernel/driver packages must warn");
        assert!(
            w.contains("linux-image-6.1") && w.contains("nvidia-driver-535"),
            "{w}"
        );
        assert!(!w.contains("vim") && !w.contains("libfoo"), "{w}");
    }

    #[test]
    fn autoremove_kernel_warning_is_silent_for_ordinary_packages() {
        assert!(autoremove_kernel_warning(&str_set(["libfoo", "oldlib"])).is_none());
    }

    /// Returns a scripted `apt-get -s autoremove` result per call (preview first,
    /// then execute), and "testhost" for hostname so state collection succeeds.
    /// Panics on an unscripted extra call so a duplicate simulate cannot be
    /// silently papered over, and shares its call counter so tests can assert the
    /// exactly-once-per-phase invariant.
    struct ScriptedAutoremoveRunner {
        outputs: Vec<Result<String, String>>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ScriptedAutoremoveRunner {
        fn with_outputs(
            outputs: Vec<Result<String, String>>,
        ) -> (
            Arc<dyn CommandRunner + Send + Sync>,
            Arc<std::sync::atomic::AtomicUsize>,
        ) {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let runner = Arc::new(Self {
                outputs,
                calls: Arc::clone(&calls),
            });
            (runner, calls)
        }
        /// Convenience: every call returns the same stdout.
        fn ok(
            outputs: &[&str],
        ) -> (
            Arc<dyn CommandRunner + Send + Sync>,
            Arc<std::sync::atomic::AtomicUsize>,
        ) {
            Self::with_outputs(outputs.iter().map(|s| Ok(s.to_string())).collect())
        }
    }
    impl CommandRunner for ScriptedAutoremoveRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, io::Error> {
            if program == "hostname" {
                return Ok("testhost\n".to_string());
            }
            if program == "apt-get" && args == ["-s", "autoremove"] {
                let i = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let out = self.outputs.get(i).unwrap_or_else(|| {
                    panic!(
                        "ScriptedAutoremoveRunner: unexpected `apt-get -s autoremove` call #{i} \
                         (only {} scripted)",
                        self.outputs.len()
                    )
                });
                return out.clone().map_err(io::Error::other);
            }
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn preview_captures_the_autoremove_set_and_warns_on_kernel_packages() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let (runner, _calls) =
            ScriptedAutoremoveRunner::ok(&["Remv linux-image-6.1 [6.1]\nRemv libfoo [1]\n"]);
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner,
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "r1",
                    "action_name": "AptAutoremove",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(resp["type"], "preview_response", "{resp}");

        let removals = resp["preview"]["proposed_change"][AUTOREMOVE_REMOVALS_KEY]
            .as_array()
            .expect("the preview must capture the autoremove deletion set");
        let names: Vec<&str> = removals.iter().map(|v| v.as_str().unwrap()).collect();
        assert!(
            names.contains(&"linux-image-6.1") && names.contains(&"libfoo"),
            "captured set wrong: {names:?}"
        );
        let warnings = resp["preview"]["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("linux-image-6.1")),
            "the kernel-package warning must be present: {warnings:?}"
        );
    }

    #[tokio::test]
    async fn execute_refuses_autoremove_when_the_deletion_set_drifted() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        // Preview sees {pkga, pkgb}; by execute pkgb is no longer removable -> drift.
        let (runner, calls) =
            ScriptedAutoremoveRunner::ok(&["Remv pkga [1]\nRemv pkgb [1]\n", "Remv pkga [1]\n"]);
        let calls_probe = Arc::clone(&calls);
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner,
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "r1",
                    "action_name": "AptAutoremove",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(resp["type"], "preview_response", "{resp}");
        let txid = resp["transaction_id"].as_str().unwrap().to_string();
        let receipt = approve_preview(&mut framed, &txid).await;

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "r2",
                    "transaction_id": txid,
                    "action_name": "AptAutoremove",
                    "params": {},
                    "approval_receipt": receipt
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let exec: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        // Refused before the executor runs — nothing is autoremoved.
        assert_eq!(
            exec["type"], "error_response",
            "drift must be refused: {exec}"
        );
        assert_eq!(exec["category"], "stale_approval", "{exec}");
        assert!(
            exec["message"].as_str().unwrap().contains("changed since"),
            "message should explain the drift: {exec}"
        );
        // Exactly one simulate at preview and one at execute — not more.
        assert_eq!(
            calls_probe.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "apt-get -s autoremove must run once per phase"
        );
    }

    /// Records whether the real action executor was invoked. Lets the
    /// unchanged-set test prove the Ok branch reaches execution without running
    /// any real command, independent of the sandbox's sudo behavior.
    #[derive(Default)]
    struct RecordingExecutor {
        called: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl ActionExecutor for RecordingExecutor {
        async fn execute(
            &self,
            _spec: &crate::actions::ActionSpec,
        ) -> Result<crate::executor::ExecutionOutput, crate::executor::ExecutorError> {
            unreachable!("dispatcher uses execute_with_progress")
        }
        async fn execute_with_progress(
            &self,
            _spec: &crate::actions::ActionSpec,
            progress: tokio::sync::mpsc::UnboundedSender<String>,
        ) -> Result<crate::executor::ExecutionOutput, crate::executor::ExecutorError> {
            self.called
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = progress.send("executed".to_string());
            Ok(crate::executor::ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }

    async fn preview_autoremove(framed: &mut FramedStream<tokio::net::UnixStream>) -> Value {
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "r1",
                    "action_name": "AptAutoremove",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        serde_json::from_slice(&framed.recv().await.unwrap()).unwrap()
    }

    async fn send_execute_autoremove(
        framed: &mut FramedStream<tokio::net::UnixStream>,
        txid: &str,
        receipt: &str,
    ) {
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "r2",
                    "transaction_id": txid,
                    "action_name": "AptAutoremove",
                    "params": {},
                    "approval_receipt": receipt
                }))
                .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn execute_proceeds_when_the_autoremove_set_is_unchanged() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        // Same set at preview and execute -> no drift -> proceeds to the executor.
        let (runner, _calls) =
            ScriptedAutoremoveRunner::ok(&["Remv pkga [1]\n", "Remv pkga [1]\n"]);
        let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let executor = Arc::new(RecordingExecutor {
            called: Arc::clone(&called),
        });
        tokio::spawn(async move {
            connection_handler_with_executor(
                server,
                state,
                runner,
                executor,
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);
        let resp = preview_autoremove(&mut framed).await;
        assert_eq!(resp["type"], "preview_response", "{resp}");
        let txid = resp["transaction_id"].as_str().unwrap().to_string();
        let receipt = approve_preview(&mut framed, &txid).await;
        send_execute_autoremove(&mut framed, &txid, &receipt).await;

        loop {
            let r: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
            match r["type"].as_str().unwrap() {
                "job_started" | "job_progress" => {}
                "job_completed" => break,
                other => panic!("an unchanged set must proceed, got {other}: {r}"),
            }
        }
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "executor must run exactly once when the set is unchanged"
        );
    }

    #[tokio::test]
    async fn preview_that_cannot_simulate_captures_no_set_and_execute_refuses() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        // Preview simulate fails -> no set captured. Execute's simulate succeeds
        // but the missing captured set makes verify refuse (fail-closed).
        let (runner, _calls) = ScriptedAutoremoveRunner::with_outputs(vec![
            Err("apt database lock held".to_string()),
            Ok("Remv pkga [1]\n".to_string()),
        ]);
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner,
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);
        let resp = preview_autoremove(&mut framed).await;
        assert_eq!(resp["type"], "preview_response", "{resp}");
        // No set captured, and the operator is warned.
        assert!(
            resp["preview"]["proposed_change"]
                .get(AUTOREMOVE_REMOVALS_KEY)
                .is_none(),
            "a failed simulate must not capture a set: {resp}"
        );
        assert!(
            resp["preview"]["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w.as_str().unwrap().contains("Could not compute")),
            "the operator must be warned: {resp}"
        );
        let txid = resp["transaction_id"].as_str().unwrap().to_string();
        let receipt = approve_preview(&mut framed, &txid).await;
        send_execute_autoremove(&mut framed, &txid, &receipt).await;

        let exec: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(exec["type"], "error_response", "{exec}");
        assert_eq!(exec["category"], "stale_approval", "{exec}");
        assert!(
            exec["message"]
                .as_str()
                .unwrap()
                .contains("did not capture"),
            "must refuse an uncaptured set: {exec}"
        );
    }

    #[tokio::test]
    async fn execute_refuses_when_the_autoremove_re_simulate_fails() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        // Preview captures a set; the execute-time re-simulate fails -> refuse
        // (execution_failure), never fall through to an unbound autoremove.
        let (runner, _calls) = ScriptedAutoremoveRunner::with_outputs(vec![
            Ok("Remv pkga [1]\n".to_string()),
            Err("apt database lock held".to_string()),
        ]);
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner,
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);
        let resp = preview_autoremove(&mut framed).await;
        assert_eq!(resp["type"], "preview_response", "{resp}");
        let txid = resp["transaction_id"].as_str().unwrap().to_string();
        let receipt = approve_preview(&mut framed, &txid).await;
        send_execute_autoremove(&mut framed, &txid, &receipt).await;

        let exec: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(exec["type"], "error_response", "{exec}");
        assert_eq!(exec["category"], "execution_failure", "{exec}");
        assert!(
            exec["message"]
                .as_str()
                .unwrap()
                .contains("confirm the autoremove set"),
            "{exec}"
        );
    }

    #[test]
    fn autoremove_binding_refuses_a_malformed_captured_set() {
        // A present-but-wrong-shaped captured set must refuse, not default to allow.
        let pc = json!({ AUTOREMOVE_REMOVALS_KEY: "not-an-array" });
        let err = verify_autoremove_binding(&pc, &str_set(["a"]))
            .expect_err("a malformed captured set must be refused");
        assert!(err.contains("malformed"), "{err}");
    }

    async fn approve_preview(
        framed: &mut FramedStream<tokio::net::UnixStream>,
        transaction_id: &str,
    ) -> String {
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "approve",
                    "request_id": format!("approve-{transaction_id}"),
                    "transaction_id": transaction_id,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(response["type"], "approval_response");
        response["approval_receipt"]
            .as_str()
            .expect("approval receipt")
            .to_string()
    }

    async fn preview_and_approve(
        framed: &mut FramedStream<tokio::net::UnixStream>,
        action_name: &str,
        params: Value,
    ) -> (String, String) {
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": format!("preview-{action_name}"),
                    "action_name": action_name,
                    "params": params,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(response["type"], "preview_response");
        let transaction_id = response["transaction_id"].as_str().unwrap().to_string();
        let receipt = approve_preview(framed, &transaction_id).await;
        (transaction_id, receipt)
    }

    #[tokio::test]
    async fn approval_details_returns_persisted_preview_before_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "details-preview",
                    "action_name": "GetMemoryInfo",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let preview: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        let transaction_id = preview["transaction_id"].as_str().unwrap();

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "approval_details",
                    "request_id": "details-read",
                    "transaction_id": transaction_id
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let details: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(details["type"], "approval_details_response");
        assert_eq!(details["transaction_id"], transaction_id);
        assert_eq!(details["action_name"], "GetMemoryInfo");
        assert_eq!(details["preview"]["risk_level"], "low");
        assert!(!details["preview"]["summary"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn approve_missing_transaction_maps_to_stale_approval() {
        let dir = tempdir().unwrap();
        let responses = exchange(
            test_state(&dir),
            CallerRole::Observer,
            vec![json!({
                "type": "approve",
                "request_id": "approve-missing",
                "transaction_id": "missing-transaction",
            })],
            1,
        )
        .await;

        assert_eq!(responses[0]["type"], "error_response");
        assert_eq!(responses[0]["category"], "stale_approval");
    }

    #[tokio::test]
    async fn approving_same_transaction_twice_maps_second_to_stale_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        let (transaction_id, _) =
            preview_and_approve(&mut framed, "GetMemoryInfo", json!({})).await;

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "approve",
                    "request_id": "approve-again",
                    "transaction_id": transaction_id,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "stale_approval");
    }

    #[tokio::test]
    async fn approve_with_forged_commitment_maps_to_integrity_failure() {
        // A tampered `approval_id` makes the store return `DatabaseInvariant`
        // (fail-closed). The dispatcher must surface that as a distinct,
        // non-retryable `integrity_failure` — NOT `transient_infrastructure_
        // failure`, which would falsely tell the user a retry can succeed.
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("sysknife-test.db");
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "preview-forge",
                    "action_name": "GetMemoryInfo",
                    "params": {},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let preview: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        let transaction_id = preview["transaction_id"].as_str().unwrap().to_string();

        // Forge the stored commitment via an independent connection to the same
        // SQLite file so the daemon reads a tampered value on the next request.
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .execute(
                "UPDATE transactions SET approval_id = 'forged' WHERE transaction_id = ?1",
                rusqlite::params![transaction_id],
            )
            .unwrap();

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "approve",
                    "request_id": "approve-forged",
                    "transaction_id": transaction_id,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "integrity_failure");
    }

    #[tokio::test]
    async fn query_history_returns_structured_rows_with_created_at_and_risk_level() {
        // Regression for the null created_at/risk_level history bug: the
        // structured query_history IPC must carry typed rows, not text.
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "preview-hist",
                    "action_name": "GetMemoryInfo",
                    "params": {},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let _ = framed.recv().await.unwrap();

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "query_history",
                    "request_id": "hist-1",
                    "limit": 10,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "history_response");
        let entries = response["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["action_name"], "GetMemoryInfo");
        assert!(
            !entries[0]["created_at"].as_str().unwrap_or("").is_empty(),
            "created_at must be populated over the structured IPC"
        );
        assert_eq!(
            entries[0]["risk_level"], "low",
            "GetSystemState is a low-risk action; risk_level must carry the exact typed value"
        );
    }

    #[tokio::test]
    async fn query_history_honours_policy_override_raising_history_above_observer() {
        // Authorization consistency: if an operator raises ListJobHistory above
        // Observer via [policy.risk_overrides], the structured query_history
        // path must refuse it too — it must not be a bypass around that policy.
        let dir = tempdir().unwrap();
        let real = test_state(&dir);
        // risk_overrides raise an action's RISK LEVEL; "high" pushes
        // ListJobHistory's derived min-role above Observer.
        let overrides =
            std::collections::HashMap::from([("ListJobHistory".to_string(), "high".to_string())]);
        let policy = crate::policy::PolicyTable::from_overrides(&overrides).unwrap();
        let state = crate::state::DaemonState::open_with_audit(
            real.config.clone(),
            policy,
            None,
            real.audit.clone(),
        );

        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "query_history",
                    "request_id": "hist-denied",
                    "limit": 10,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "authorization_failure");
    }

    #[tokio::test]
    async fn cancel_queued_transaction_succeeds_and_marks_it_canceled() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let handler_state = state.clone();
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "preview-cancel",
                    "action_name": "GetMemoryInfo",
                    "params": {},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let preview: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        let transaction_id = preview["transaction_id"].as_str().unwrap().to_string();

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "cancel",
                    "request_id": "cancel-1",
                    "transaction_id": transaction_id,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "cancel_response");
        assert_eq!(
            state
                .audit
                .get(&transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            JobState::Canceled
        );
    }

    #[tokio::test]
    async fn cancel_running_transaction_is_rejected_and_left_running() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let handler_state = state.clone();
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        let (transaction_id, receipt) =
            preview_and_approve(&mut framed, "GetMemoryInfo", json!({})).await;
        // Claim it (Queued -> Running) so it is in-flight from the store's view.
        assert!(state
            .audit
            .claim_approved_for_execution(&transaction_id, &receipt_digest(&receipt))
            .await
            .unwrap());

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "cancel",
                    "request_id": "cancel-running",
                    "transaction_id": transaction_id,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "not_cancelable");
        assert_eq!(
            state
                .audit
                .get(&transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            JobState::Running,
            "an in-flight action must not be disturbed by cancel"
        );
    }

    #[tokio::test]
    async fn cancel_missing_transaction_is_rejected() {
        let dir = tempdir().unwrap();
        let responses = exchange(
            test_state(&dir),
            CallerRole::Observer,
            vec![json!({
                "type": "cancel",
                "request_id": "cancel-missing",
                "transaction_id": "no-such-transaction",
            })],
            1,
        )
        .await;
        assert_eq!(responses[0]["type"], "error_response");
        assert_eq!(responses[0]["category"], "not_cancelable");
    }

    #[tokio::test]
    async fn undelivered_approval_is_revoked_so_the_user_can_retry() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let handler_state = state.clone();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "preview-undelivered",
                    "action_name": "GetMemoryInfo",
                    "params": {},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let preview: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        let transaction_id = preview["transaction_id"].as_str().unwrap();

        let (peer, broken_stream) = tokio::io::duplex(64);
        drop(peer);
        let mut broken_framed = FramedStream::new(broken_stream);
        assert!(handle_approve(
            &mut broken_framed,
            &state,
            &uid_caller(CallerRole::Admin),
            "approve-undelivered",
            transaction_id,
        )
        .await
        .is_err());

        let (retry_stream, receiver) = tokio::io::duplex(4096);
        let mut retry_framed = FramedStream::new(retry_stream);
        handle_approve(
            &mut retry_framed,
            &state,
            &uid_caller(CallerRole::Admin),
            "approve-retry",
            transaction_id,
        )
        .await
        .unwrap();
        let mut receiver = FramedStream::new(receiver);
        let response: Value = serde_json::from_slice(&receiver.recv().await.unwrap()).unwrap();
        assert_eq!(response["type"], "approval_response");
    }

    #[tokio::test]
    async fn approval_details_for_running_transaction_maps_to_stale_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let handler_state = state.clone();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        let (transaction_id, receipt) =
            preview_and_approve(&mut framed, "GetMemoryInfo", json!({})).await;
        assert!(state
            .audit
            .claim_approved_for_execution(&transaction_id, &receipt_digest(&receipt))
            .await
            .unwrap());

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "approval_details",
                    "request_id": "details-running",
                    "transaction_id": transaction_id,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "stale_approval");
    }

    /// Send `requests` to a spawned handler, collect exactly `want_responses`
    /// response frames, then drop the client to signal EOF.
    async fn exchange(
        state: DaemonState,
        role: CallerRole,
        requests: Vec<Value>,
        want_responses: usize,
    ) -> Vec<Value> {
        exchange_as(state, uid_caller_with(1000, role), requests, want_responses).await
    }

    /// `exchange` with the caller spelled out, for tests that assert on which
    /// account the daemon recorded.
    async fn exchange_as(
        state: DaemonState,
        caller: CallerAttribution,
        requests: Vec<Value>,
        want_responses: usize,
    ) -> Vec<Value> {
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(server, state, runner(), caller).await;
        });

        let mut framed = FramedStream::new(client);
        for req in &requests {
            let bytes = serde_json::to_vec(req).unwrap();
            framed.send(&bytes).await.unwrap();
        }

        let mut responses = Vec::new();
        for _ in 0..want_responses {
            let raw = framed.recv().await.unwrap();
            responses.push(serde_json::from_slice::<Value>(&raw).unwrap());
        }
        responses
    }

    // ------------------------------------------------------------------
    // query_state
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn query_state_returns_state_response() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({"type": "query_state", "request_id": "r1"})],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "state_response");
        assert_eq!(resps[0]["request_id"], "r1");
        assert_eq!(resps[0]["state"]["host_name"], "testhost");
    }

    // ------------------------------------------------------------------
    // preview
    // ------------------------------------------------------------------

    /// The account the connection was attributed to must reach the stored row.
    ///
    /// Everything else about the principal is tested in isolation: the resolver,
    /// the renderings, the encoder, the store. None of that notices if
    /// `handle_preview` passes a default instead of the connection's own caller,
    /// because the value would still be a well-formed principal that verifies.
    /// This is the test that fails for a hardcoded one.
    #[tokio::test]
    async fn the_recorded_principal_is_the_one_the_connection_was_attributed_to() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let audit = std::sync::Arc::clone(&state.audit);

        let resps = exchange_as(
            state,
            uid_caller_with(4242, CallerRole::Observer),
            vec![json!({
                "type": "preview",
                "request_id": "r-principal",
                "action_name": "GetMemoryInfo",
                "params": {}
            })],
            1,
        )
        .await;

        let transaction_id = resps[0]["transaction_id"].as_str().unwrap();
        let row = audit
            .fetch_chain_row(transaction_id)
            .await
            .expect("fetch the row just written")
            .expect("preview records a transaction");

        assert_eq!(
            row.caller_principal.as_deref(),
            Some("uid:4242"),
            "the row must name the account resolved for this connection, not a default"
        );
        assert_eq!(row.chain_version, crate::audit_chain::CHAIN_VERSION_CURRENT);
    }

    #[tokio::test]
    async fn preview_returns_hash_and_transaction_id() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "preview",
                "request_id": "r1",
                "action_name": "GetMemoryInfo",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "preview_response");
        assert_eq!(resps[0]["request_id"], "r1");
        let hash = resps[0]["preview"]["request_hash"].as_str().unwrap();
        assert_eq!(
            hash.len(),
            64,
            "request_hash should be a 64-char hex SHA-256"
        );
        assert!(
            !resps[0]["transaction_id"].as_str().unwrap().is_empty(),
            "transaction_id must be set"
        );
    }

    #[tokio::test]
    async fn preview_hash_is_deterministic() {
        // The same action + params must always produce the same hash.
        let hash1 = compute_request_hash(
            "InstallFlatpak",
            &json!({"app_id": "org.gnome.Builder", "remote": "flathub"}),
        );
        let hash2 = compute_request_hash(
            "InstallFlatpak",
            &json!({"remote": "flathub", "app_id": "org.gnome.Builder"}),
        );
        assert_eq!(hash1, hash2, "canonical JSON must sort keys");
    }

    #[test]
    fn canonical_json_recurses_into_arrays() {
        // Objects nested inside arrays must also have sorted keys so that
        // {"packages": [{"b": 1, "a": 2}]} and {"packages": [{"a": 2, "b": 1}]}
        // produce the same hash.
        let hash1 =
            compute_request_hash("InstallPackages", &json!({"packages": [{"b": 1, "a": 2}]}));
        let hash2 =
            compute_request_hash("InstallPackages", &json!({"packages": [{"a": 2, "b": 1}]}));
        assert_eq!(hash1, hash2, "nested object keys in arrays must be sorted");
    }

    #[test]
    fn canonical_json_preserves_array_element_order() {
        // Array element order is semantically significant ("install a then b"
        // is different from "install b then a"), so it must be preserved.
        let hash1 = compute_request_hash("Op", &json!({"items": ["a", "b"]}));
        let hash2 = compute_request_hash("Op", &json!({"items": ["b", "a"]}));
        assert_ne!(hash1, hash2, "array element order must be preserved");
    }

    // ------------------------------------------------------------------
    // authorization
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn high_risk_action_rejected_for_observer() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer, // UpdateSystem requires Admin
            vec![json!({
                "type": "preview",
                "request_id": "r1",
                "action_name": "UpdateSystem",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "authorization_failure");
    }

    #[tokio::test]
    async fn under_privileged_caller_cannot_act_on_admin_transaction() {
        // Regression: authorization must be enforced on approve / cancel /
        // approval-details, not only at preview time. An Admin-tier transaction
        // that was previewed by an Admin caller must be untouchable by an
        // under-privileged caller on a *different* connection, yet remain
        // actionable by an authorized caller.
        let dir = tempdir().unwrap();
        // UpdateSystem is the Admin-tier vehicle here, and it is rpm-ostree
        // shaped, so the host has to be a Fedora-family one. The subject of this
        // test is authorization, not platform.
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::FedoraSilverblue { version: 41 });

        // An Admin caller previews an Admin-tier action, persisting a queued tx.
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let handler_state = state.clone();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "preview-admin",
                    "action_name": "UpdateSystem",
                    "params": {},
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let preview: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        assert_eq!(preview["type"], "preview_response");
        let transaction_id = preview["transaction_id"].as_str().unwrap().to_string();

        // Every mutating/reading verb an Observer might try must be refused with
        // authorization_failure while leaving the transaction untouched.
        for (request_id, verb) in [
            ("obs-approve", "approve"),
            ("obs-cancel", "cancel"),
            ("obs-details", "details"),
        ] {
            let (stream, rx) = tokio::io::duplex(4096);
            let mut caller = FramedStream::new(stream);
            match verb {
                "approve" => handle_approve(
                    &mut caller,
                    &state,
                    &uid_caller(CallerRole::Observer),
                    request_id,
                    &transaction_id,
                )
                .await
                .unwrap(),
                "cancel" => handle_cancel(
                    &mut caller,
                    &state,
                    &uid_caller(CallerRole::Observer),
                    request_id,
                    &transaction_id,
                )
                .await
                .unwrap(),
                _ => handle_approval_details(
                    &mut caller,
                    &state,
                    &uid_caller(CallerRole::Observer),
                    request_id,
                    &transaction_id,
                )
                .await
                .unwrap(),
            }
            let mut rx = FramedStream::new(rx);
            let resp: Value = serde_json::from_slice(&rx.recv().await.unwrap()).unwrap();
            assert_eq!(resp["type"], "error_response", "{verb} must be refused");
            assert_eq!(
                resp["category"], "authorization_failure",
                "{verb} refusal must be an authorization failure"
            );
        }

        // The transaction survived the refusals: an authorized caller can still
        // approve it, proving we blocked only the unauthorized path.
        let (stream, rx) = tokio::io::duplex(4096);
        let mut admin = FramedStream::new(stream);
        handle_approve(
            &mut admin,
            &state,
            &uid_caller(CallerRole::Admin),
            "admin-approve",
            &transaction_id,
        )
        .await
        .unwrap();
        let mut rx = FramedStream::new(rx);
        let resp: Value = serde_json::from_slice(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(resp["type"], "approval_response");
    }

    #[tokio::test]
    async fn medium_risk_action_rejected_for_observer() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer, // InstallFlatpak requires Dev
            vec![json!({
                "type": "preview",
                "request_id": "r1",
                "action_name": "InstallFlatpak",
                "params": {"username": "alice", "app_id": "org.gnome.Builder", "remote": "flathub"}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "authorization_failure");
    }

    #[tokio::test]
    async fn low_risk_action_allowed_for_observer() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "preview",
                "request_id": "r1",
                "action_name": "GetMemoryInfo",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "preview_response");
    }

    #[test]
    fn unsupported_distros_cannot_reach_mutation_paths() {
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::UbuntuCore {
            major: 24,
            minor: 4,
        });
        assert!(validate_action_platform(&state, "AptInstall").is_err());

        // Below the support floor: no longer receiving Ubuntu security updates.
        // The vehicle has to be an action Ubuntu can run at all — `UpdateSystem`
        // is `rpm-ostree upgrade` and is fenced to the Fedora family, so using it
        // here would assert the support floor while actually measuring the family
        // fence.
        state.host_distro = Some(sysknife_core::distro::DistroId::Ubuntu {
            major: 18,
            minor: 4,
        });
        assert!(validate_action_platform(&state, "AptUpgrade").is_err());

        // The counterpart assertion, so this test keeps its teeth: releases at
        // and above the floor DO reach the mutation path, interim ones included.
        for (major, minor) in [(20, 4), (25, 10), (26, 4)] {
            state.host_distro = Some(sysknife_core::distro::DistroId::Ubuntu { major, minor });
            assert!(
                validate_action_platform(&state, "AptUpgrade").is_ok(),
                "Ubuntu {major}.{minor:02} must be able to run mutating actions"
            );
        }
    }

    #[test]
    fn a_low_risk_action_that_mutates_is_not_treated_as_a_read() {
        // `AptUpdate` is RiskLevel::Low, so min_role_for_action puts it at
        // Observer — yet it runs `sudo apt-get update`. Any exemption keyed on
        // the RBAC role therefore lets a privileged mutation through, which is
        // why the platform gate does not exempt reads at all.
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::Debian { version: Some(12) });
        assert!(
            !state.host_distro.as_ref().unwrap().is_supported(),
            "this test needs an ineligible host"
        );
        assert_eq!(
            crate::policy::min_role_for_action("AptUpdate"),
            Some(CallerRole::Observer),
            "AptUpdate is the action that makes the role a bad proxy for mutation"
        );
        assert!(
            validate_action_platform(&state, "AptUpdate").is_err(),
            "a privileged mutation must stay refused on an ineligible host"
        );
    }
    #[test]
    fn raising_a_read_only_action_via_risk_overrides_does_not_arm_the_platform_fence() {
        // `[policy.risk_overrides]` answers "who may run this", not "is this a
        // mutation". Deriving `is_mutating` from the override-adjusted role let
        // an operator who tightened RBAC on a harmless read also make that read
        // fail whenever the host distro could not be detected — a restriction
        // they never asked for, appearing in an unrelated subsystem.
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = None;
        let overrides =
            std::collections::HashMap::from([("GetDiskUsage".to_string(), "high".to_string())]);
        state.policy = crate::policy::PolicyTable::from_overrides(&overrides).unwrap();

        assert_eq!(
            state.policy.min_role_for_action("GetDiskUsage"),
            Some(CallerRole::Admin),
            "the override still governs authorization"
        );
        assert!(
            validate_action_platform(&state, "GetDiskUsage").is_ok(),
            "a read-only action stays exempt from the distro fence"
        );
    }

    #[test]
    fn supported_hosts_still_enforce_action_family() {
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::Ubuntu {
            major: 24,
            minor: 4,
        });
        assert!(validate_action_platform(&state, "AptInstall").is_ok());
        assert!(validate_action_platform(&state, "AddLayeredPackage").is_err());
    }

    // ------------------------------------------------------------------
    // query_action / describe — the same fences as preview and execute
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn query_action_refuses_an_action_the_host_family_cannot_run() {
        // `preview` and `execute` both call `validate_action_platform`;
        // `query_action` reached `build_action_spec` and ran the command. On a
        // Debian host that meant shelling out to `rpm-ostree`, so the caller
        // got a "No such file or directory" execution error instead of the
        // clean refusal the other two paths give.
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::Ubuntu {
            major: 24,
            minor: 4,
        });

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "query_action",
                "request_id": "r1",
                "action_name": "GetLayeredPackages",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "unsupported_platform");
    }

    #[tokio::test]
    async fn describe_refuses_an_action_the_caller_is_not_allowed_to_run() {
        // Describe renders the exact command an action would run. It had no
        // authorization check at all, so an Observer could enumerate the argv
        // of every privileged action on the box.
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "describe",
                "request_id": "r1",
                "action_name": "GrantSudoAccess",
                "params": {"username": "alice", "commands": "/usr/bin/ls", "nopasswd": false}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "authorization_failure");
    }

    #[tokio::test]
    async fn describe_refuses_an_action_the_host_family_cannot_run() {
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::Ubuntu {
            major: 24,
            minor: 4,
        });

        let resps = exchange(
            state,
            CallerRole::Admin,
            vec![json!({
                "type": "describe",
                "request_id": "r1",
                "action_name": "AddLayeredPackage",
                "params": {"package": "vim"}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "unsupported_platform");
    }

    #[tokio::test]
    async fn describe_still_answers_for_an_allowed_action() {
        // The fences must not turn describe into a privileged-only call: a
        // read-only action stays describable by an Observer.
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "describe",
                "request_id": "r1",
                "action_name": "GetDiskUsage",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "describe_response");
    }

    // ------------------------------------------------------------------
    // execute — stale approval
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn execute_without_prior_preview_returns_stale_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "execute",
                "request_id": "r1",
                "transaction_id": "missing-transaction",
                "action_name": "GetMemoryInfo",
                "params": {},
                "approval_receipt": "unissued-receipt"
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "stale_approval");
    }

    #[tokio::test]
    async fn execute_with_changed_params_rejects_without_consuming_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let handler_state = state.clone();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        let (transaction_id, receipt) = preview_and_approve(
            &mut framed,
            "GetServiceStatus",
            json!({"unit": "sshd.service"}),
        )
        .await;

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "changed-params",
                    "transaction_id": transaction_id,
                    "action_name": "GetServiceStatus",
                    "params": {"unit": "cron.service"},
                    "approval_receipt": receipt,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "stale_approval");
        assert_eq!(
            state
                .audit
                .get(&transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            JobState::Queued
        );
        assert!(state
            .audit
            .claim_approved_for_execution(&transaction_id, &receipt_digest(&receipt))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn execute_with_changed_action_rejects_without_consuming_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let handler_state = state.clone();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        let (transaction_id, receipt) =
            preview_and_approve(&mut framed, "GetMemoryInfo", json!({})).await;

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "changed-action",
                    "transaction_id": transaction_id,
                    "action_name": "GetDiskUsage",
                    "params": {},
                    "approval_receipt": receipt,
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();

        assert_eq!(response["type"], "error_response");
        assert_eq!(response["category"], "stale_approval");
        assert_eq!(
            state
                .audit
                .get(&transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            JobState::Queued
        );
        assert!(state
            .audit
            .claim_approved_for_execution(&transaction_id, &receipt_digest(&receipt))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn job_started_send_failure_releases_slot_and_marks_transaction_failed() {
        let dir = tempdir().unwrap();
        let mut state = test_state(&dir);
        state.host_distro = Some(sysknife_core::distro::DistroId::FedoraSilverblue { version: 44 });
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        let handler_state = state.clone();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                handler_state,
                runner(),
                uid_caller_with(1000, CallerRole::Admin),
            )
            .await;
        });
        let mut preview_stream = FramedStream::new(client);
        let params = json!({"package": "vim"});
        let (transaction_id, receipt) =
            preview_and_approve(&mut preview_stream, "AddLayeredPackage", params.clone()).await;

        let (peer, broken_stream) = tokio::io::duplex(64);
        drop(peer);
        let mut broken_framed = FramedStream::new(broken_stream);
        let typed_transaction_id = TransactionId(transaction_id.clone());
        let typed_receipt = ApprovalReceipt(receipt);
        let result = handle_execute(
            &mut broken_framed,
            &state,
            Arc::new(crate::executor::RealActionExecutor),
            runner(),
            &uid_caller(CallerRole::Admin),
            "execute-disconnected",
            &typed_transaction_id,
            "AddLayeredPackage",
            &params,
            &typed_receipt,
        )
        .await;

        assert!(result.is_err(), "the initial response write must fail");
        assert!(
            state.running_exclusive.lock().await.is_empty(),
            "a disconnected client must not retain any exclusion lock"
        );
        assert_eq!(
            state
                .audit
                .get(&transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            JobState::Failed,
            "a claimed transaction must not remain Running when execution never starts"
        );
    }

    // ------------------------------------------------------------------
    // execute — full preview → execute flow
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn execute_after_preview_with_receipt_returns_job_completed() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);

        // Step 1: preview.
        let preview_req = json!({
            "type": "preview",
            "request_id": "r1",
            "action_name": "GetMemoryInfo",
            "params": {}
        });
        framed
            .send(&serde_json::to_vec(&preview_req).unwrap())
            .await
            .unwrap();

        let raw = framed.recv().await.unwrap();
        let preview_resp: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(preview_resp["type"], "preview_response");
        let transaction_id = preview_resp["transaction_id"].as_str().unwrap();
        let receipt = approve_preview(&mut framed, transaction_id).await;

        // Step 2: execute with the one-time receipt the daemon returned.
        let exec_req = json!({
            "type": "execute",
            "request_id": "r2",
            "transaction_id": transaction_id,
            "action_name": "GetMemoryInfo",
            "params": {},
            "approval_receipt": receipt
        });
        framed
            .send(&serde_json::to_vec(&exec_req).unwrap())
            .await
            .unwrap();

        // Expect job_started first.
        let raw = framed.recv().await.unwrap();
        let started: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(started["type"], "job_started");
        let job_id = started["job_id"].as_str().unwrap().to_string();

        // Drain frames until job_completed (there may be job_progress frames).
        loop {
            let raw = framed.recv().await.unwrap();
            let msg: Value = serde_json::from_slice(&raw).unwrap();
            let msg_type = msg["type"].as_str().unwrap();
            match msg_type {
                "job_progress" => {
                    assert_eq!(msg["job_id"], job_id);
                }
                "job_completed" => {
                    assert_eq!(msg["job_id"], job_id);
                    let status = msg["result"]["status"].as_str().unwrap();
                    // rpm-ostree may not be available in CI; both outcomes are valid.
                    assert!(
                        matches!(status, "succeeded" | "failed" | "needs_reboot"),
                        "unexpected status: {status}"
                    );
                    break;
                }
                other => panic!("unexpected message type: {other}"),
            }
        }
    }

    // ------------------------------------------------------------------
    // T12 — `update_status` failure surfaces as a job-completed warning
    //
    // When the audit-log update fails after a job runs, the dispatcher
    // logs to stderr AND attaches a "audit trail update failed: …"
    // string to the job_completed response's `warnings` field so the
    // client can flag the audit gap. The warning emission was
    // unverified: a regression that swapped the warnings push for an
    // early return would silently drop the audit-loss signal.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn update_status_failure_surfaces_as_audit_warning_in_job_completed() {
        use crate::audit_chain::{AuditKey, ChainRow, VerifyOutcome};
        use crate::store::AuditStore;
        use crate::transactions::{
            NewTransaction as NewTx, RecordedPreviewedTransaction, TransactionStoreError,
        };
        use sysknife_types::{JobState, PreviewEnvelope, TransactionRecord};

        // A tiny `AuditStore` wrapper that delegates to the real
        // SQLite-backed store for everything except `update_status`,
        // which returns the most plausible production failure mode
        // ("not found" — e.g. the row was rotated out before the dispatcher
        // could close the loop). The dispatcher must still emit
        // job_completed with the warning attached.
        #[derive(Debug)]
        struct UpdateStatusFails(std::sync::Arc<dyn AuditStore>);

        #[async_trait::async_trait]
        impl AuditStore for UpdateStatusFails {
            async fn record(&self, t: NewTx) -> Result<TransactionRecord, TransactionStoreError> {
                self.0.record(t).await
            }
            async fn record_previewed(
                &self,
                t: NewTx,
                p: PreviewEnvelope,
            ) -> Result<RecordedPreviewedTransaction, TransactionStoreError> {
                self.0.record_previewed(t, p).await
            }
            async fn get(
                &self,
                id: &str,
            ) -> Result<Option<TransactionRecord>, TransactionStoreError> {
                self.0.get(id).await
            }
            async fn get_preview(
                &self,
                id: &str,
            ) -> Result<Option<PreviewEnvelope>, TransactionStoreError> {
                self.0.get_preview(id).await
            }
            async fn update_status(
                &self,
                id: &str,
                _s: JobState,
            ) -> Result<(), TransactionStoreError> {
                Err(TransactionStoreError::NotFound(id.to_string()))
            }
            async fn approve_transaction(
                &self,
                id: &str,
            ) -> Result<Option<String>, TransactionStoreError> {
                self.0.approve_transaction(id).await
            }
            async fn revoke_unconsumed_approval(
                &self,
                id: &str,
            ) -> Result<bool, TransactionStoreError> {
                self.0.revoke_unconsumed_approval(id).await
            }
            async fn claim_approved_for_execution(
                &self,
                id: &str,
                digest: &str,
            ) -> Result<bool, TransactionStoreError> {
                self.0.claim_approved_for_execution(id, digest).await
            }
            async fn cleanup_stale_queued(&self) -> Result<u64, TransactionStoreError> {
                self.0.cleanup_stale_queued().await
            }
            async fn cancel_queued(&self, id: &str) -> Result<bool, TransactionStoreError> {
                self.0.cancel_queued(id).await
            }
            async fn list_transactions(
                &self,
                limit: u32,
                status: Option<&str>,
                action: Option<&str>,
                since: Option<u32>,
            ) -> Result<Vec<TransactionRecord>, TransactionStoreError> {
                self.0.list_transactions(limit, status, action, since).await
            }
            async fn list_history(
                &self,
                limit: u32,
                status: Option<&str>,
                action: Option<&str>,
                since: Option<u32>,
            ) -> Result<Vec<crate::transactions::JobHistoryEntry>, TransactionStoreError>
            {
                self.0.list_history(limit, status, action, since).await
            }
            async fn fetch_chain_row(
                &self,
                id: &str,
            ) -> Result<Option<ChainRow>, TransactionStoreError> {
                self.0.fetch_chain_row(id).await
            }
            async fn fetch_chain_rows(&self) -> Result<Vec<ChainRow>, TransactionStoreError> {
                self.0.fetch_chain_rows().await
            }
            async fn fetch_event_rows(
                &self,
            ) -> Result<Vec<crate::audit_chain::EventRow>, TransactionStoreError> {
                self.0.fetch_event_rows().await
            }
            async fn verify_audit_chain(
                &self,
                k: &AuditKey,
            ) -> Result<VerifyOutcome, TransactionStoreError> {
                self.0.verify_audit_chain(k).await
            }
        }

        let dir = tempdir().unwrap();
        let real = test_state(&dir);
        // Wrap the inner audit store with our update-status-failing decorator.
        let faulty: std::sync::Arc<dyn AuditStore> =
            std::sync::Arc::new(UpdateStatusFails(real.audit.clone()));
        let cfg = real.config.clone();
        let state = crate::state::DaemonState::open_with_audit(
            cfg,
            crate::policy::PolicyTable::empty(),
            None,
            faulty,
        );

        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);

        // Preview + execute against a low-risk action so Observer can run it.
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "r1",
                    "action_name": "GetMemoryInfo",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let preview_resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
        let transaction_id = preview_resp["transaction_id"].as_str().unwrap();
        let receipt = approve_preview(&mut framed, transaction_id).await;

        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "r2",
                    "transaction_id": transaction_id,
                    "action_name": "GetMemoryInfo",
                    "params": {},
                    "approval_receipt": receipt
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        // Drain frames until we hit job_completed.
        let mut completed: Option<Value> = None;
        for _ in 0..30 {
            let raw = framed.recv().await.unwrap();
            let msg: Value = serde_json::from_slice(&raw).unwrap();
            if msg["type"] == "job_completed" {
                completed = Some(msg);
                break;
            }
        }
        let completed = completed.expect("dispatcher must emit job_completed");
        let warnings = completed["result"]["warnings"]
            .as_array()
            .expect("warnings array on job_completed");

        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap_or("").contains("audit trail update failed")),
            "expected an `audit trail update failed` warning when update_status returns Err; got: {warnings:#?}"
        );
    }

    // ------------------------------------------------------------------
    // T4 — concurrent execute race at the dispatcher boundary
    //
    // The transactions store guarantees that receipt consumption and the
    // Queued-to-Running transition happen in one atomic claim; the second
    // caller observes that the receipt is consumed and bails. Drive
    // that contract through TWO concurrent unix_connection_handler instances
    // sharing one DaemonState: one preview produces a Queued row, then
    // two executes race for it.  Exactly one must reach job_started;
    // the other must surface `stale_approval`.
    //
    // The test runs against the multi-thread tokio runtime so the two
    // handlers are genuinely parallel — single-thread would serialise
    // them and never exercise the conditional UPDATE.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_executes_against_one_preview_serialise_to_one_winner() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        // ── Producer: one preview to seed a Queued row ───────────────
        let (pc, ps) = tokio::net::UnixStream::pair().unwrap();
        {
            let state = state.clone();
            tokio::spawn(async move {
                unix_connection_handler(
                    ps,
                    state,
                    runner(),
                    uid_caller_with(1000, CallerRole::Observer),
                )
                .await;
            });
        }
        let mut framed_p = FramedStream::new(pc);
        framed_p
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "preview-once",
                    "action_name": "GetMemoryInfo",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let raw = framed_p.recv().await.unwrap();
        let preview_resp: Value = serde_json::from_slice(&raw).unwrap();
        let transaction_id = preview_resp["transaction_id"].as_str().unwrap().to_string();
        let approval_receipt = approve_preview(&mut framed_p, &transaction_id).await;

        // ── Two execute connections sharing the same DaemonState ─────
        async fn exec_once(
            state: crate::state::DaemonState,
            transaction_id: String,
            approval_receipt: String,
            request_id: &'static str,
        ) -> Vec<Value> {
            let (c, s) = tokio::net::UnixStream::pair().unwrap();
            tokio::spawn(async move {
                unix_connection_handler(
                    s,
                    state,
                    runner(),
                    uid_caller_with(1000, CallerRole::Observer),
                )
                .await;
            });
            let mut f = FramedStream::new(c);
            f.send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": request_id,
                    "transaction_id": transaction_id,
                    "action_name": "GetMemoryInfo",
                    "params": {},
                    "approval_receipt": approval_receipt
                }))
                .unwrap(),
            )
            .await
            .unwrap();

            // Read frames until we hit either job_completed (winner path)
            // or error_response (loser path). Cap at 30 frames so a stuck
            // handler can't hang the test.
            let mut frames = Vec::new();
            for _ in 0..30 {
                let raw = match f.recv().await {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let v: Value = serde_json::from_slice(&raw).unwrap();
                let kind = v["type"].as_str().unwrap_or("").to_string();
                frames.push(v);
                if kind == "job_completed" || kind == "error_response" {
                    break;
                }
            }
            frames
        }

        let (a, b) = tokio::join!(
            exec_once(
                state.clone(),
                transaction_id.clone(),
                approval_receipt.clone(),
                "exec-A"
            ),
            exec_once(
                state.clone(),
                transaction_id.clone(),
                approval_receipt.clone(),
                "exec-B"
            ),
        );

        // Each side must end in either job_completed or error_response.
        let terminal = |frames: &[Value]| -> &'static str {
            for f in frames {
                match f["type"].as_str().unwrap_or("") {
                    "job_completed" => return "win",
                    "error_response" => return "lose",
                    _ => {}
                }
            }
            "neither"
        };
        let outcomes = [terminal(&a), terminal(&b)];

        // Exactly one winner, exactly one loser. Order is unspecified.
        let mut sorted = outcomes;
        sorted.sort();
        assert_eq!(
            sorted,
            ["lose", "win"],
            "exactly one execute must win and one must lose; got {outcomes:?}\n A={a:#?}\n B={b:#?}"
        );

        // The loser must be flagged as stale_approval, not some other
        // category — that's the receipt claim's wire contract.
        let loser = if outcomes[0] == "lose" { &a } else { &b };
        let err_frame = loser
            .iter()
            .find(|f| f["type"] == "error_response")
            .expect("loser has an error_response");
        assert_eq!(
            err_frame["category"], "stale_approval",
            "loser must be classified stale_approval; got {err_frame:#?}"
        );
    }

    // ------------------------------------------------------------------
    // T5 — replay attack at the dispatcher boundary
    //
    // The transaction store verifies and consumes the one-time receipt while
    // moving the row from Queued to Running. A captured receipt submitted a
    // second time must surface as `stale_approval`. Pin that contract through
    // the live dispatcher, not just the store.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn re_executing_a_completed_approval_returns_stale_approval() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();

        tokio::spawn(async move {
            unix_connection_handler(
                server,
                state,
                runner(),
                uid_caller_with(1000, CallerRole::Observer),
            )
            .await;
        });

        let mut framed = FramedStream::new(client);

        // Step 1: preview a low-risk action so we can drive the full
        // execute path under Observer (which can run Get* actions).
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "preview",
                    "request_id": "r1",
                    "action_name": "GetMemoryInfo",
                    "params": {}
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        let raw = framed.recv().await.unwrap();
        let preview_resp: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(preview_resp["type"], "preview_response");
        let transaction_id = preview_resp["transaction_id"].as_str().unwrap().to_string();
        let approval_receipt = approve_preview(&mut framed, &transaction_id).await;

        // Step 2: first execute — must succeed and reach a terminal state.
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "r2",
                    "transaction_id": transaction_id,
                    "action_name": "GetMemoryInfo",
                    "params": {},
                    "approval_receipt": approval_receipt
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        // Drain everything until job_completed so the transaction row
        // has been moved out of Queued.
        loop {
            let raw = framed.recv().await.unwrap();
            let msg: Value = serde_json::from_slice(&raw).unwrap();
            match msg["type"].as_str().unwrap() {
                "job_started" | "job_progress" => continue,
                "job_completed" => break,
                other => panic!("unexpected message during first execute: {other}"),
            }
        }

        // Step 3: replay the same one-time receipt. The receipt is consumed,
        // so the dispatcher must reject it rather than re-execute the action.
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "r3-replay",
                    "transaction_id": transaction_id,
                    "action_name": "GetMemoryInfo",
                    "params": {},
                    "approval_receipt": approval_receipt
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        let raw = framed.recv().await.unwrap();
        let resp: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            resp["type"], "error_response",
            "replay must produce error_response, got: {resp}"
        );
        assert_eq!(
            resp["category"], "stale_approval",
            "replay must be classified as stale_approval, got: {}",
            resp["category"]
        );
        assert_eq!(resp["request_id"], "r3-replay");
    }

    // ------------------------------------------------------------------
    // describe
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn describe_returns_command_and_risk_for_known_action() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "describe",
                "request_id": "r1",
                "action_name": "GetDateTime",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "describe_response");
        assert_eq!(resps[0]["request_id"], "r1");
        assert_eq!(resps[0]["command"], "timedatectl");
        assert_eq!(resps[0]["risk_level"], "low");
        assert_eq!(resps[0]["reboot_required"], false);
    }

    #[tokio::test]
    async fn describe_returns_error_for_unknown_action() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({
                "type": "describe",
                "request_id": "r1",
                "action_name": "NotARealAction",
                "params": {}
            })],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "validation_failure");
    }

    // ------------------------------------------------------------------
    // unknown message type
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_message_type_returns_validation_failure() {
        let dir = tempdir().unwrap();
        let state = test_state(&dir);

        let resps = exchange(
            state,
            CallerRole::Observer,
            vec![json!({"type": "does_not_exist", "request_id": "r1"})],
            1,
        )
        .await;

        assert_eq!(resps[0]["type"], "error_response");
        assert_eq!(resps[0]["category"], "validation_failure");
    }

    // ------------------------------------------------------------------
    // Dispatcher progress relay
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn fast_executor_progress_is_drained_before_job_completed() {
        struct FastProgressExecutor;

        #[async_trait::async_trait]
        impl ActionExecutor for FastProgressExecutor {
            async fn execute(
                &self,
                _spec: &crate::actions::ActionSpec,
            ) -> Result<crate::executor::ExecutionOutput, crate::executor::ExecutorError>
            {
                unreachable!("dispatcher uses execute_with_progress")
            }

            async fn execute_with_progress(
                &self,
                _spec: &crate::actions::ActionSpec,
                progress: tokio::sync::mpsc::UnboundedSender<String>,
            ) -> Result<crate::executor::ExecutionOutput, crate::executor::ExecutorError>
            {
                progress.send("last line before exit".to_string()).unwrap();
                Ok(crate::executor::ExecutionOutput {
                    stdout: "last line before exit\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                })
            }
        }

        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(async move {
            connection_handler_with_executor(
                server,
                state,
                runner(),
                Arc::new(FastProgressExecutor),
                uid_caller(CallerRole::Observer),
            )
            .await;
        });
        let mut framed = FramedStream::new(client);
        let (transaction_id, receipt) =
            preview_and_approve(&mut framed, "GetMemoryInfo", json!({})).await;
        framed
            .send(
                &serde_json::to_vec(&json!({
                    "type": "execute",
                    "request_id": "execute-fast-progress",
                    "transaction_id": transaction_id,
                    "action_name": "GetMemoryInfo",
                    "params": {},
                    "approval_receipt": receipt,
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        let mut progress_lines = Vec::new();
        loop {
            let response: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
            match response["type"].as_str().unwrap() {
                "job_progress" => {
                    progress_lines.push(response["line"].as_str().unwrap().to_string())
                }
                "job_started" => {}
                "job_completed" => break,
                other => panic!("unexpected response: {other}"),
            }
        }
        assert!(progress_lines
            .iter()
            .any(|line| line == "last line before exit"));
    }

    // ------------------------------------------------------------------
    // vsock token auth gate
    // ------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    mod vsock_auth {
        use super::*;
        use std::sync::Arc;

        fn executor() -> Arc<dyn ActionExecutor> {
            Arc::new(crate::executor::RealActionExecutor)
        }

        /// The daemon refuses a token file other local users can read, so
        /// tests must provision one the way an operator is told to
        /// (`install -m 600`). `std::fs::write` alone lands at 0644 under the
        /// usual umask and would be rejected.
        fn write_token_mode(path: &std::path::Path, mode: u32) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        /// A bearer token any local user can read is not a credential. The
        /// daemon must refuse it rather than grant `token_role()` to whoever
        /// presents it.
        #[tokio::test]
        async fn group_or_world_readable_token_file_is_rejected() {
            let dir = tempdir().unwrap();
            let token_path = dir.path().join("token");
            std::fs::write(&token_path, "test-secret").unwrap();
            write_token_mode(&token_path, 0o644);

            assert!(
                crate::auth::validate_token_against_file("test-secret", &token_path).is_none(),
                "a 0644 token file must be rejected even when the token matches"
            );

            // Same file, same token, tightened permissions — now accepted.
            write_token_mode(&token_path, 0o600);
            assert!(
                crate::auth::validate_token_against_file("test-secret", &token_path).is_some(),
                "a 0600 token file with a matching token must be accepted"
            );
        }

        /// Send a valid auth frame then a `query_state` — connection must succeed.
        #[tokio::test]
        async fn valid_token_grants_access() {
            let dir = tempdir().unwrap();
            let token_path = dir.path().join("token");
            std::fs::write(&token_path, "test-secret").unwrap();
            write_token_mode(&token_path, 0o600);

            let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
            let state = test_state(&dir);

            tokio::spawn(async move {
                let mut framed = FramedStream::new(server);
                let role = authenticate_vsock_token(&mut framed, &token_path).await;
                if let Some(r) = role {
                    dispatch_loop(
                        &mut framed,
                        state,
                        runner(),
                        executor(),
                        CallerAttribution::from_vsock_token(r),
                    )
                    .await;
                }
            });

            let mut framed = FramedStream::new(client);
            let auth = serde_json::json!({"type": "auth", "token": "test-secret"});
            framed
                .send(&serde_json::to_vec(&auth).unwrap())
                .await
                .unwrap();
            let req = serde_json::json!({"type": "query_state", "request_id": "vsock-r1"});
            framed
                .send(&serde_json::to_vec(&req).unwrap())
                .await
                .unwrap();
            let raw = framed.recv().await.unwrap();
            let resp: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(resp["type"], "state_response");
        }

        /// Wrong token — connection must be closed immediately (EOF on client).
        #[tokio::test]
        async fn wrong_token_closes_connection() {
            let dir = tempdir().unwrap();
            let token_path = dir.path().join("token");
            std::fs::write(&token_path, "correct").unwrap();
            write_token_mode(&token_path, 0o600);

            let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
            let state = test_state(&dir);

            tokio::spawn(async move {
                let mut framed = FramedStream::new(server);
                let _ = authenticate_vsock_token(&mut framed, &token_path).await;
                // None returned — handler closes connection (drops framed)
                drop(state);
            });

            let mut framed = FramedStream::new(client);
            let auth = serde_json::json!({"type": "auth", "token": "wrong"});
            framed
                .send(&serde_json::to_vec(&auth).unwrap())
                .await
                .unwrap();
            // Server dropped the stream — recv must fail (EOF or reset)
            let result = framed.recv().await;
            assert!(
                result.is_err(),
                "expected EOF after wrong token, got {:?}",
                result
            );
        }

        /// EOF before any auth frame — connection must be closed without panic.
        #[tokio::test]
        async fn eof_before_auth_frame_closes_connection() {
            let dir = tempdir().unwrap();
            let token_path = dir.path().join("token");
            std::fs::write(&token_path, "secret").unwrap();
            write_token_mode(&token_path, 0o600);

            let (client, server) = tokio::io::duplex(4 * 1024 * 1024);

            tokio::spawn(async move {
                let mut framed = FramedStream::new(server);
                let result = authenticate_vsock_token(&mut framed, &token_path).await;
                assert!(result.is_none());
            });

            // Close write side immediately (sends EOF)
            drop(client);
        }

        /// Malformed JSON as first frame — must return None without panic.
        #[tokio::test]
        async fn malformed_json_frame_closes_connection() {
            let dir = tempdir().unwrap();
            let token_path = dir.path().join("token");
            std::fs::write(&token_path, "secret").unwrap();
            write_token_mode(&token_path, 0o600);

            let (client, server) = tokio::io::duplex(4 * 1024 * 1024);

            let handle = tokio::spawn(async move {
                let mut framed = FramedStream::new(server);
                let result = authenticate_vsock_token(&mut framed, &token_path).await;
                assert!(result.is_none());
            });

            let mut framed = FramedStream::new(client);
            framed.send(b"not json at all {{{{").await.unwrap();
            drop(framed);
            handle.await.unwrap();
        }

        /// Wrong `type` field — must return None.
        #[tokio::test]
        async fn wrong_msg_type_closes_connection() {
            let dir = tempdir().unwrap();
            let token_path = dir.path().join("token");
            std::fs::write(&token_path, "secret").unwrap();
            write_token_mode(&token_path, 0o600);

            let (client, server) = tokio::io::duplex(4 * 1024 * 1024);

            let handle = tokio::spawn(async move {
                let mut framed = FramedStream::new(server);
                let result = authenticate_vsock_token(&mut framed, &token_path).await;
                assert!(result.is_none());
            });

            let mut framed = FramedStream::new(client);
            let bad = serde_json::json!({"type": "query_state", "token": "secret"});
            framed
                .send(&serde_json::to_vec(&bad).unwrap())
                .await
                .unwrap();
            drop(framed);
            handle.await.unwrap();
        }
    }

    // ------------------------------------------------------------------
    // stream-type agnosticism (vsock / duplex)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn connection_handler_accepts_duplex_stream() {
        // Proves the handler works with any AsyncRead+AsyncWrite stream,
        // not only UnixStream. This is the key invariant enabling vsock support.
        let (client, server) = tokio::io::duplex(4 * 1024 * 1024);
        let dir = tempdir().unwrap();
        let state = test_state(&dir);
        tokio::spawn(unix_connection_handler(
            server,
            state,
            runner(),
            uid_caller(CallerRole::Observer),
        ));

        let mut framed = FramedStream::new(client);
        let req = json!({"type": "query_state", "request_id": "duplex-r1"});
        framed
            .send(&serde_json::to_vec(&req).unwrap())
            .await
            .unwrap();
        let raw = framed.recv().await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(resp["type"], "state_response");
        assert_eq!(resp["request_id"], "duplex-r1");
    }
}
