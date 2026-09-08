//! Top-level dispatch for all `sysknife` CLI commands.
//!
//! Each public `run_*` function corresponds to one subcommand or the
//! free-form intent path.  All printed output goes through [`Logger`] so
//! that `--log-to` tee works transparently.
//!
//! ## Approval flow
//!
//! Without `--step-by-step`: [`ApprovalPolicy::decide_plan`] is called once
//! for the whole plan.  If a single confirmation is needed the user is asked
//! once, then all steps execute in sequence.
//!
//! With `--step-by-step`: [`ApprovalPolicy::decide_step`] is called before
//! each step so the user can approve or reject them individually.
//!
//! `--dry-run` short-circuits before any execution: the plan is printed and
//! the function returns `Ok(())`.

use std::io::{self, IsTerminal, Write as _};
use std::path::PathBuf;

use clap::CommandFactory;
use serde_json::{json, Value};
use sysknife_brain::config::BrainConfig;
use sysknife_brain::planner::{LlmPlanner, Plan, PlanRiskLevel};
use sysknife_brain::PlanEvent;
use sysknife_types::{
    DistroHint, RiskLevel, TransactionId, DISTRO_FAMILY_DEBIAN, DISTRO_FAMILY_FEDORA,
    DISTRO_FAMILY_OTHER,
};

use sysknife_brain::state_client::StateClient as _;

use crate::approval::{ApprovalDecision, ApprovalPolicy, MaxRisk};
use crate::cli::{AuditExportArgs, AuditVerifyArgs, Cli, HistoryArgs};
use crate::client::{DaemonClient, SocketTarget};
use crate::error::CliError;

// ---------------------------------------------------------------------------
// distro_id_to_hint — DistroId → DistroHint conversion
// ---------------------------------------------------------------------------

/// Convert a `sysknife_core::distro::DistroId` to a `DistroHint` for the planner.
///
/// This is the single place where the CLI bridges the detection layer
/// (`sysknife-core`) and the planning layer (`sysknife-brain`), keeping each
/// side independent of the other.
pub fn distro_id_to_hint(distro: &sysknife_core::distro::DistroId) -> DistroHint {
    use sysknife_core::distro::DistroFamily;
    let family = match distro.family() {
        DistroFamily::Fedora => DISTRO_FAMILY_FEDORA,
        DistroFamily::Debian => DISTRO_FAMILY_DEBIAN,
        DistroFamily::Other => DISTRO_FAMILY_OTHER,
    };
    DistroHint {
        family,
        version: Some(distro.to_string()),
    }
}

// ---------------------------------------------------------------------------
// resolve_socket / resolve_socket_target
// ---------------------------------------------------------------------------

/// Resolve the daemon [`SocketTarget`] the CLI (and MCP server) should dial.
///
/// Precedence:
/// 1. `$SYSKNIFE_SOCKET` — explicit override; accepts `unix://`, `vsock://`, or
///    a bare path.
/// 2. Otherwise [`sysknife_core::default_listen_uri`] — the *same* resolver the
///    daemon and Tauri GUI use (`$SYSKNIFE_LISTEN_URI` →
///    `$XDG_RUNTIME_DIR/sysknife/daemon.sock` → `/tmp/sysknife-$UID.sock`). This
///    keeps the CLI pointed at wherever the daemon actually bound in both dev
///    and production, rather than a hardcoded production path that only matches
///    under systemd.
///
/// Exits the process if the resolved target string is unparseable.
pub fn resolve_socket_target() -> SocketTarget {
    let raw =
        std::env::var("SYSKNIFE_SOCKET").unwrap_or_else(|_| sysknife_core::default_listen_uri());
    SocketTarget::try_from_str(&raw).unwrap_or_else(|e| {
        eprintln!("sysknife: invalid socket target {raw:?}: {e}");
        std::process::exit(1);
    })
}

/// `remote_daemon_caveat` applied to the process environment.
///
/// Reads its own variable rather than taking one as an argument — the same shape
/// [`verify_configured_anchor`] uses — so the caveat cannot drift from the socket
/// the client actually used. An unparseable value yields no caveat:
/// `resolve_socket_target` already exits with a clear message before
/// verification runs.
pub(crate) fn remote_daemon_caveat_from_env() -> Option<String> {
    let (raw, source, target) = configured_socket_target()?;
    // `SYSKNIFE_SOCKET` is a deliberate client-side override, so any value there
    // — unix or vsock — carries the wrong-machine caveat.
    if source == "SYSKNIFE_SOCKET" {
        return remote_daemon_caveat(Some((&raw, source)), &target);
    }
    // `SYSKNIFE_LISTEN_URI` is not, on its own, a remoteness signal: the packaged
    // daemon unit sets it to the *local* socket, and `config.toml`'s `[daemon]
    // socket` maps here too, so a local single-box deployment has it set. Warning
    // on every unix value would print the caveat on every `audit verify` of a
    // local daemon — the exact "caveat nobody reads" failure this note guards
    // against. A vsock target is the one unambiguous case: the daemon is in
    // another kernel, so warn for that and stay quiet for unix.
    //
    // A unix socket *forwarded* through `config.toml` is therefore a false
    // negative here; distinguishing it from a local config socket needs the
    // daemon's own machine identity (issue #146), which is why
    // `resolve_daemon_socket_caveat` prefers the machine-id comparison and only
    // falls back to this heuristic.
    if matches!(target, SocketTarget::Vsock { .. }) {
        return remote_daemon_caveat(Some((&raw, source)), &target);
    }
    None
}

/// The caveat that belongs next to a verification verdict when the daemon being
/// administered may not be the machine whose chain was just read.
///
/// SysKnife has two data paths and they do not go to the same place. `plan`,
/// `execute`, `history` and `doctor` travel over `SYSKNIFE_SOCKET`, which the
/// documented topologies point at another host: an SSH-forwarded Unix socket, or
/// a vsock target in a VM. Verification is not a daemon request at all; it opens
/// a store on the local filesystem (see [`sysknife_core::resolve_audit_store`]).
///
/// So an operator who tunnels to `web01`, executes there, then runs `audit
/// verify` reads their **own** machine's store. If that store exists, which it
/// does on any laptop that ever ran a user-mode daemon, the verdict is `Intact`
/// for a chain that has nothing to do with the actions just taken. Silence there
/// would turn the product's central claim into a false reassurance.
///
/// `socket_env` is the raw `SYSKNIFE_SOCKET` value, or `None` when unset. Unset
/// means the local default, which is the common case and stays quiet: a caveat
/// printed on every run is a caveat nobody reads.
fn remote_daemon_caveat(socket_env: Option<(&str, &str)>, target: &SocketTarget) -> Option<String> {
    let (raw, source) = socket_env?;

    #[cfg(target_os = "linux")]
    if matches!(target, SocketTarget::Vsock { .. }) {
        return Some(format!(
            "NOTE: {source} is {raw}, so the daemon runs in a VM while this \
             verification read a store on this machine. The chain lives where the daemon \
             wrote it. Verify inside the VM, or copy its database and exported public key \
             out and re-run with --pubkey <FILE>."
        ));
    }

    Some(format!(
        "NOTE: {source} is {raw}. If that socket is forwarded from another host \
         (for example `ssh -L`), the actions you took ran there while this verification \
         read a store on this machine. Verify on the host that owns the daemon, or copy \
         its database and exported public key out and re-run with --pubkey <FILE>."
    ))
}

/// The machine-id comparison verdict for `audit verify` (#146).
///
/// Only a *mismatch* is a reliable signal: two hosts with different
/// `/etc/machine-id` are definitely different machines, so a forwarded socket to
/// one of them warrants the wrong-machine caveat — which is what closes the gap.
/// A *match* is deliberately NOT treated as proof of "this machine": cloned VM
/// and container images routinely share one `/etc/machine-id`, so equal hashes
/// can mean two distinct clones. The check therefore only ever ADDS a warning;
/// it never suppresses one the transport heuristic would raise (a hash match
/// falls through to `Unknown` → the heuristic, which keeps vsock-always-warns and
/// the explicit-`SYSKNIFE_SOCKET` warning intact).
#[derive(Debug, PartialEq, Eq)]
enum SocketOrigin {
    /// The daemon's machine-id differs from this host's: a different machine.
    Remote(String),
    /// Inconclusive — daemon unreachable, an older daemon without the field,
    /// `/etc/machine-id` unreadable, or hashes that MATCH (not proof of local,
    /// because clones share a machine-id). Fall back to the env heuristic.
    Unknown,
}

/// The configured daemon socket the client would dial: `SYSKNIFE_SOCKET` (an
/// explicit override) wins, else `config.toml`/unit-provided
/// `SYSKNIFE_LISTEN_URI`. Matches `resolve_socket_target`'s precedence: a
/// set-but-unparseable `SYSKNIFE_SOCKET` short-circuits to `None` (it is never
/// silently skipped in favor of `SYSKNIFE_LISTEN_URI`, which the client would
/// not dial).
fn configured_socket_target() -> Option<(String, &'static str, SocketTarget)> {
    if let Ok(raw) = std::env::var("SYSKNIFE_SOCKET") {
        let target = SocketTarget::try_from_str(&raw).ok()?;
        return Some((raw, "SYSKNIFE_SOCKET", target));
    }
    if let Ok(raw) = std::env::var("SYSKNIFE_LISTEN_URI") {
        if let Ok(target) = SocketTarget::try_from_str(&raw) {
            return Some((raw, "SYSKNIFE_LISTEN_URI", target));
        }
    }
    None
}

/// Pure decision: compare the daemon's reported machine-id hash to the local one.
/// Split from the I/O so the verdict logic is deterministically testable. Only a
/// definite mismatch yields `Remote`; everything else is `Unknown` (see the enum
/// docs for why a match is not `Local`).
fn socket_origin_from(
    local_hash: Option<&str>,
    daemon_hash: Option<&str>,
    raw: &str,
    source: &str,
    target: &SocketTarget,
) -> SocketOrigin {
    match (local_hash, daemon_hash) {
        (Some(l), Some(d)) if l != d => SocketOrigin::Remote(
            // Given `Some(socket_env)`, remote_daemon_caveat always returns Some
            // (it only returns None for an unset socket).
            remote_daemon_caveat(Some((raw, source)), target)
                .expect("a configured socket always yields a caveat message"),
        ),
        _ => SocketOrigin::Unknown,
    }
}

/// Ask the configured daemon for its machine-id hash and compare it to this
/// host's. `Remote` only on a definite mismatch; otherwise `Unknown`.
///
/// The query only runs for a unix socket configured via `SYSKNIFE_LISTEN_URI` —
/// the one case the env heuristic is silent on. For an explicit `SYSKNIFE_SOCKET`
/// or a vsock target the heuristic already warns, so a round-trip could not add
/// anything and is skipped (keeping `audit verify` offline in those cases).
fn daemon_socket_origin() -> SocketOrigin {
    let Some((raw, source, target)) = configured_socket_target() else {
        return SocketOrigin::Unknown;
    };
    if source != "SYSKNIFE_LISTEN_URI" || !matches!(target, SocketTarget::Unix(_)) {
        return SocketOrigin::Unknown;
    }
    let local = sysknife_daemon::state_collector::machine_id_hash();
    let daemon = DaemonClient::new(target.clone()).machine_id_hash();
    socket_origin_from(local.as_deref(), daemon.as_deref(), &raw, source, &target)
}

/// The wrong-machine caveat for `audit verify`. A definite machine-id mismatch
/// adds the caveat (closing the forwarded-unix-socket gap #146); otherwise it
/// falls back to the env-only heuristic, so behavior is never worse than before
/// and the heuristic's vsock/explicit-override warnings are never suppressed.
fn resolve_daemon_socket_caveat() -> Option<String> {
    match daemon_socket_origin() {
        SocketOrigin::Remote(caveat) => Some(caveat),
        SocketOrigin::Unknown => remote_daemon_caveat_from_env(),
    }
}

/// The caveat that belongs next to a verification verdict when no independent
/// checkpoint anchor is configured.
///
/// Truncating the newest rows needs no signing key: the retained prefix still
/// chains, and verification walks it from an empty expected predecessor, so it
/// reports `Intact`. Detecting the loss requires a previously anchored signed
/// tip in a store the host attacker does not control. Returning `None` when an
/// anchor exists keeps the normal output free of noise.
/// Render an anchor cross-check verdict for the human report.
fn anchor_line(outcome: &CheckpointOutcome) -> String {
    match outcome {
        CheckpointOutcome::Consistent {
            checkpoints_checked,
        } => format!(
            "OK: {checkpoints_checked} anchored checkpoint(s) still match this chain \
             (a deleted tail would show here)"
        ),
        CheckpointOutcome::Truncated {
            checkpoint_seq,
            current_max_seq,
        } => format!(
            "TRUNCATED: seq={checkpoint_seq} was anchored but the chain now ends at \
             seq={current_max_seq}. Rows have been deleted since that checkpoint."
        ),
        CheckpointOutcome::TipMismatch {
            seq,
            anchored,
            actual,
        } => format!(
            "REWRITTEN: the chain hash at seq={seq} does not match the anchored \
             value.\n  anchored: {anchored}\n  actual:   {actual}"
        ),
        CheckpointOutcome::BadSignature { seq } => format!(
            "BAD CHECKPOINT SIGNATURE: the checkpoint at seq={seq} does not verify \
             under this key"
        ),
        CheckpointOutcome::CannotVerify { reason } => {
            format!("ANCHOR NOT CHECKED: {reason}")
        }
    }
}

/// The machine-readable form of [`anchor_line`].
fn anchor_json(outcome: &CheckpointOutcome) -> serde_json::Value {
    let status = match outcome {
        CheckpointOutcome::Consistent { .. } => "consistent",
        CheckpointOutcome::Truncated { .. } => "truncated",
        CheckpointOutcome::TipMismatch { .. } => "rewritten",
        CheckpointOutcome::BadSignature { .. } => "bad_signature",
        CheckpointOutcome::CannotVerify { .. } => "cannot_verify",
    };
    json!({
        "configured": true,
        "status": status,
        "detail": anchor_line(outcome),
    })
}

fn anchor_caveat() -> &'static str {
    "NOTE: no independent checkpoint anchor is configured, so removal of the \
         newest rows would not be detectable — a truncated chain still verifies. \
         Set SYSKNIFE_CHECKPOINT_DB and run `sysknife audit checkpoint` \
         periodically; see docs/the-audit-chain.md."
}

/// Whether this step needs an operator confirmation *after* its preview has
/// been rendered.
///
/// Two modes, one rule:
///
/// - `--step-by-step` asks about every step, so every step is confirmed here,
///   where the daemon's proposed change is already visible.
/// - Otherwise the single plan-level prompt covers the scope of the run, and
///   re-asking per step would turn one prompt into N. HIGH risk is the
///   exception: it is the one class `--yes` can never auto-approve
///   (`HARDCODED_MAX_AUTO_APPROVE` is MEDIUM), and it is where "what exactly
///   changes" matters most, so it is re-confirmed against the real preview.
///
/// This adds no new refusal class to `--non-interactive`: a plan containing a
/// HIGH step is already refused at the plan gate before this point.
///
/// `--dangerously-skip-approval` deliberately does not change this predicate.
/// A HIGH step still takes the post-preview branch, so the daemon's preview is
/// still fetched, still checked against the approved risk, and still printed;
/// the policy then answers `AutoApproved` instead of asking. Short-circuiting
/// here instead would have skipped the preview itself, and the preview is the
/// only record of what an unattended run was about to change.
fn post_preview_confirmation_required(step_by_step: bool, risk: &PlanRiskLevel) -> bool {
    step_by_step || matches!(risk, PlanRiskLevel::High)
}

/// Whether the daemon recorded the unattended declaration in this preview.
///
/// Compares against the daemon's own constant rather than a copy of the
/// sentence. A local literal here would be a second source of truth that could
/// drift silently, and the failure mode of that drift is the CLI deciding an
/// unattended run *was* recorded when it was not.
fn unattended_marker_present(warnings: &[String]) -> bool {
    warnings
        .iter()
        .any(|w| w == sysknife_daemon::dispatcher::UNATTENDED_WARNING)
}

// ---------------------------------------------------------------------------
// since_to_hours
// ---------------------------------------------------------------------------

/// Parse an RFC 3339 / ISO-8601 UTC datetime string and return the number of
/// whole hours that have elapsed since that moment.
///
/// Returns `None` when:
/// - the string is not a valid UTC timestamp (`Z` or `+00:00` suffix),
/// - the datetime is in the future, or
/// - the value is too large to fit in `u32`.
///
/// Sub-second precision (`.NNN`) is accepted and truncated.  Non-zero UTC
/// offsets are not supported and return `None`.
pub fn since_to_hours(s: &str) -> Option<u32> {
    let epoch = rfc3339_to_unix(s)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    if epoch > now {
        return None;
    }
    u32::try_from((now - epoch) / 3600).ok()
}

/// Parse a UTC RFC 3339 string to seconds since Unix epoch (no external dep).
///
/// Supports `YYYY-MM-DDThh:mm:ssZ` and `YYYY-MM-DDThh:mm:ss+00:00`.
/// Sub-second fractions are stripped.
///
/// Uses Howard Hinnant's civil day algorithm to convert a proleptic-Gregorian
/// date to a day count, then scales to seconds.
fn rfc3339_to_unix(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00"))?;

    // Split on the 'T' separator.
    let (date_part, time_and_frac) = s.split_once('T')?;

    // Drop sub-second fractions: keep only up to "hh:mm:ss".
    let time_part = &time_and_frac[..time_and_frac.find('.').unwrap_or(time_and_frac.len())];
    if time_part.len() < 8 {
        return None;
    }

    // Parse date components.
    let mut date_iter = date_part.splitn(4, '-');
    let y: i64 = date_iter.next()?.parse().ok()?;
    let m: i64 = date_iter.next()?.parse().ok()?;
    let d: i64 = date_iter.next()?.parse().ok()?;
    if date_iter.next().is_some() {
        return None; // extra segments → reject
    }

    // Parse time components.
    let mut time_iter = time_part.splitn(4, ':');
    let h: i64 = time_iter.next()?.parse().ok()?;
    let mn: i64 = time_iter.next()?.parse().ok()?;
    let sec: i64 = time_iter.next()?.parse().ok()?;
    if time_iter.next().is_some() {
        return None; // extra segments → reject
    }

    // Range validation.
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mn > 59 || sec > 60
    // allow leap second
    {
        return None;
    }

    // Howard Hinnant's civil_from_days: compute days since 1970-01-01.
    //
    // Reference: https://howardhinnant.github.io/date_algorithms.html
    // The civil epoch starts on 0000-03-01; shift y back by 1 for Jan/Feb so
    // Feb 29 falls at the end of its civil year.
    let z = if m > 2 { y } else { y - 1 };
    let era = (if z >= 0 { z } else { z - 399 }) / 400;
    let yoe = z - era * 400; // year-of-era [0, 399]
    let m_adj = if m > 2 { m - 3 } else { m + 9 }; // month-of-civil-year [0, 11]
    let doy = (153 * m_adj + 2) / 5 + d - 1; // day-of-year from Mar 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day-of-era
    let days = era * 146097 + doe - 719468; // days since 1970-01-01

    Some(days * 86_400 + h * 3600 + mn * 60 + sec)
}

// ---------------------------------------------------------------------------
// authoritative_plan_risk + risk-consistency helpers
//
// The highest-risk-across-a-plan query lives on `AuthorizedPlan::highest_risk`
// so it can only be asked of a plan whose risks are authoritative.
// ---------------------------------------------------------------------------

/// Map the daemon's `RiskLevel` into the planner's risk enum.
fn plan_risk_of(risk: RiskLevel) -> PlanRiskLevel {
    match risk {
        RiskLevel::Low => PlanRiskLevel::Low,
        RiskLevel::Medium => PlanRiskLevel::Medium,
        RiskLevel::High => PlanRiskLevel::High,
    }
}

/// The authoritative risk for a plan step's action: the daemon's
/// `ActionSpec`-derived gate risk ([`sysknife_daemon::preview::gate_risk`]),
/// mapped into the planner's risk enum.
///
/// The CLI substitutes this for the LLM's *proposed* per-step risk (see
/// [`run_intent`]) so the plan the operator sees and the `--yes` / `--max-risk`
/// auto-approval decision derive from the single source of truth rather than a
/// model guess. Unknown actions map to `High` — `gate_risk`'s conservative
/// fallback — so a missing spec can never downgrade the CLI's approval friction.
///
/// Note: this reads the CLI binary's *own* linked `sysknife-daemon` catalogue,
/// which equals the running daemon's only when both are the same build. The
/// execution loop re-validates against the live daemon preview via
/// [`daemon_risk_within_approved`] so a version skew can never execute a step at
/// higher risk than was approved.
fn authoritative_plan_risk(action_name: &str) -> PlanRiskLevel {
    plan_risk_of(sysknife_daemon::preview::gate_risk(action_name))
}

/// Refuse a plan whose parameters the daemon would refuse, before the operator
/// is asked to approve it.
///
/// [`authoritative_plan_risk`] asks the catalogue about a step by *name* only,
/// so nothing built its `ActionSpec` until the daemon did — at execution, after
/// approval. A live Ubuntu 22.04 run showed what that costs: "block port 0 in
/// the firewall" produced an approvable `UfwDeny{port_or_service:"0"}` even
/// though the daemon's `validated_port_or_service` rejects port 0 outright, so
/// the operator was shown a plan that could only fail.
///
/// [`sysknife_daemon::executor::build_action_spec`] is the daemon's own
/// construction path, params and all, and it is pure — so calling it here
/// validates against the single source of truth rather than a second copy of
/// each rule that could drift from it. Anything it rejects here would have
/// failed at execution anyway; the only change is *when* the user finds out.
fn reject_unrunnable_params(plan: &Plan) -> Result<(), CliError> {
    for step in plan.steps() {
        if let Err(e) =
            sysknife_daemon::executor::build_action_spec(step.action_name(), step.params())
        {
            return Err(CliError::PlanningFailed(format!(
                "step {} has parameters the daemon cannot run: {e}",
                step.action_name()
            )));
        }
    }
    Ok(())
}

/// Fail-closed check run at execution time: is the live daemon's risk for a step
/// no higher than the risk the CLI approved it at?
///
/// The plan-level/step-level approval decisions use the CLI's locally linked
/// [`authoritative_plan_risk`]. If the connected daemon is a *different* build
/// that reclassified an action upward (e.g. Medium → High, the same shape as a
/// past security fix), the CLI could have auto-approved at the stale lower tier.
/// Before minting a receipt we compare against the daemon's live preview risk and
/// refuse to proceed when it is higher — the CLI must never execute a step at a
/// higher risk than the operator approved.
fn daemon_risk_within_approved(approved: &PlanRiskLevel, daemon: &PlanRiskLevel) -> bool {
    // PlanRiskLevel: Ord (Low < Medium < High).
    daemon <= approved
}

pub async fn run_approve(
    transaction_id: &TransactionId,
    socket: SocketTarget,
    json: bool,
    log: &Logger,
) -> Result<(), CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::ApprovalNeedsTerminal);
    }
    let client = DaemonClient::new(socket);
    let details = client.approval_details(transaction_id).await?;
    log.print_stderr(&format!(
        "Action:  {}\nRisk:    {:?}\nSummary: {}\nProposed change:\n{}",
        details.action_name,
        details.preview.risk_level,
        crate::operator_text::operator_safe(&details.preview.summary),
        // `to_string_pretty` is not a sanitiser: it escapes C0 controls but
        // emits U+202E and U+200B literally. This is the last thing printed
        // before the operator is asked to approve, and the proposed change is
        // the authoritative statement of what will happen — the one string on
        // screen that must not be able to lie about its own target.
        crate::operator_text::operator_safe_block(
            &serde_json::to_string_pretty(&details.preview.proposed_change)
                .unwrap_or_else(|_| "<unavailable>".to_string())
        )
    ));
    let approved = if details.preview.risk_level == RiskLevel::High {
        prompt_exact(
            "High-risk action. Type the exact action name to approve",
            &details.action_name,
        )
        .await
    } else {
        prompt_confirm(&format!("Approve transaction {}?", details.transaction_id)).await
    };
    if !approved {
        return Err(CliError::Rejected);
    }

    let receipt = client.approve(transaction_id).await?;
    if json {
        log.println(
            &serde_json::json!({
                "transaction_id": transaction_id.as_str(),
                "approval_receipt": receipt.as_str(),
            })
            .to_string(),
        );
    } else {
        // The one place the receipt is meant to leave the process: the
        // operator has to be able to paste it into `sysknife execute`.
        log.println(&format!("Approval receipt: {}", receipt.as_str()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// build_history_params (private helper)
// ---------------------------------------------------------------------------

pub(crate) fn build_history_params(
    limit: u32,
    status: Option<&str>,
    action: Option<&str>,
    since_hours: Option<u32>,
) -> Value {
    let mut params = json!({ "limit": limit });
    if let Some(s) = status {
        params["status_filter"] = json!(s);
    }
    if let Some(a) = action {
        params["action_filter"] = json!(a);
    }
    if let Some(h) = since_hours {
        params["since_hours"] = json!(h);
    }
    params
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

/// Tees all output to stdout and optionally to a log file.
///
/// `Mutex` makes `Logger` `Send + Sync` so it can be shared across the async
/// executor boundary without requiring a separate Arc.
pub struct Logger {
    file: std::sync::Mutex<Option<std::fs::File>>,
}

impl Logger {
    /// Construct.  Pass `None` to disable file tee.
    pub fn new(path: Option<&std::path::Path>) -> Result<Self, CliError> {
        let file = match path {
            None => None,
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(p)
                    .map_err(|e| CliError::ConfigOrDaemon(format!("open log file: {e}")))?,
            ),
        };
        Ok(Self {
            file: std::sync::Mutex::new(file),
        })
    }

    /// Print `line` to stdout and, if a log file is configured, also append it
    /// to that file.
    ///
    /// On the first file-write failure a warning is emitted to stderr and the
    /// file tee is permanently disabled so that subsequent writes do not spin
    /// on a dead handle.  The stdout print always succeeds (or panics, which is
    /// the correct response to a broken stdout in a CLI tool).
    pub fn println(&self, line: &str) {
        println!("{line}");
        let mut guard = self.file.lock().expect("Logger mutex poisoned");
        if let Some(f) = guard.as_mut() {
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("sysknife: log write failed ({e}); --log-to tee disabled");
                *guard = None;
            }
        }
    }

    /// Print `line` to stderr only.  Not teed to the log file — errors belong
    /// on stderr and must not be mixed into a structured log meant for parsing.
    pub fn print_stderr(&self, line: &str) {
        eprintln!("{line}");
    }
}

// ---------------------------------------------------------------------------
// run_completions
// ---------------------------------------------------------------------------

/// Write a shell completion script for `shell` to stdout.
pub fn run_completions(shell: clap_complete::Shell) {
    clap_complete::generate(shell, &mut Cli::command(), "sysknife", &mut io::stdout());
}

// ---------------------------------------------------------------------------
// run_doctor
// ---------------------------------------------------------------------------

/// Check daemon connectivity and print configuration summary.
pub async fn run_doctor(
    socket: SocketTarget,
    json_out: bool,
    log: &Logger,
) -> Result<(), CliError> {
    let config = BrainConfig::from_env().map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;

    // `{:?}` printed `Unix("/run/…")` at users; `label()` gives the URI form
    // they can put back into SYSKNIFE_SOCKET.
    let socket_label = socket.label();
    let client = DaemonClient::new(socket);

    // Detect the running distro once; failure is non-fatal for doctor.
    let distro_label = match sysknife_core::distro::detect() {
        Ok(d) => d.to_string(),
        Err(e) => format!("unknown ({})", e),
    };

    // `curated_state` is a blocking sync call; use spawn_blocking so the
    // multi-threaded runtime is not blocked on one thread indefinitely.
    let state_result = tokio::task::spawn_blocking(move || client.curated_state())
        .await
        .map_err(|e| CliError::ConfigOrDaemon(format!("join: {e}")))?;

    match state_result {
        Ok(state) => {
            if json_out {
                let out = json!({
                    "ok": true,
                    "socket": socket_label,
                    "host": state.host_name(),
                    "provider": config.provider_name(),
                    "model": config.model_name(),
                    "distro": distro_label,
                });
                log.println(&serde_json::to_string(&out).expect("static JSON"));
            } else {
                crate::render::print_doctor_ok(
                    &socket_label,
                    state.host_name(),
                    config.provider_name(),
                    config.model_name(),
                    &distro_label,
                    log,
                );
            }
            Ok(())
        }
        Err(e) => {
            if json_out {
                // Scripts need to know which socket failed, not just that one did.
                let out = json!({ "ok": false, "socket": socket_label, "error": e.to_string() });
                log.println(&serde_json::to_string(&out).expect("static JSON"));
            } else {
                crate::render::print_doctor_fail(&socket_label, &e.to_string());
            }
            // The report above is the user-facing output; `Exit` carries the
            // code (4, as for any config/daemon failure) without main
            // re-printing the same sentence underneath it.
            Err(CliError::Exit(4))
        }
    }
}

// ---------------------------------------------------------------------------
// run_history
// ---------------------------------------------------------------------------

/// Query past SysKnife execution history via `ListJobHistory`.
pub async fn run_history(
    args: HistoryArgs,
    socket: SocketTarget,
    log: &Logger,
) -> Result<(), CliError> {
    let since_hours = match args.since.as_deref() {
        None => None,
        Some(s) => {
            // Distinguish the two failure modes so the user knows how to fix each.
            if rfc3339_to_unix(s).is_none() {
                return Err(CliError::ConfigOrDaemon(format!(
                    "--since: {s:?} is not a valid UTC RFC 3339 timestamp \
                     (accepted formats: 2026-01-15T10:30:00Z or 2026-01-15T10:30:00+00:00)"
                )));
            }
            match since_to_hours(s) {
                Some(h) => Some(h),
                None => {
                    return Err(CliError::ConfigOrDaemon(format!(
                        "--since: {s:?} is in the future"
                    )));
                }
            }
        }
    };

    let params = build_history_params(
        args.limit,
        args.status.as_deref(),
        args.action.as_deref(),
        since_hours,
    );

    let client = DaemonClient::new(socket);
    let output =
        tokio::task::spawn_blocking(move || client.query_action("ListJobHistory", &params))
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("join: {e}")))?
            .map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;

    log.println(&output);
    Ok(())
}

// ---------------------------------------------------------------------------
// RunOpts
// ---------------------------------------------------------------------------

/// Options derived from global CLI flags; threaded into `run_intent` and
/// `run_repl` so callers do not have to pass each flag individually.
pub struct RunOpts {
    pub socket: SocketTarget,
    pub yes: bool,
    pub max_risk: Option<MaxRisk>,
    pub non_interactive: bool,
    pub dry_run: bool,
    pub json: bool,
    pub step_by_step: bool,
    /// Both halves of the two-key rule were supplied, so the approval gate is
    /// lifted for this run. Set only from [`crate::cli::UnattendedConsent`].
    pub skip_approval: bool,
}

impl RunOpts {
    /// Build the `ApprovalPolicy` for this set of flags.
    pub fn approval_policy(&self) -> ApprovalPolicy {
        ApprovalPolicy::new(
            self.yes,
            self.max_risk,
            self.non_interactive,
            self.dry_run,
            self.skip_approval,
        )
    }
}

// ---------------------------------------------------------------------------
// run_audit_export / run_audit_verify
// ---------------------------------------------------------------------------

/// Export the signed transaction-chain rows from the configured audit store.
///
/// This is deliberately a local storage read, just like `audit verify`; it
/// does not cross the daemon protocol or load the private audit key.
pub async fn run_audit_export(args: AuditExportArgs, log: &Logger) -> Result<(), CliError> {
    use sysknife_core::config::LacsConfig;
    use sysknife_daemon::audit_chain::{select_chain_rows_for_export, validate_export_since};

    if let Some(since) = args.since.as_deref() {
        validate_export_since(since).map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;
    }

    let lacs_config = LacsConfig::load();
    let resolved_store = sysknife_core::resolve_audit_store();
    if let Some(note) = resolved_store.note() {
        log.print_stderr(&format!("note: {note}"));
    }

    let rows = match lacs_config.storage.as_ref() {
        Some(storage) if storage.backend.eq_ignore_ascii_case("postgres") => {
            let config = postgres_config(storage)
                .map_err(|reason| CliError::ConfigOrDaemon(format!("audit export: {reason}")))?;
            sysknife_daemon::store::postgres::PostgresStore::read_chain_rows(&config)
                .await
                .map_err(|e| {
                    CliError::ConfigOrDaemon(format!("postgres audit chain query failed: {e}"))
                })?
        }
        _ => {
            use sysknife_daemon::transactions::TransactionStore;

            let db_path = resolved_store.path();
            // `Path::exists()` answers false for both ENOENT and EACCES, so
            // probing with it tells an operator the root-owned 0700 system
            // store does not exist and suggests starting the daemon, when the
            // daemon is running and the fix is sudo. `run_audit_verify` has
            // carried the corrected form since #275; export was written
            // without it.
            if !sysknife_core::path_is_present(db_path) {
                return Err(CliError::ConfigOrDaemon(format!(
                    "audit database not found at {}; set $SYSKNIFE_DATABASE_PATH or run the daemon first",
                    db_path.display()
                )));
            }
            if !db_path.exists() {
                let sudo_hint =
                    if db_path == std::path::Path::new(sysknife_core::PRODUCTION_DATABASE_PATH) {
                        "; the system daemon's store is root-owned, so run this under sudo or \
                     set $SYSKNIFE_DATABASE_PATH"
                    } else {
                        ""
                    };
                return Err(CliError::ConfigOrDaemon(format!(
                    "audit database not found or not readable at {}; set $SYSKNIFE_DATABASE_PATH \
                     or run the daemon first{sudo_hint}",
                    db_path.display()
                )));
            }
            let store = TransactionStore::open_read_only(db_path).map_err(|e| {
                CliError::ConfigOrDaemon(format!("opening audit database failed: {e}"))
            })?;
            store
                .fetch_chain_rows()
                .map_err(|e| CliError::ConfigOrDaemon(format!("audit chain query failed: {e}")))?
        }
    };

    let rows = select_chain_rows_for_export(rows, args.since.as_deref(), args.limit)
        .map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;
    let json = serde_json::to_string(&rows)
        .map_err(|e| CliError::ConfigOrDaemon(format!("serializing audit export failed: {e}")))?;
    log.println(&json);
    Ok(())
}

/// Walk the audit log hash chain and report integrity status.
///
/// Resolves the database path via [`sysknife_core::default_database_path`]
/// (same precedence as the daemon: `$SYSKNIFE_DATABASE_PATH` →
/// `$XDG_STATE_HOME/sysknife/daemon.sqlite` → fallbacks). Loads the audit
/// key from the path the daemon would generate it at (sibling of the DB,
/// or `$SYSKNIFE_AUDIT_KEY_PATH`).
///
/// Exit codes:
/// - 0 — chain intact across all rows
/// - 1 — chain broken; first offending row is reported
/// - 2 — verification could not be completed (missing key, unreadable DB,
///   retired key not on disk, etc.)
///
/// On exit code 2, do **not** treat the audit log as either intact or
/// tampered — the result is unknown until the operator resolves the
/// underlying access problem.
pub async fn run_audit_verify(args: AuditVerifyArgs, log: &Logger) -> Result<(), CliError> {
    use sysknife_core::config::LacsConfig;
    use sysknife_daemon::audit_chain::AuditKey;

    // Honour the same `[storage]` config the daemon uses, so `sysknife audit
    // verify` works against whichever backend is in production. Without this,
    // a Postgres-backed deployment can never verify its chain from the CLI.
    let lacs_config = LacsConfig::load();

    // A system-installed daemon keeps its chain in /var/lib/sysknife, but that
    // path reaches it through the unit's own Environment= lines, which a CLI run
    // by an operator never sees. Resolving only the per-user path therefore made
    // `audit verify` read an absent store and report the chain as unverifiable
    // on a perfectly healthy install.
    let store = sysknife_core::resolve_audit_store();

    let label_for_diag = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => "postgres".to_string(),
        _ => store.path().display().to_string(),
    };

    // Reading a store the operator did not name is never silent.
    if let Some(note) = store.note() {
        log.print_stderr(&format!("note: {note}"));
    }

    let db_path = store.path().to_path_buf();

    // Build the verifier. With `--pubkey`, verify using only the exported
    // public key (the auditor path, no private key). Otherwise load the private
    // signing key from its file (sibling of the SQLite path, or
    // `$SYSKNIFE_AUDIT_KEY_PATH`).
    let verifier = if let Some(pubkey_path) = args.pubkey.as_ref() {
        match std::fs::read_to_string(pubkey_path) {
            Ok(contents) => Verifier::Public(contents.trim().to_string()),
            Err(e) => {
                let reason = format!(
                    "public key file {} could not be read: {e}",
                    pubkey_path.display()
                );
                emit_verification(
                    &args,
                    log,
                    &cannot_verify_all(reason),
                    &label_for_diag,
                    None,
                );
                return Err(CliError::Exit(2));
            }
        }
    } else {
        let key_path = sysknife_daemon::audit_chain::resolve_audit_key_path(&db_path);

        if !key_path.exists() {
            let reason = format!(
                "audit key not found or not readable at {}; the daemon generates this \
                 on first run, set $SYSKNIFE_AUDIT_KEY_PATH, or pass --pubkey <FILE> to \
                 verify with the exported public key{}",
                key_path.display(),
                // The system store lives under a root-owned directory, so an
                // operator hits this path with a healthy chain. Say which of the
                // two escape hatches applies to that case.
                if store.path() == std::path::Path::new(sysknife_core::PRODUCTION_DATABASE_PATH) {
                    "; the system daemon's key is root-owned, so run this under sudo or \
                     verify with --pubkey"
                } else {
                    ""
                }
            );
            emit_verification(
                &args,
                log,
                &cannot_verify_all(reason),
                &label_for_diag,
                None,
            );
            return Err(CliError::Exit(2));
        }

        match AuditKey::load_or_generate(&key_path) {
            Ok(k) => Verifier::Private(Box::new(k)),
            Err(e) => {
                let reason = format!("audit key load failed: {e}");
                emit_verification(
                    &args,
                    log,
                    &cannot_verify_all(reason),
                    &label_for_diag,
                    None,
                );
                return Err(CliError::Exit(2));
            }
        }
    };

    // Branch on storage backend. SQLite: open the local file read-only.
    // Postgres: connect via sqlx and verify against the remote chain.
    let outcome = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => {
            verify_postgres(s, &verifier).await
        }
        _ => verify_sqlite(&db_path, &verifier).await,
    };

    // `verify_chain` proves the chain is internally consistent and correctly
    // signed. It cannot prove it is COMPLETE: a chain with its newest rows
    // deleted still verifies. Only a previously anchored tip catches that, and
    // this command used to report `audit_anchor: {configured: true}` without
    // ever reading the anchor — implying a check it did not perform.
    let anchor = verify_configured_anchor(&lacs_config, &db_path, &verifier).await;
    let exit_code = combined_verification_exit_code(&outcome, anchor.as_ref());
    emit_verification(&args, log, &outcome, &label_for_diag, anchor.as_ref());
    if exit_code == 0 {
        Ok(())
    } else {
        Err(CliError::Exit(exit_code))
    }
}

/// `sysknife audit checkpoint`: sign the current chain tip and anchor it to an
/// external append-only database, then verify all anchored checkpoints against
/// the local chain. Anchoring off-box is what makes truncation/rewrite of the
/// local chain detectable.
pub async fn run_audit_checkpoint(
    args: crate::cli::AuditCheckpointArgs,
    _log: &Logger,
) -> Result<(), CliError> {
    use sysknife_daemon::audit_chain::{
        checkpoint_outcome_to_exit_code, outcome_to_exit_code, AuditKey,
    };
    use sysknife_daemon::checkpoint_sink::{anchor_once, AnchorOutcome, PostgresCheckpointSink};
    use sysknife_daemon::transactions::TransactionStore;

    // Resolve the checkpoint database URL. Prefer the env var so credentials
    // are not exposed on the command line (visible via `ps` / shell history).
    let db_url = match args
        .db
        .clone()
        .or_else(|| std::env::var("SYSKNIFE_CHECKPOINT_DB").ok())
    {
        Some(u) => u,
        None => {
            eprintln!(
                "no checkpoint database configured; pass --db <URL> or set \
                 SYSKNIFE_CHECKPOINT_DB (preferred, keeps credentials off argv)"
            );
            return Err(CliError::Exit(2));
        }
    };

    let db_path = sysknife_core::default_database_path();

    // Load the private signing key (same location rules as `verify`).
    let key_path = sysknife_daemon::audit_chain::resolve_audit_key_path(&db_path);
    require_exists(&key_path, "audit key")?;
    let key = AuditKey::load_or_generate(&key_path).map_err(|e| {
        eprintln!("audit key load failed: {e}");
        CliError::Exit(2)
    })?;

    // Read the current chain tip from the local sqlite store.
    require_exists(&db_path, "audit database")?;
    let store = TransactionStore::open_read_only(&db_path).map_err(|e| {
        eprintln!("opening audit database failed: {e}");
        CliError::Exit(2)
    })?;
    let rows = store.fetch_chain_rows().map_err(|e| {
        eprintln!("reading audit chain failed: {e}");
        CliError::Exit(2)
    })?;
    // The anchoring rules — refuse a broken chain, read back after writing,
    // re-verify every anchored checkpoint — live in the daemon crate so this
    // command and the daemon's periodic anchor task cannot drift apart.
    let sink = PostgresCheckpointSink::connect(&db_url)
        .await
        .map_err(|e| {
            eprintln!("connecting to checkpoint database failed: {e}");
            CliError::Exit(2)
        })?;

    let created_at = chrono::Utc::now().to_rfc3339();
    let outcome = anchor_once(&key, &rows, &sink, &created_at)
        .await
        .map_err(|e| {
            eprintln!("checkpoint sink error: {e}");
            CliError::Exit(2)
        })?;

    match outcome {
        AnchorOutcome::Anchored {
            seq,
            checkpoints_checked,
        } => {
            println!("anchored checkpoint: seq={seq} -> external database");
            println!("checkpoints consistent ({checkpoints_checked} verified)");
            Ok(())
        }
        AnchorOutcome::ChainEmpty => {
            eprintln!("audit chain is empty; nothing to checkpoint");
            Err(CliError::Exit(2))
        }
        AnchorOutcome::ChainBroken(broken) => {
            eprintln!("refusing to anchor: local audit chain does not verify: {broken:?}");
            Err(CliError::Exit(outcome_to_exit_code(&broken)))
        }
        AnchorOutcome::ReadBackMissing => {
            eprintln!(
                "anchored checkpoint not found on read-back; the checkpoint database \
                 may be a lagging replica or a different database than the write hit"
            );
            Err(CliError::Exit(2))
        }
        AnchorOutcome::Inconsistent(other) => {
            eprintln!("checkpoint verification FAILED: {other:?}");
            Err(CliError::Exit(checkpoint_outcome_to_exit_code(&other)))
        }
    }
}

/// What the audit chain is verified against.
/// Cross-check the local chain against the configured checkpoint anchor.
///
/// `None` when no anchor is configured — that case keeps [`anchor_caveat`],
/// which is honest about truncation being undetectable. When one IS configured
/// the check must actually run: an operator who set anchoring up and gets back
/// only `configured: true` is worse informed than one who never bothered.
///
/// Anchoring is SQLite-only today (`sysknife audit checkpoint` opens a
/// `TransactionStore`), so a Postgres deployment gets an explicit "not
/// supported" rather than a silent skip that would read as coverage.
async fn verify_configured_anchor(
    lacs_config: &sysknife_core::config::LacsConfig,
    db_path: &std::path::Path,
    verifier: &Verifier,
) -> Option<CheckpointOutcome> {
    use sysknife_daemon::checkpoint_sink::{verify_against_anchor, PostgresCheckpointSink};
    use sysknife_daemon::transactions::TransactionStore;

    let db_url = std::env::var("SYSKNIFE_CHECKPOINT_DB")
        .ok()
        .filter(|v| !v.trim().is_empty())?;

    if lacs_config
        .storage
        .as_ref()
        .is_some_and(|s| s.backend.eq_ignore_ascii_case("postgres"))
    {
        return Some(CheckpointOutcome::CannotVerify {
            reason: "checkpoint anchoring is implemented for the sqlite backend only; \
                     `sysknife audit checkpoint` cannot anchor a postgres chain either, \
                     so this chain has no anchor to check against"
                .to_string(),
        });
    }

    let rows = match TransactionStore::open_read_only(db_path).and_then(|s| s.fetch_chain_rows()) {
        Ok(rows) => rows,
        Err(e) => {
            return Some(CheckpointOutcome::CannotVerify {
                reason: format!("reading the local chain for the anchor check failed: {e}"),
            })
        }
    };

    let sink = match PostgresCheckpointSink::connect(&db_url).await {
        Ok(s) => s,
        Err(e) => {
            return Some(CheckpointOutcome::CannotVerify {
                reason: format!("connecting to the checkpoint database failed: {e}"),
            })
        }
    };

    match verify_against_anchor(&verifier.verifying_key_hex(), &rows, &sink).await {
        Ok(outcome) => Some(outcome),
        Err(e) => Some(CheckpointOutcome::CannotVerify {
            reason: format!("reading anchored checkpoints failed: {e}"),
        }),
    }
}

pub(crate) enum Verifier {
    /// The private signing key (also derives the public key used to verify).
    Private(Box<sysknife_daemon::audit_chain::AuditKey>),
    /// Only the hex-encoded Ed25519 public key — the auditor path, which proves
    /// the chain without the ability to forge it.
    Public(String),
}

use sysknife_daemon::audit_chain::{AuditVerification, CheckpointOutcome};

impl Verifier {
    /// The hex Ed25519 public key, however the verifier was built. Checkpoint
    /// signatures verify with the public half in both the operator (private key
    /// on disk) and auditor (`--pubkey`) paths.
    fn verifying_key_hex(&self) -> String {
        match self {
            Verifier::Private(key) => key.verifying_key_hex(),
            Verifier::Public(hex) => hex.clone(),
        }
    }
}

/// Lift a single "we could not even read the rows" reason into all three
/// checks, so the caller never has to special-case a partially populated
/// result.
fn cannot_verify_all(reason: String) -> AuditVerification {
    use sysknife_daemon::audit_chain::{BindingOutcome, VerifyOutcome};
    AuditVerification {
        chain: VerifyOutcome::CannotVerify {
            reason: reason.clone(),
        },
        events: VerifyOutcome::CannotVerify { reason },
        binding: BindingOutcome::NotChecked,
        // The store or the key could not be opened, so no census was taken.
        // `None`, not a census of zero rows: a database nobody could read and an
        // empty one that read fine must not serialize the same way.
        attribution: None,
    }
}

pub(crate) async fn verify_sqlite(
    db_path: &std::path::Path,
    verifier: &Verifier,
) -> AuditVerification {
    use sysknife_daemon::audit_chain::{verify_all, verify_all_with_pubkey};
    use sysknife_daemon::transactions::TransactionStore;

    // Path::exists is false for both ENOENT and EACCES. Prefer a message that
    // covers the unreadable 0700 system store and points operators at sudo /
    // an explicit path, matching the audit-key diagnostic above.
    if !sysknife_core::path_is_present(db_path) {
        return cannot_verify_all(format!(
            "audit database not found at {}; set $SYSKNIFE_DATABASE_PATH \
             or run the daemon first",
            db_path.display()
        ));
    }
    if !db_path.exists() {
        let sudo_hint = if db_path == std::path::Path::new(sysknife_core::PRODUCTION_DATABASE_PATH)
        {
            "; the system daemon's store is root-owned, so run this under sudo or \
             set $SYSKNIFE_DATABASE_PATH"
        } else {
            ""
        };
        return cannot_verify_all(format!(
            "audit database not found or not readable at {}; set $SYSKNIFE_DATABASE_PATH \
             or run the daemon first{sudo_hint}",
            db_path.display()
        ));
    }
    let store = match TransactionStore::open_read_only(db_path) {
        Ok(s) => s,
        Err(e) => return cannot_verify_all(format!("opening audit database failed: {e}")),
    };
    let tx_rows = match store.fetch_chain_rows() {
        Ok(rows) => rows,
        Err(e) => return cannot_verify_all(format!("audit chain query failed: {e}")),
    };
    let event_rows = match store.fetch_event_rows() {
        Ok(rows) => rows,
        Err(e) => return cannot_verify_all(format!("approval-event query failed: {e}")),
    };
    match verifier {
        Verifier::Private(key) => verify_all(key, &tx_rows, &event_rows),
        Verifier::Public(vk_hex) => verify_all_with_pubkey(vk_hex, &tx_rows, &event_rows),
    }
}

pub(crate) async fn verify_postgres(
    storage: &sysknife_core::config::StorageSection,
    verifier: &Verifier,
) -> AuditVerification {
    use sysknife_daemon::store::postgres::PostgresStore;

    let cfg = match postgres_config(storage) {
        Ok(config) => config,
        Err(reason) => return cannot_verify_all(reason),
    };

    match verifier {
        Verifier::Private(key) => {
            let store =
                match PostgresStore::connect(&cfg, std::sync::Arc::new((**key).clone())).await {
                    Ok(s) => s,
                    Err(e) => return cannot_verify_all(format!("postgres connect failed: {e}")),
                };
            match store.verify_all(key).await {
                Ok(verification) => verification,
                Err(e) => cannot_verify_all(format!("postgres audit chain query failed: {e}")),
            }
        }
        Verifier::Public(verifying_key_hex) => {
            match PostgresStore::verify_all_with_pubkey(&cfg, verifying_key_hex).await {
                Ok(verification) => verification,
                Err(e) => cannot_verify_all(format!("postgres audit chain query failed: {e}")),
            }
        }
    }
}

/// Project the relaxed user-facing storage section into Postgres' checked
/// connection configuration. Both audit readers use this so `verify` and
/// `export` cannot drift on pool settings or URL validation.
fn postgres_config(
    storage: &sysknife_core::config::StorageSection,
) -> Result<sysknife_daemon::store::postgres::PostgresConfig, String> {
    use sysknife_core::config::StorageBackend;
    use sysknife_daemon::store::postgres::PostgresConfig;

    let (url, pool) = match storage.parsed()? {
        StorageBackend::Sqlite => {
            return Err(
                "postgres reader called with backend = \"sqlite\" — caller picked the wrong path"
                    .to_string(),
            );
        }
        StorageBackend::Postgres { url, pool } => (url, pool),
    };

    let mut config = PostgresConfig {
        url,
        ..PostgresConfig::default()
    };
    if let Some(value) = pool.max_connections {
        config.max_connections = value;
    }
    if let Some(value) = pool.acquire_timeout_secs {
        config.acquire_timeout = std::time::Duration::from_secs(value);
    }
    if let Some(value) = pool.statement_cache_capacity {
        config.statement_cache_capacity = value;
    }
    Ok(config)
}

/// What the chain verdict says about the standing of the attribution counts.
///
/// The three cases need different words, and collapsing them is how the notes
/// came to print "authentic and verified" under a `CANNOT VERIFY` verdict.
/// `Broken` is not the same as `CannotVerify` either: a break is evidence of
/// tampering somewhere, while an unknown encoding or a rotated key means this
/// build could not check, which is not a finding about the rows at all.
enum CountStanding {
    /// The chain verified end to end, so the counts are findings.
    Proven,
    /// A break was detected. Rows before it verified; rows after it were not
    /// checked by this walk, and the census cannot tell the two apart.
    BreakDetected,
    /// Nothing could be checked: an unknown `chain_version`, a `key_id` mismatch
    /// after key rotation, unusable `--pubkey` hex.
    NotChecked,
}

/// Say what the trail can and cannot tell an operator about who acted.
///
/// `standing` decides the wording of the two notes that describe what the rows
/// are; the unattested WARNING is about mechanism and does not use it. Without it
/// the notes asserted rows were "authentic and verified" underneath a `BROKEN` or
/// `CANNOT VERIFY` verdict, which is the one sentence this command must never
/// print.
///
/// One unconditional summary line, then a note per reason, because the reasons
/// have different remedies. An operator who reads only the summary still learns
/// the denominator; an operator acting on a note learns which of "chase
/// SO_PEERCRED", "nothing can be done" and "investigate an out-of-band write"
/// applies.
fn emit_attribution(
    log: &Logger,
    census: &sysknife_daemon::audit_chain::AttributionCensus,
    standing_of: CountStanding,
) {
    if census.rows() == 0 {
        return;
    }

    let standing = match standing_of {
        CountStanding::Proven => "authentic and verified",
        // Not "unverified": some of them may have verified, and this renderer
        // holds aggregate counts, so it cannot say which. What it can say without
        // overreaching is that the chain did not verify to the end.
        CountStanding::BreakDetected | CountStanding::NotChecked => {
            "read, on a chain that did not verify to the end"
        }
    };

    log.println(&format!(
        "ATTRIBUTION: {} of {} row(s) name an account; {} name nobody.",
        census.named(),
        census.rows(),
        census.unnamed(),
    ));
    match standing_of {
        CountStanding::Proven => {}
        CountStanding::BreakDetected => log.println(
            "  These counts describe what the rows claim, not what was proven. A break was \
             detected above, so rows past it were not checked by this walk. Some of them may \
             be perfectly authentic -- deleting or reordering a row breaks the link while \
             leaving every later signature valid -- and some may be an attacker's. This \
             command cannot tell you which, only that it did not vouch for them.",
        ),
        CountStanding::NotChecked => log.println(
            "  These counts describe what the rows claim, not what was proven: the verdict \
             above says this build could not check the chain at all. That is a statement \
             about this binary or this key, not a finding about the rows.",
        ),
    }

    if census.attribution_failed() > 0 {
        log.println(&format!(
            "NOTE: {} row(s) record that the daemon could not name the caller \
             (principal `{}`). Those actions are {standing}, but the trail cannot say \
             which account took them. This happens when SO_PEERCRED yields no usable \
             peer, or when the peer is not representable in the daemon's namespaces; \
             see the daemon log for the connections concerned.",
            census.attribution_failed(),
            sysknife_daemon::auth::CallerPrincipal::Unattributed.as_signed_str(),
        ));
    }
    // Kept separate from the note above on purpose. Both say "this row names
    // nobody", but only one of them describes something an operator can act on:
    // an attribution failure is a live configuration problem, while a row older
    // than the column is settled history. Merging them into one count was the
    // original defect: zero attribution failures over a pre-0.3.0 database read
    // as full attribution.
    if census.not_recorded() > 0 {
        log.println(&format!(
            "NOTE: {} row(s) carry no caller principal the signature covers, normally \
             because they were written before the chain signed one (chain_version 1 and 2, \
             so before 0.3.0). They are {standing}, and they name nobody. That cannot be \
             repaired: writing a principal into an existing row would change the bytes its \
             signature covers, so the trail keeps the gap instead of hiding it.",
            census.not_recorded(),
        ));
    }
    // The only note that asks for an investigation rather than explaining a
    // limit. Nothing in SysKnife writes these values, so one of them existing is
    // itself the finding.
    if census.unattested() > 0 {
        log.println(&format!(
            "WARNING: {} row(s) have no caller principal that any signature vouches for. \
             Three causes: the column is populated on an encoding that does not sign it \
             (chain_version 1 and 2 leave it out of the signed message, so it can be \
             written out of band without breaking anything); or the value is not one this \
             build can read back as something the daemon could have written; or the row \
             declares an encoding this build does not know, in which case its principal may \
             be absent or kept somewhere this build cannot see. The first two are \
             out-of-band writes to investigate. The third means a newer SysKnife wrote \
             these rows, and the fix is to verify with a build at least that new. Either \
             way these rows name nobody here.",
            census.unattested(),
        ));
    }
}

/// Render all three checks. The transaction chain stays the headline line so
/// existing output and exit codes are unchanged for a clean chain; the other
/// two are reported underneath and can independently fail the command.
fn emit_verification(
    args: &AuditVerifyArgs,
    log: &Logger,
    verification: &AuditVerification,
    backend_label: &str,
    anchor: Option<&CheckpointOutcome>,
) {
    use sysknife_daemon::audit_chain::{BindingOutcome, VerifyOutcome};

    let census = verification.attribution;

    if args.json {
        let payload = json!({
            "status": status_word(combined_verification_exit_code(verification, anchor)),
            "backend": backend_label,
            "chain": outcome_json(&verification.chain),
            "approval_events": outcome_json(&verification.events),
            "audit_anchor": match anchor {
                Some(outcome) => anchor_json(outcome),
                None => json!({"configured": false, "caveat": anchor_caveat()}),
            },
            "daemon_socket_caveat": resolve_daemon_socket_caveat(),
            // Null rather than zero when no census was taken. A machine reader
            // that alerts on low attribution must be able to tell "no rows were
            // read" from "no row named an account"; a zero for both is the
            // confusion this release exists to remove.
            "rows_censused": census.map(|c| c.rows()),
            "attributed_rows": census.map(|c| c.named()),
            "unattributed_rows": census.map(|c| c.attribution_failed()),
            "rows_without_principal": census.map(|c| c.not_recorded()),
            "rows_unattested": census.map(|c| c.unattested()),
            "rows_naming_no_account": census.map(|c| c.unnamed()),
            "binding": binding_json(&verification.binding),
        });
        log.println(
            &serde_json::to_string_pretty(&payload)
                .expect("verify outcome payload is serializable"),
        );
        return;
    }

    match &verification.chain {
        VerifyOutcome::Intact { rows_checked } => {
            log.println(&format!(
                "OK: {rows_checked} row(s) verified in {backend_label}"
            ));
        }
        VerifyOutcome::Broken {
            rows_checked,
            first_broken_seq,
            first_broken_transaction_id,
            expected,
            actual,
        } => {
            log.println(&format!(
                "BROKEN: chain intact for first {rows_checked} row(s); \
                 row seq={first_broken_seq} (transaction {first_broken_transaction_id}) \
                 does not chain.\n  expected: {expected}\n  actual:   {actual}"
            ));
        }
        VerifyOutcome::CannotVerify { reason } => {
            log.println(&format!("CANNOT VERIFY: {reason}"));
        }
    }

    // Both caveats sit directly under the chain verdict, because that verdict is
    // what an operator reads as "the audit log is fine". Which machine was read
    // comes first: an Intact verdict for the wrong host misleads more than an
    // unanchored one does.
    if let Some(census) = census {
        // Keyed off the transaction chain's own verdict, never off the aggregate
        // status: that one is the worst of three checks, so a broken *approval
        // event* chain would otherwise mark a fully verified attribution trail as
        // unproven.
        let standing = match &verification.chain {
            VerifyOutcome::Intact { .. } => CountStanding::Proven,
            VerifyOutcome::Broken { .. } => CountStanding::BreakDetected,
            VerifyOutcome::CannotVerify { .. } => CountStanding::NotChecked,
        };
        emit_attribution(log, &census, standing);
    }
    if let Some(caveat) = resolve_daemon_socket_caveat() {
        log.println(&caveat);
    }
    match anchor {
        Some(outcome) => log.println(&anchor_line(outcome)),
        None => {
            log.println(anchor_caveat());
        }
    }

    match &verification.events {
        VerifyOutcome::Intact { rows_checked } => {
            log.println(&format!("OK: {rows_checked} approval event(s) verified"));
        }
        VerifyOutcome::Broken {
            rows_checked,
            first_broken_seq,
            first_broken_transaction_id,
            ..
        } => {
            log.println(&format!(
                "BROKEN: approval events intact for first {rows_checked}; \
                 event seq={first_broken_seq} (transaction {first_broken_transaction_id}) \
                 does not chain"
            ));
        }
        VerifyOutcome::CannotVerify { reason } => {
            log.println(&format!("CANNOT VERIFY approval events: {reason}"));
        }
    }

    match &verification.binding {
        BindingOutcome::Consistent { bindings_checked } => {
            log.println(&format!(
                "OK: {bindings_checked} row(s) still match the approval event they committed to"
            ));
        }
        BindingOutcome::NotChecked => {
            log.println("CANNOT VERIFY binding: transaction or approval-event rows were not read");
        }
        BindingOutcome::MissingEvent {
            transaction_seq,
            event_tip,
        } => {
            log.println(&format!(
                "BROKEN: transaction seq={transaction_seq} committed to approval event \
                 {event_tip}, which is no longer in the event chain — approval events \
                 were deleted from the end of the chain"
            ));
        }
    }
}

/// Combine the local audit checks with the external anchor using the same
/// precedence as [`AuditVerification::exit_code`]. A detected break is stronger
/// evidence than a different check being inconclusive, so exit code `1` must
/// outrank `2` rather than relying on numeric ordering.
fn combined_verification_exit_code(
    verification: &AuditVerification,
    anchor: Option<&CheckpointOutcome>,
) -> i32 {
    let codes = [
        verification.exit_code(),
        anchor
            .map(sysknife_daemon::audit_chain::checkpoint_outcome_to_exit_code)
            .unwrap_or(0),
    ];
    if codes.contains(&1) {
        1
    } else if codes.contains(&2) {
        2
    } else {
        0
    }
}

fn status_word(exit_code: i32) -> &'static str {
    match exit_code {
        0 => "intact",
        1 => "broken",
        _ => "cannot_verify",
    }
}

fn outcome_json(outcome: &sysknife_daemon::audit_chain::VerifyOutcome) -> serde_json::Value {
    use sysknife_daemon::audit_chain::VerifyOutcome;
    match outcome {
        VerifyOutcome::Intact { rows_checked } => json!({
            "status": "intact",
            "rows_checked": rows_checked,
        }),
        VerifyOutcome::Broken {
            rows_checked,
            first_broken_seq,
            first_broken_transaction_id,
            expected,
            actual,
        } => json!({
            "status": "broken",
            "rows_checked": rows_checked,
            "first_broken_seq": first_broken_seq,
            "first_broken_transaction_id": first_broken_transaction_id,
            "expected": expected,
            "actual": actual,
        }),
        VerifyOutcome::CannotVerify { reason } => json!({
            "status": "cannot_verify",
            "reason": reason,
        }),
    }
}

fn binding_json(outcome: &sysknife_daemon::audit_chain::BindingOutcome) -> serde_json::Value {
    use sysknife_daemon::audit_chain::BindingOutcome;
    match outcome {
        BindingOutcome::Consistent { bindings_checked } => json!({
            "status": "consistent",
            "bindings_checked": bindings_checked,
        }),
        BindingOutcome::NotChecked => json!({
            "status": "not_checked",
        }),
        BindingOutcome::MissingEvent {
            transaction_seq,
            event_tip,
        } => json!({
            "status": "missing_event",
            "transaction_seq": transaction_seq,
            "event_tip": event_tip,
        }),
    }
}

// ---------------------------------------------------------------------------
// run_intent
// ---------------------------------------------------------------------------

/// What `run_intent` does with one [`ApprovalDecision`].
///
/// Extracted from the two gates in `run_intent` (plan-level and, under
/// `--step-by-step`, per step). They were near-identical `match` blocks over
/// the same enum, so the two could disagree about what a decision means — and
/// neither was reachable in a test without an LLM provider and a live daemon.
#[derive(Debug)]
enum GateAction {
    /// Execute without asking.
    Proceed,
    /// Ask the operator; a "no" is a rejection.
    AskOperator,
    /// Do not execute, and do not ask.
    Refuse(CliError),
}

/// Map an approval decision onto the gate's behaviour.
///
/// `highest` is the risk being gated: the plan's highest for the plan-level
/// gate, the step's own under `--step-by-step`.
fn gate_action(decision: ApprovalDecision, highest: &PlanRiskLevel) -> GateAction {
    match decision {
        ApprovalDecision::AutoApproved => GateAction::Proceed,
        ApprovalDecision::RequiresPrompt => GateAction::AskOperator,
        ApprovalDecision::RequiresInteraction => GateAction::Refuse(CliError::NonInteractive),
        ApprovalDecision::ExceedsCeiling(ceiling) => {
            GateAction::Refuse(CliError::RiskCeilingExceeded {
                highest: highest.clone(),
                ceiling,
            })
        }
    }
}

/// Plan and (optionally) execute a single natural-language intent.
pub async fn run_intent(intent: String, opts: &RunOpts, log: &Logger) -> Result<(), CliError> {
    let config = BrainConfig::from_env().map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;

    // Detect the running distro once at intent startup.
    // Failure is non-fatal: routing checks are skipped when detection fails
    // (the daemon will produce its own error at execution time).
    let distro = sysknife_core::distro::detect().ok();

    // Captured before `config` is moved into the planner below.
    let provider_label = config.provider_name().to_string();
    let model_label = config.model_name().to_string();

    // Nothing used to say a provider had been picked by elimination, so a
    // keyless first run failed against a port the user had never heard of.
    if let Some(notice) = config.provider_guess_notice() {
        eprintln!("! {notice}");
    }

    let plan_client = DaemonClient::new(opts.socket.clone());

    // Layer 3: planning event channel — planner emits PlanEvent as it works;
    // the CLI subscribes and updates the spinner message in real time.
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<PlanEvent>();

    let mut planner = LlmPlanner::from_config(config, Box::new(plan_client))
        .map_err(CliError::ConfigOrDaemon)?
        .with_prefs_path(sysknife_core::config::prefs_path())
        .with_progress(progress_tx);
    if let Some(ref d) = distro {
        planner = planner.with_distro(distro_id_to_hint(d));
    }

    // Layer 1: spinner — auto-hidden by indicatif when stderr is not a TTY.
    // Same redaction as the notice below: the spinner is transient on a TTY, but
    // it is the same string and there is no reason to hold the two to different
    // standards.
    let spinner = (!opts.json).then(|| {
        crate::render::make_spinner(format!(
            "Planning \"{}\"…",
            sysknife_brain::prefs::loggable_intent(&intent)
        ))
    });

    // …and because it is hidden there, a piped or ssh'd run would otherwise
    // print nothing at all while the provider thinks. Say it once instead.
    if !io::stderr().is_terminal() {
        crate::render::print_planning_notice(&provider_label, &model_label, &intent);
    }

    // Spawn event updater: receives PlanEvent and updates the spinner message.
    // The task exits naturally when the channel closes (i.e. when the planner
    // is dropped after plan_intent returns).
    let spinner_for_task = spinner.clone();
    let event_task = tokio::spawn(async move {
        while let Some(event) = progress_rx.recv().await {
            if let Some(ref pb) = spinner_for_task {
                match event {
                    PlanEvent::Thinking => pb.set_message("Thinking…"),
                    PlanEvent::QueryingTool(ref name) => {
                        pb.set_message(format!("Querying {name}…"))
                    }
                    PlanEvent::ProposingPlan => pb.set_message("Proposing plan…"),
                }
            }
        }
    });

    // `plan_intent` may call `StateClient::curated_state()` (a blocking sync
    // Unix socket call) on the current async thread.  This is tolerable on
    // the multi-threaded runtime: the call is bounded by SOCKET_TIMEOUT (10 s)
    // and ties up one worker thread for at most that duration.
    let plan_result = planner.plan_intent(&intent).await;

    // Drop the planner to close the UnboundedSender, which closes the channel
    // and allows event_task to drain and exit.
    drop(planner);
    if let Err(e) = event_task.await {
        eprintln!("sysknife: event task panicked: {e}");
    }

    finish_spinner(&spinner);

    let plan = plan_result.map_err(|e| match e {
        // Not a failure: the planner understood the request and the answer is
        // no. Carried as its own variant so the CLI renders a reason instead of
        // "planning failed", and so scripts do not read it as a fault (#179).
        sysknife_brain::planner::PlanningError::Refused { reason, suggestion } => {
            CliError::Refused { reason, suggestion }
        }
        other => CliError::PlanningFailed(other.to_string()),
    })?;

    // Before anything is displayed or approved: refuse a plan the daemon could
    // not run as written. A parameter the executor rejects is a planning
    // failure, not an execution failure, and the operator should never be asked
    // to approve one.
    reject_unrunnable_params(&plan)?;

    // ---- distro routing guard ---------------------------------------------
    // Validate every step's action against the detected distro. This sits beside
    // the parameter check, and before the plan is displayed, for the same reason:
    // it ran after approval, so on a Fedora host `sysknife run "show the firewall
    // rules"` printed the plan, asked for confirmation, waited for "yes", and only
    // then refused. A dry run still displays such a plan on purpose — inspecting
    // what the planner produced is the point of it.
    if !opts.dry_run {
        for step in plan.steps() {
            if let Err(msg) =
                crate::distro_routing::check_action_distro(step.action_name(), distro.as_ref())
            {
                return Err(CliError::ConfigOrDaemon(msg));
            }
        }
    }

    // Surface any step where the planner's proposed risk disagreed with the
    // authoritative ActionSpec risk. A mismatch is a useful signal in its own
    // right — the model may be confused about this action (and could have gotten
    // its params wrong too), which the operator is well-placed to notice before
    // approving. Emitted to stderr so it never pollutes `--json` stdout.
    for step in plan.steps() {
        let authoritative = authoritative_plan_risk(step.action_name());
        if *step.proposed_risk_level() != authoritative {
            log.print_stderr(&format!(
                "sysknife: {} — planner rated {} risk; using {} (ActionSpec-derived)",
                step.action_name(),
                step.proposed_risk_level().as_str(),
                authoritative.as_str(),
            ));
        }
    }

    // Substitute the daemon's ActionSpec-derived risk (the single source of
    // truth) for the planner's proposed per-step risk, so the plan the operator
    // sees below and the auto-approval gate both reflect authoritative risk.
    // Without this, a planner that under-rates an action could let
    // `--yes --max-risk medium` auto-approve a step that is actually High risk.
    // This uses the CLI's *own* linked catalogue; the execution loop below
    // re-validates each step against the live daemon preview so a CLI/daemon
    // version skew can never execute above the approved risk.
    //
    // From here on `plan` is an `AuthorizedPlan`: its steps expose the
    // authoritative `risk_level()`, so every gate below is structurally
    // prevented from reading the LLM's proposed risk.
    let plan = plan.into_authorized(authoritative_plan_risk);

    // ---- print plan --------------------------------------------------------

    if opts.json {
        let steps: Vec<Value> = plan
            .steps()
            .map(|s| {
                json!({
                    "action": s.action_name(),
                    "summary": s.summary(),
                    "risk": s.risk_level().as_str(),
                    "params": s.params(),
                })
            })
            .collect();
        log.println(
            &serde_json::to_string(&json!({
                "plan": { "intent": plan.intent(), "summary": plan.summary(), "steps": steps }
            }))
            .expect("static JSON"),
        );
    } else {
        crate::render::print_plan(&plan, log);
    }

    if opts.dry_run {
        if opts.step_by_step {
            log.print_stderr("warning: --step-by-step has no effect with --dry-run");
        }
        return Ok(());
    }

    // ---- plan-level approval (non-step-by-step) ----------------------------

    let policy = opts.approval_policy();

    if !opts.step_by_step {
        let highest = plan.highest_risk().expect("plan has steps").clone();
        match gate_action(policy.decide_plan(&plan), &highest) {
            GateAction::Proceed => {}
            GateAction::Refuse(err) => return Err(err),
            GateAction::AskOperator => {
                let n = plan.steps().len();
                let msg = if opts.json {
                    "Execute this plan?".to_owned()
                } else {
                    format!(
                        "  {} step{}, {} risk — execute?",
                        n,
                        if n == 1 { "" } else { "s" },
                        crate::render::risk_colored(&highest),
                    )
                };
                if !prompt_confirm(&msg).await {
                    return Err(CliError::Rejected);
                }
            }
        }
    }

    // ---- execute steps -----------------------------------------------------

    let exec_client = DaemonClient::new(opts.socket.clone());
    let start = std::time::Instant::now();

    for step in plan.steps() {
        // Preview BEFORE asking. The plan printed above carries planner
        // summaries and risk only; the daemon's preview is what says which
        // package version arrives, which file changes, whether a reboot follows
        // and whether a rollback exists. Asking first and previewing afterwards
        // meant the preview was never a decision point — consent had already
        // been given and execution followed immediately.
        let prepared = exec_client
            .preview_declaring(step.action_name(), step.params(), opts.skip_approval)
            .await?;
        let preview = &prepared.preview;

        // The declaration is only worth making if it was recorded. A daemon
        // older than this field accepts the preview and drops it, which would
        // leave an unattended run indistinguishable from an approved one in
        // the signed chain. Refuse rather than execute unrecorded.
        if opts.skip_approval && !unattended_marker_present(&preview.warnings) {
            return Err(CliError::ConfigOrDaemon(format!(
                "{}: this run has the approval gate lifted, but the daemon did not record it in \
                 the preview warnings, so the audit row would not show that no human approved. \
                 The daemon is older than this CLI. Upgrade it, or drop \
                 --dangerously-skip-approval.",
                step.action_name(),
            )));
        }

        // Fail closed on CLI/daemon risk skew: the plan-level decision used the
        // CLI's own linked catalogue. If the live daemon rates this step higher
        // than we approved it at, refuse to mint a receipt rather than execute
        // above the approved risk (see `daemon_risk_within_approved`).
        let daemon_risk = plan_risk_of(preview.risk_level);
        if !daemon_risk_within_approved(step.risk_level(), &daemon_risk) {
            return Err(CliError::ConfigOrDaemon(format!(
                "{}: the running daemon rates this {} risk, above the {} the CLI approved — \
                 the CLI and daemon builds may differ. Aborting without executing; upgrade the \
                 CLI (or re-run with a matching --max-risk) so risk gating agrees.",
                step.action_name(),
                daemon_risk.as_str(),
                step.risk_level().as_str(),
            )));
        }

        if opts.json {
            log.println(&serde_json::to_string(preview).expect("PreviewEnvelope is Serialize"));
        } else {
            crate::render::print_step_header(step.action_name(), preview);
        }

        // Now that the authoritative preview is on screen, take the approval
        // decision for this step. `--step-by-step` asks about every step;
        // otherwise the plan-level prompt already covered scope and only HIGH
        // risk is re-confirmed here (see `post_preview_confirmation_required`).
        if post_preview_confirmation_required(opts.step_by_step, step.risk_level()) {
            match gate_action(policy.decide_step(step.risk_level()), step.risk_level()) {
                GateAction::Proceed => {}
                GateAction::Refuse(err) => return Err(err),
                GateAction::AskOperator => {
                    let msg = if opts.json {
                        // The summary is model-written and this string IS the
                        // approval question; it must not be able to redraw it.
                        format!(
                            "Execute {} ({})?",
                            step.action_name(),
                            crate::operator_text::operator_safe(step.summary())
                        )
                    } else {
                        format!(
                            "Apply {} ({} risk) as previewed above?",
                            step.action_name(),
                            crate::render::risk_colored(step.risk_level()),
                        )
                    };
                    if !prompt_confirm(&msg).await {
                        return Err(CliError::Rejected);
                    }
                }
            }
        }

        // Spinner clears on the first output line so execution output
        // streams naturally without a spinner in the way.
        let exec_spinner: Option<indicatif::ProgressBar> = (!opts.json)
            .then(|| crate::render::make_spinner(format!("Executing {}…", step.action_name())));
        let exec_spinner_ref = exec_spinner.clone();
        let mut first_line = true;

        let approval_receipt = exec_client.approve(&prepared.transaction_id).await?;
        let exec_result = exec_client
            .execute(
                &prepared.transaction_id,
                step.action_name(),
                step.params(),
                &approval_receipt,
                |line| {
                    if first_line {
                        finish_spinner(&exec_spinner_ref);
                        first_line = false;
                    }
                    if opts.json {
                        log.println(line);
                    } else {
                        crate::render::print_output_line(line, log);
                    }
                },
            )
            .await;

        // Always clear the exec spinner regardless of success or error.
        // finish_spinner() is idempotent, so this is safe even if the callback
        // already fired. If execute() errored before the first output line,
        // this prevents the spinner artifact from being left on the terminal.
        finish_spinner(&exec_spinner);

        exec_result.map(|result| {
            if opts.json {
                log.println(&serde_json::to_string(&result).expect("ResultEnvelope is Serialize"));
            } else {
                crate::render::print_step_done(&result, log);
            }
        })?;
    }

    if !opts.json {
        crate::render::print_success(start.elapsed().as_secs_f32(), log);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// run_repl
// ---------------------------------------------------------------------------

/// Interactive REPL — reads intents with rustyline (arrow-key history,
/// Ctrl+R reverse search, Ctrl+C to cancel input, Ctrl+D to exit).
///
/// History persists across sessions in `~/.local/share/sysknife/history`.
///
/// `tokio::task::block_in_place` parks the current worker thread during each
/// blocking `readline()` call so other tasks on the multi-thread runtime can
/// run freely.  rustyline does not need to be `Send` with this approach.
pub async fn run_repl(opts: &RunOpts, log: &Logger) -> Result<(), CliError> {
    use rustyline::{error::ReadlineError, DefaultEditor};

    let history_path =
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/sysknife/history"));

    let mut rl = DefaultEditor::new()
        .map_err(|e| CliError::ExecutionFailed(format!("readline init: {e}")))?;

    if let Some(ref p) = history_path {
        // Ensure the parent directory exists before the first load/save.
        if let Some(parent) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "sysknife: failed to create history directory {}: {e}",
                    parent.display()
                );
            }
        }
        // Absence of the history file is not an error; any other failure is.
        match rl.load_history(p) {
            Ok(()) => {}
            Err(rustyline::error::ReadlineError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("sysknife: failed to load history from {}: {e}", p.display());
            }
        }
    }

    loop {
        // Block the worker thread only during the blocking readline call.
        // Other tokio threads continue executing tasks unaffected.
        let readline_result = tokio::task::block_in_place(|| rl.readline("sysknife> "));

        match readline_result {
            Ok(line) => {
                let intent = line.trim().to_string();
                // Ignore the result: duplicates are silently skipped by rustyline.
                let _ = rl.add_history_entry(line.as_str());
                if intent.is_empty() {
                    continue;
                }
                if matches!(intent.as_str(), "exit" | "quit") {
                    break;
                }
                if let Err(e) = run_intent(intent, opts, log).await {
                    log.print_stderr(&format!("error: {e}"));
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => {
                log.print_stderr(&format!("readline error: {e}"));
                break;
            }
        }
    }

    if let Some(ref p) = history_path {
        if let Err(e) = rl.save_history(p) {
            eprintln!("sysknife: failed to save history to {}: {e}", p.display());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Clear `spinner` if one is present. A no-op when `spinner` is `None` (e.g.
/// `--json` mode, where no spinner was ever created) or already finished.
fn finish_spinner(spinner: &Option<indicatif::ProgressBar>) {
    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }
}

/// Check that `path` exists; if not, print `"{what} not found at <path>"` to
/// stderr and fail with exit code 2 (used by `run_audit_checkpoint`, which
/// checks both the audit key file and the audit database file this way).
fn require_exists(path: &std::path::Path, what: &str) -> Result<(), CliError> {
    if path.exists() {
        Ok(())
    } else {
        eprintln!("{what} not found at {}", path.display());
        Err(CliError::Exit(2))
    }
}

/// Ask the user a yes/no question on stderr; return `true` iff they answer "y"
/// or "yes" (case-insensitive).
///
/// Uses `tokio::io::stdin` to keep the async executor free while waiting for
/// input.  On EOF or an I/O error a warning is printed to stderr and the
/// function returns `false` (safe default: do not execute).
async fn prompt_confirm(msg: &str) -> bool {
    use tokio::io::AsyncBufReadExt as _;

    eprint!("{msg} [y/N] ");
    let _ = io::stderr().flush();

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut buf = String::new();

    match reader.read_line(&mut buf).await {
        Ok(0) => {
            eprintln!("\nsysknife: stdin closed (EOF) — treating as 'no'");
            false
        }
        Err(e) => {
            eprintln!("\nsysknife: stdin read error ({e}) — treating as 'no'");
            false
        }
        Ok(_) => matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
    }
}

async fn prompt_exact(msg: &str, expected: &str) -> bool {
    use tokio::io::AsyncBufReadExt as _;

    eprint!("{msg} ({expected}): ");
    let _ = io::stderr().flush();
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut buf = String::new();
    match reader.read_line(&mut buf).await {
        Ok(0) | Err(_) => false,
        Ok(_) => buf.trim() == expected,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // What the verifier says about attribution
    // -----------------------------------------------------------------------

    /// Render `audit verify` output into a string by teeing the logger to a file.
    /// The alternative, capturing stdout, is not reliable under a parallel test
    /// runner because the handle is process-wide.
    ///
    /// The verdict is a parameter, not a constant. Hardcoding `Intact` here is
    /// what let two releases' worth of notes claim rows were "authentic and
    /// verified" under a `BROKEN` verdict: every test ran in the one state where
    /// the claim happened to be true.
    fn rendered(
        chain: sysknife_daemon::audit_chain::VerifyOutcome,
        attribution: Option<sysknife_daemon::audit_chain::AttributionCensus>,
        json: bool,
    ) -> String {
        rendered_with_anchor(chain, attribution, json, None)
    }

    fn rendered_with_anchor(
        chain: sysknife_daemon::audit_chain::VerifyOutcome,
        attribution: Option<sysknife_daemon::audit_chain::AttributionCensus>,
        json: bool,
        anchor: Option<&CheckpointOutcome>,
    ) -> String {
        use sysknife_daemon::audit_chain::{BindingOutcome, VerifyOutcome};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("verify.log");
        let log = Logger::new(Some(&path)).expect("logger");
        let verification = AuditVerification {
            chain,
            events: VerifyOutcome::Intact { rows_checked: 0 },
            binding: BindingOutcome::Consistent {
                bindings_checked: 0,
            },
            attribution,
        };
        emit_verification(
            &crate::cli::AuditVerifyArgs { json, pubkey: None },
            &log,
            &verification,
            "/tmp/test.db",
            anchor,
        );
        std::fs::read_to_string(&path).expect("logger wrote the rendered output")
    }

    /// Counts named `n` with counts `(named, attribution_failed, not_recorded,
    /// unattested)`, over an `Intact` chain of that many rows.
    fn intact_with(
        named: u64,
        attribution_failed: u64,
        not_recorded: u64,
        unattested: u64,
    ) -> String {
        use sysknife_daemon::audit_chain::{AttributionCensus, VerifyOutcome};
        let census = AttributionCensus::from_counts_for_tests(
            named,
            attribution_failed,
            not_recorded,
            unattested,
        );
        rendered(
            VerifyOutcome::Intact {
                rows_checked: census.rows(),
            },
            Some(census),
            false,
        )
    }

    /// The reason a row names nobody decides what an operator does next, so the
    /// two reasons cannot share one line. An attribution failure points at
    /// `SO_PEERCRED` on a live host; a row that predates the column is history and
    /// cannot be fixed, because backfilling it would rewrite signed bytes.
    ///
    /// Each count is asserted next to its own phrase. Asserting a bare `"2
    /// row(s)"` passed even with the format arguments swapped, because the other
    /// half of the same sentence also prints a count.
    #[test]
    fn each_reason_a_row_names_nobody_gets_its_own_note_with_its_own_count() {
        let text = intact_with(4, 3, 2, 0);

        assert!(
            text.contains("ATTRIBUTION: 4 of 9 row(s) name an account; 5 name nobody."),
            "the summary must give the operator the denominator, got: {text}"
        );
        assert!(
            text.contains("NOTE: 3 row(s) record that the daemon could not name the caller"),
            "the attribution-failure count must sit with its own phrase, got: {text}"
        );
        assert!(
            text.contains("SO_PEERCRED"),
            "and point at the live cause, got: {text}"
        );
        assert!(
            text.contains("NOTE: 2 row(s) carry no caller principal the signature covers"),
            "the pre-v3 count must sit with its own phrase, got: {text}"
        );
        assert!(
            text.contains("cannot be repaired"),
            "and say the gap is permanent, got: {text}"
        );
    }

    /// The `none:unattributed` note is rendered from the principal the daemon
    /// actually signs, never a literal, so the text cannot drift from the value it
    /// tells the operator to search for.
    #[test]
    fn the_attribution_failure_note_names_the_principal_the_daemon_signs() {
        let text = intact_with(0, 2, 0, 0);
        let principal = sysknife_daemon::auth::CallerPrincipal::Unattributed.as_signed_str();
        assert!(
            text.contains(&principal),
            "the note must quote `{principal}` so it can be grepped for, got: {text}"
        );
    }

    /// A clean, fully attributed chain must not print a note. A note on every run
    /// is a note operators learn to skip, which would waste the one signal that
    /// says the trail cannot name who acted.
    #[test]
    fn a_fully_attributed_chain_prints_no_attribution_note() {
        let text = intact_with(9, 0, 0, 0);

        assert!(
            text.contains("ATTRIBUTION: 9 of 9 row(s) name an account; 0 name nobody."),
            "the summary still prints, so the operator sees the denominator: {text}"
        );
        // Scoped to the attribution notes: the unconfigured-anchor caveat is a
        // different concern and prints here regardless.
        assert!(
            !text.contains("name the caller")
                && !text.contains("no caller principal")
                && !text.contains("no signature vouches for"),
            "nothing to warn about on a fully attributed chain, got: {text}"
        );
    }

    /// The defect this whole review pass turned up: the notes used to assert that
    /// rows were "authentic and verified" whatever the verdict said. Printed under
    /// `CANNOT VERIFY` that is a straight falsehood, and it is the sentence an
    /// operator would rely on.
    #[test]
    fn an_unverified_chain_never_calls_its_rows_verified() {
        use sysknife_daemon::audit_chain::{AttributionCensus, VerifyOutcome};
        let census = AttributionCensus::from_counts_for_tests(4, 1, 2, 0);

        for chain in [
            VerifyOutcome::CannotVerify {
                reason: "invalid public key hex".to_string(),
            },
            VerifyOutcome::Broken {
                rows_checked: 1,
                first_broken_seq: 2,
                first_broken_transaction_id: "tx2".to_string(),
                expected: "x".to_string(),
                actual: "y".to_string(),
            },
        ] {
            let text = rendered(chain.clone(), Some(census), false);
            assert!(
                !text.contains("authentic and verified"),
                "nothing was verified, so the notes must not say so, got: {text}"
            );
            assert!(
                text.contains("did not verify to the end"),
                "and they must say what the rows actually are, got: {text}"
            );
            assert!(
                text.contains("not what was proven"),
                "the counts must be marked as claims, got: {text}"
            );
        }
    }

    /// An `Intact` verdict is the only state in which the counts are findings
    /// rather than claims, so it is the only state that may say so.
    #[test]
    fn an_intact_chain_calls_its_rows_verified() {
        let text = intact_with(0, 1, 1, 0);
        assert!(
            text.contains("authentic and verified"),
            "an intact chain's rows are verified and the note should say it: {text}"
        );
        assert!(
            !text.contains("not what was proven"),
            "and nothing here is a mere claim, got: {text}"
        );
    }

    /// A principal no signature covers is the one attribution finding that asks
    /// for an investigation, so it prints as a WARNING and explains the mechanism:
    /// on v1 and v2 rows that column is outside the signed message.
    #[test]
    fn an_unattested_principal_is_reported_as_something_to_investigate() {
        let text = intact_with(1, 0, 0, 2);

        assert!(
            text.contains(
                "WARNING: 2 row(s) have no caller principal that any signature vouches for"
            ),
            "an unsigned principal must be surfaced as a finding, got: {text}"
        );
        assert!(
            text.contains("out of band"),
            "and name the mechanism, got: {text}"
        );
        assert!(
            text.contains("ATTRIBUTION: 1 of 3 row(s) name an account"),
            "while the summary counts them among the rows naming nobody, got: {text}"
        );
    }

    /// Nothing read means nothing known. Rendering a census of zero rows would put
    /// "0 of 0 row(s) name an account" under a `CANNOT VERIFY` verdict, which
    /// reads as a fact about the database.
    #[test]
    fn a_verification_that_read_nothing_says_nothing_about_attribution() {
        use sysknife_daemon::audit_chain::VerifyOutcome;
        let text = rendered(
            VerifyOutcome::CannotVerify {
                reason: "audit database not found".to_string(),
            },
            None,
            false,
        );
        assert!(
            !text.contains("ATTRIBUTION:"),
            "no census was taken, so no attribution line may be printed: {text}"
        );
    }

    /// The JSON report carries every count under a stable key, because the whole
    /// point of splitting them is that a machine reader can tell them apart.
    /// Distinct values throughout, so any permutation of the keys fails.
    #[test]
    fn the_json_report_carries_every_attribution_count() {
        use sysknife_daemon::audit_chain::{AttributionCensus, VerifyOutcome};
        let census = AttributionCensus::from_counts_for_tests(6, 1, 2, 3);
        let text = rendered(
            VerifyOutcome::Intact { rows_checked: 12 },
            Some(census),
            true,
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("--json must emit one JSON document");
        assert_eq!(parsed["attributed_rows"], 6);
        assert_eq!(parsed["unattributed_rows"], 1);
        assert_eq!(parsed["rows_without_principal"], 2);
        assert_eq!(parsed["rows_unattested"], 3);
        assert_eq!(parsed["rows_naming_no_account"], 6);
        assert_eq!(parsed["rows_censused"], 12);
    }

    /// `null`, not `0`, when no census was taken. An agent that alerts on a low
    /// attribution ratio must not read an unreadable database as a database where
    /// nothing was found: that is the same confusion as the counter this release
    /// replaced, one level up.
    #[test]
    fn the_json_report_marks_an_unreadable_binding_not_checked() {
        use sysknife_daemon::audit_chain::BindingOutcome;
        let verification = cannot_verify_all("audit database not found".to_string());

        assert_eq!(verification.binding, BindingOutcome::NotChecked);
        assert_eq!(verification.exit_code(), 2);
        assert_eq!(binding_json(&verification.binding)["status"], "not_checked");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("verify.log");
        let log = Logger::new(Some(&path)).expect("logger");
        emit_verification(
            &crate::cli::AuditVerifyArgs {
                json: true,
                pubkey: None,
            },
            &log,
            &verification,
            "/tmp/test.db",
            None,
        );
        let text = std::fs::read_to_string(&path).expect("logger wrote the rendered output");

        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("--json must emit one JSON document");
        assert_eq!(parsed["binding"]["status"], "not_checked");
        for key in [
            "attributed_rows",
            "unattributed_rows",
            "rows_without_principal",
            "rows_unattested",
            "rows_naming_no_account",
            "rows_censused",
        ] {
            assert!(
                parsed[key].is_null(),
                "{key} must be null when no rows were read, got: {}",
                parsed[key]
            );
        }
    }

    // -----------------------------------------------------------------------
    // Which machine's chain was verified
    // -----------------------------------------------------------------------

    /// The control plane and the verifier read different things: `plan`,
    /// `execute`, `history` and `doctor` all travel to `SYSKNIFE_SOCKET`, while
    /// verification opens a store on the local filesystem. In the SSH-tunnel
    /// and vsock topologies the docs recommend, those are two different
    /// machines, and a laptop that ever ran a user-mode daemon has a local
    /// chain that verifies happily. "Intact" for the wrong host is the one
    /// failure this command must never produce silently.
    #[test]
    fn a_forwarded_socket_makes_the_verifier_name_the_machine_it_read() {
        let caveat = remote_daemon_caveat(
            Some(("/tmp/sysknife-web01.sock", "SYSKNIFE_SOCKET")),
            &SocketTarget::Unix("/tmp/sysknife-web01.sock".into()),
        )
        .expect("an explicitly configured socket must produce a caveat");

        assert!(
            caveat.contains("/tmp/sysknife-web01.sock"),
            "the caveat must name the daemon socket in play, got: {caveat}"
        );
        assert!(
            caveat.to_lowercase().contains("this machine"),
            "and say the store just read is local, got: {caveat}"
        );
    }

    /// vsock is unambiguous: the daemon is in another kernel, so the chain
    /// cannot be on this filesystem. The wording should not hedge.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_vsock_daemon_caveat_says_the_chain_lives_in_the_vm() {
        let caveat = remote_daemon_caveat(
            Some(("vsock://3:9734", "SYSKNIFE_SOCKET")),
            &SocketTarget::Vsock { cid: 3, port: 9734 },
        )
        .expect("a vsock target is always another host");

        let lower = caveat.to_lowercase();
        assert!(
            lower.contains("vm") || lower.contains("another host"),
            "name where the chain actually is, got: {caveat}"
        );
        assert!(
            caveat.contains("--pubkey"),
            "and point at the auditor path that works across machines, got: {caveat}"
        );
    }

    /// `audit verify` must actually PRINT the wrong-machine caveat, not merely
    /// compute it. Deleting the caveat line from `emit_verification` otherwise
    /// passes the whole suite while defeating the security claim the caveat
    /// exists for. This drives the real render path and asserts the caveat
    /// reaches both the human output and the `--json` field.
    #[test]
    fn audit_verify_prints_the_wrong_machine_caveat() {
        use sysknife_daemon::audit_chain::VerifyOutcome;
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SYSKNIFE_SOCKET", "unix:///tmp/sysknife-web01.sock");

        let human = rendered(VerifyOutcome::Intact { rows_checked: 3 }, None, false);
        let json = rendered(VerifyOutcome::Intact { rows_checked: 3 }, None, true);

        std::env::remove_var("SYSKNIFE_SOCKET");

        assert!(
            human.contains("/tmp/sysknife-web01.sock") && human.contains("forwarded"),
            "the human output must carry the caveat, got: {human}"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("--json emits one document");
        let caveat = parsed["daemon_socket_caveat"]
            .as_str()
            .expect("daemon_socket_caveat must be present and a string");
        assert!(
            caveat.contains("/tmp/sysknife-web01.sock"),
            "the JSON caveat must name the socket, got: {caveat}"
        );
    }

    /// A vsock target configured through `config.toml` reaches the client as
    /// `SYSKNIFE_LISTEN_URI`. vsock is unambiguously another kernel, so the
    /// wrong-machine caveat must fire and name the variable actually in play.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_vsock_set_via_listen_uri_still_warns() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SYSKNIFE_SOCKET");
        std::env::set_var("SYSKNIFE_LISTEN_URI", "vsock://3:9734");

        let caveat = remote_daemon_caveat_from_env();

        std::env::remove_var("SYSKNIFE_LISTEN_URI");

        let caveat = caveat.expect("a vsock target is always another host");
        assert!(
            caveat.contains("SYSKNIFE_LISTEN_URI"),
            "must name the variable that configured it, not SYSKNIFE_SOCKET, got: {caveat}"
        );
    }

    /// The packaged daemon unit and a local `config.toml` both set
    /// `SYSKNIFE_LISTEN_URI` to the machine's own unix socket. Warning there would
    /// print the wrong-machine caveat on every local `audit verify`, the
    /// "caveat nobody reads" failure. A unix value in `SYSKNIFE_LISTEN_URI` must
    /// stay quiet; only `SYSKNIFE_SOCKET` (an explicit override) or vsock warns.
    #[test]
    fn a_local_unix_socket_from_listen_uri_stays_quiet() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("SYSKNIFE_SOCKET");
        std::env::set_var("SYSKNIFE_LISTEN_URI", "unix:///run/sysknife/daemon.sock");

        let caveat = remote_daemon_caveat_from_env();

        std::env::remove_var("SYSKNIFE_LISTEN_URI");
        assert!(
            caveat.is_none(),
            "a local unix socket from config must not warn on every verify, got: {caveat:?}"
        );
    }

    /// Precedence must match `resolve_socket_target`: `SYSKNIFE_SOCKET` is the
    /// socket the client dials when both are set, so the caveat must name it.
    /// Swapping the order would point the wrong-machine warning at a socket the
    /// client never used.
    #[test]
    fn socket_env_takes_precedence_over_listen_uri_in_the_caveat() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("SYSKNIFE_SOCKET", "unix:///tmp/sysknife-dialed.sock");
        std::env::set_var("SYSKNIFE_LISTEN_URI", "unix:///tmp/sysknife-other.sock");

        let caveat = remote_daemon_caveat_from_env();

        std::env::remove_var("SYSKNIFE_SOCKET");
        std::env::remove_var("SYSKNIFE_LISTEN_URI");

        let caveat = caveat.expect("an explicit SYSKNIFE_SOCKET override warns");
        assert!(
            caveat.contains("/tmp/sysknife-dialed.sock") && caveat.contains("SYSKNIFE_SOCKET"),
            "the caveat must name the socket the client actually dialed, got: {caveat}"
        );
        assert!(
            !caveat.contains("sysknife-other.sock"),
            "and must not name the socket it did not dial, got: {caveat}"
        );
    }

    fn unix_target() -> SocketTarget {
        SocketTarget::Unix("/run/sysknife/daemon.sock".into())
    }

    #[test]
    fn socket_origin_is_unknown_when_hashes_match_because_clones_share_machine_id() {
        // A hash match is NOT proof of "this machine": cloned VM/container images
        // routinely share one /etc/machine-id, so equal hashes can be two distinct
        // clones. A match must therefore fall through to the heuristic (Unknown),
        // never suppress a warning it would otherwise raise (#146 review).
        assert_eq!(
            socket_origin_from(
                Some("same-hash"),
                Some("same-hash"),
                "unix:///run/sysknife/daemon.sock",
                "SYSKNIFE_LISTEN_URI",
                &unix_target(),
            ),
            SocketOrigin::Unknown
        );
    }

    #[test]
    fn socket_origin_is_remote_when_a_forwarded_unix_socket_is_another_machine() {
        // The exact gap #146 closes: a unix socket via SYSKNIFE_LISTEN_URI whose
        // daemon reports a DIFFERENT machine-id (the reliable direction) must warn.
        match socket_origin_from(
            Some("local-hash"),
            Some("remote-hash"),
            "unix:///run/sysknife/daemon.sock",
            "SYSKNIFE_LISTEN_URI",
            &unix_target(),
        ) {
            SocketOrigin::Remote(caveat) => {
                assert!(caveat.contains("SYSKNIFE_LISTEN_URI"), "{caveat}");
                assert!(caveat.contains("forwarded"), "{caveat}");
            }
            other => panic!("a forwarded unix socket on another machine must warn, got {other:?}"),
        }
    }

    #[test]
    fn socket_origin_is_unknown_when_the_daemon_or_local_id_is_missing() {
        // Daemon unreachable / older daemon without the field -> fall back.
        assert_eq!(
            socket_origin_from(
                Some("local"),
                None,
                "unix:///x",
                "SYSKNIFE_LISTEN_URI",
                &unix_target()
            ),
            SocketOrigin::Unknown
        );
        // Local /etc/machine-id unreadable -> cannot decide -> fall back.
        assert_eq!(
            socket_origin_from(
                None,
                Some("daemon"),
                "unix:///x",
                "SYSKNIFE_LISTEN_URI",
                &unix_target()
            ),
            SocketOrigin::Unknown
        );
    }

    /// A one-shot mock daemon on a unix socket that answers `query_state` with a
    /// `state_response` reporting the given machine-id hash, so the whole
    /// query → compare → verdict chain can be driven end-to-end.
    fn spawn_mock_daemon(
        sock: std::path::PathBuf,
        reported_hash: &str,
    ) -> std::thread::JoinHandle<()> {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let listener = UnixListener::bind(&sock).expect("bind mock daemon");
        let reported = reported_hash.to_string();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut lenb = [0u8; 4];
                if stream.read_exact(&mut lenb).is_err() {
                    return;
                }
                let len = u32::from_le_bytes(lenb) as usize;
                let mut body = vec![0u8; len];
                let _ = stream.read_exact(&mut body);
                let resp = serde_json::json!({
                    "type": "state_response",
                    "request_id": "cli-machine-id",
                    "state": {
                        "host_name": "other", "deployment": "", "services": [], "flatpaks": [],
                        "toolboxes": [], "layered_packages": [], "containers": [], "users": [],
                        "machine_id_hash": reported
                    }
                });
                let bytes = serde_json::to_vec(&resp).unwrap();
                let _ = stream.write_all(&(bytes.len() as u32).to_le_bytes());
                let _ = stream.write_all(&bytes);
            }
        })
    }

    // A hash that cannot equal this host's real /etc/machine-id hash.
    const NOT_THIS_HOST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn daemon_socket_origin_warns_end_to_end_when_the_forwarded_daemon_is_another_machine() {
        let _g = ENV_LOCK.lock().unwrap();
        // The local side reads the real /etc/machine-id; skip where it is absent.
        if sysknife_daemon::state_collector::machine_id_hash().is_none() {
            return;
        }
        let sock = std::env::temp_dir().join(format!("sk146-wire-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let server = spawn_mock_daemon(sock.clone(), NOT_THIS_HOST);
        std::env::remove_var("SYSKNIFE_SOCKET");
        std::env::set_var("SYSKNIFE_LISTEN_URI", format!("unix://{}", sock.display()));
        let origin = daemon_socket_origin();
        std::env::remove_var("SYSKNIFE_LISTEN_URI");
        let _ = server.join();
        let _ = std::fs::remove_file(&sock);
        assert!(
            matches!(origin, SocketOrigin::Remote(_)),
            "a forwarded daemon reporting a different machine-id must warn, got {origin:?}"
        );
    }

    #[test]
    fn daemon_socket_origin_skips_the_query_for_an_explicit_socket_env() {
        let _g = ENV_LOCK.lock().unwrap();
        if sysknife_daemon::state_collector::machine_id_hash().is_none() {
            return;
        }
        // Same mismatching mock daemon, but reached via SYSKNIFE_SOCKET: the
        // heuristic already warns for that, so the query is skipped and the
        // verdict is Unknown (NOT Remote), proving no round-trip is attempted.
        let sock = std::env::temp_dir().join(format!("sk146-skip-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let server = spawn_mock_daemon(sock.clone(), NOT_THIS_HOST);
        std::env::set_var("SYSKNIFE_SOCKET", format!("unix://{}", sock.display()));
        std::env::remove_var("SYSKNIFE_LISTEN_URI");
        let origin = daemon_socket_origin();
        std::env::remove_var("SYSKNIFE_SOCKET");
        // The query was skipped, so nothing connected; unblock the mock's accept()
        // with a throwaway connection so its thread exits, then clean up.
        let _ = std::os::unix::net::UnixStream::connect(&sock);
        let _ = server.join();
        let _ = std::fs::remove_file(&sock);
        assert_eq!(
            origin,
            SocketOrigin::Unknown,
            "SYSKNIFE_SOCKET must skip the machine-id query and fall back to the heuristic"
        );
    }

    /// No env var means the daemon is this machine's own, which is the common
    /// case. Emitting the caveat there would train operators to ignore it.
    #[test]
    fn the_default_socket_produces_no_caveat() {
        assert!(
            remote_daemon_caveat(
                None,
                &SocketTarget::Unix("/run/sysknife/daemon.sock".into())
            )
            .is_none(),
            "an unset SYSKNIFE_SOCKET is the local daemon; stay quiet"
        );
    }

    // -----------------------------------------------------------------------
    // Audit-integrity caveat
    // -----------------------------------------------------------------------

    /// "OK: N rows verified" is true and incomplete. A chain whose newest rows
    /// were deleted still verifies: the remaining prefix chains correctly and
    /// the verifier starts from an empty predecessor. Only an independent
    /// checkpoint anchor makes that removal detectable, and the packaged unit
    /// configures none, so the default deployment must say so next to its
    /// verdict rather than let "OK" be read as "nothing was removed".
    #[test]
    fn a_verdict_without_an_anchor_carries_a_truncation_caveat() {
        let caveat = anchor_caveat();
        assert!(
            caveat.to_lowercase().contains("truncat"),
            "the caveat must name what is undetectable, got: {caveat}"
        );
        assert!(
            caveat.contains("SYSKNIFE_CHECKPOINT_DB"),
            "and how to fix it, got: {caveat}"
        );
    }

    /// A configured anchor used to suppress the caveat and report nothing else,
    /// so the verdict said `configured: true` and checked nothing. It must now
    /// carry the cross-check result, and a bad result must reach the exit code —
    /// a verify that prints TRUNCATED and exits 0 is not a verify.
    #[test]
    fn an_anchored_chain_reports_the_cross_check_not_just_that_it_is_configured() {
        use sysknife_daemon::audit_chain::checkpoint_outcome_to_exit_code;

        let consistent = CheckpointOutcome::Consistent {
            checkpoints_checked: 3,
        };
        assert!(anchor_line(&consistent).starts_with("OK:"));
        assert_eq!(anchor_json(&consistent)["status"], "consistent");
        assert_eq!(anchor_json(&consistent)["configured"], true);
        assert_eq!(checkpoint_outcome_to_exit_code(&consistent), 0);

        let truncated = CheckpointOutcome::Truncated {
            checkpoint_seq: 42,
            current_max_seq: 17,
        };
        let line = anchor_line(&truncated);
        assert!(
            line.contains("TRUNCATED") && line.contains("42") && line.contains("17"),
            "the verdict must name the gap it found, got: {line}"
        );
        assert_eq!(anchor_json(&truncated)["status"], "truncated");
        assert_eq!(
            checkpoint_outcome_to_exit_code(&truncated),
            1,
            "a detected truncation must fail the command"
        );

        // A configured anchor that holds nothing must not read as success.
        let empty = CheckpointOutcome::CannotVerify {
            reason: "no checkpoints".to_string(),
        };
        assert_eq!(anchor_json(&empty)["status"], "cannot_verify");
        assert_eq!(checkpoint_outcome_to_exit_code(&empty), 2);
    }

    #[test]
    fn a_detected_break_outranks_an_inconclusive_anchor_in_the_cli_exit_code() {
        use sysknife_daemon::audit_chain::{BindingOutcome, VerifyOutcome};

        let verification = AuditVerification {
            chain: VerifyOutcome::Broken {
                rows_checked: 3,
                first_broken_seq: 4,
                first_broken_transaction_id: "tx-4".to_string(),
                expected: "expected".to_string(),
                actual: "actual".to_string(),
            },
            events: VerifyOutcome::Intact { rows_checked: 4 },
            binding: BindingOutcome::Consistent {
                bindings_checked: 4,
            },
            attribution: None,
        };
        let anchor = CheckpointOutcome::CannotVerify {
            reason: "checkpoint database unavailable".to_string(),
        };

        assert_eq!(
            combined_verification_exit_code(&verification, Some(&anchor)),
            1
        );
    }

    #[test]
    fn json_status_includes_a_truncated_anchor_verdict() {
        use sysknife_daemon::audit_chain::VerifyOutcome;

        let anchor = CheckpointOutcome::Truncated {
            checkpoint_seq: 42,
            current_max_seq: 17,
        };
        let text = rendered_with_anchor(
            VerifyOutcome::Intact { rows_checked: 17 },
            None,
            true,
            Some(&anchor),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&text).expect("--json must emit one JSON document");

        assert_eq!(parsed["status"], "broken");
    }

    // -----------------------------------------------------------------------
    // Approval happens after the authoritative preview
    // -----------------------------------------------------------------------

    /// Step-by-step mode asks about every step, so every step must be asked
    /// about *after* its preview is on screen.
    #[test]
    fn step_by_step_confirms_every_step_after_its_preview() {
        for risk in [
            PlanRiskLevel::Low,
            PlanRiskLevel::Medium,
            PlanRiskLevel::High,
        ] {
            assert!(
                post_preview_confirmation_required(true, &risk),
                "--step-by-step must confirm {risk:?} steps at the preview"
            );
        }
    }

    /// In the default single-approval mode the plan prompt covers scope, so
    /// re-asking about every step would turn one prompt into N. HIGH is the
    /// exception: it is the class that can never be auto-approved, and the
    /// preview is the only place the operator sees what actually changes.
    #[test]
    fn default_mode_reconfirms_only_high_risk_steps_at_the_preview() {
        assert!(!post_preview_confirmation_required(
            false,
            &PlanRiskLevel::Low
        ));
        assert!(!post_preview_confirmation_required(
            false,
            &PlanRiskLevel::Medium
        ));
        assert!(post_preview_confirmation_required(
            false,
            &PlanRiskLevel::High
        ));
    }

    /// The skew check that stops an unattended run from executing unrecorded.
    ///
    /// A daemon older than the `unattended` field accepts the preview and
    /// silently drops it, so the signed row would look exactly like one a
    /// human approved. The CLI compares against the daemon crate's own
    /// constant rather than a local copy of the sentence, because a copy that
    /// drifted would answer "recorded" for a row that carries nothing.
    #[test]
    fn the_marker_check_matches_the_daemon_constant_exactly() {
        let real = sysknife_daemon::dispatcher::UNATTENDED_WARNING.to_string();
        assert!(unattended_marker_present(std::slice::from_ref(&real)));
        assert!(unattended_marker_present(&[
            "System state could not be collected".into(),
            real.clone(),
        ]));
    }

    #[test]
    fn the_marker_check_rejects_an_absent_or_near_miss_warning() {
        assert!(!unattended_marker_present(&[]));
        assert!(!unattended_marker_present(&["something else".into()]));

        // A near miss is the dangerous case: an older daemon, or one whose
        // wording drifted, must read as "not recorded" rather than close
        // enough. Substring matching would accept all three of these.
        let real = sysknife_daemon::dispatcher::UNATTENDED_WARNING;
        for near in [
            real.trim_end_matches('.'),
            &real.to_lowercase(),
            &format!(" {real}"),
            &real.replace("no operator", "No operator"),
        ] {
            assert!(
                !unattended_marker_present(&[near.to_string()]),
                "near miss must not count as recorded: {near:?}"
            );
        }
    }

    /// Structural guard on the execute loop: the daemon preview must be
    /// fetched before any approval decision is taken for that step.
    ///
    /// The defect this replaces was purely one of order — the operator was
    /// asked "execute?" while only planner summaries had been printed, and the
    /// preview carrying `proposed_change`, `expected_side_effects` and
    /// `rollback_available` arrived afterwards, when consent had already been
    /// given. A behavioural test would need a live daemon and an LLM, so the
    /// order is pinned in the source instead.
    #[test]
    fn the_execute_loop_previews_before_it_gates() {
        let src = include_str!("runner.rs");
        let loop_start = src
            .find("    // ---- execute steps ---")
            .expect("execute-steps section marker present");
        // Stop at the test module. Without this bound the search window
        // includes the two literals below, so the guard reads itself: the
        // production call could be renamed away entirely and the assertion
        // would still find a match, in the wrong order, and report a defect
        // that is really a stale anchor.
        let body_end = src[loop_start..]
            .find("#[cfg(test)]")
            .map(|i| loop_start + i)
            .expect("the test module follows the execute loop");
        let body = &src[loop_start..body_end];

        let preview_at = body
            .find(".preview_declaring(step.action_name()")
            .expect("the loop previews each step");
        let gate_at = body
            .find("policy.decide_step(")
            .expect("the loop gates each step");

        assert!(
            preview_at < gate_at,
            "approval is decided before the preview is fetched; the operator would \
             consent without seeing the daemon's proposed change"
        );
    }
    use sysknife_brain::action_name::ActionName;
    use sysknife_brain::planner::{AuthorizedPlan, PlanStep};

    /// Serialize env-var mutations so concurrent tests do not race on
    /// `SYSKNIFE_SOCKET`.  All tests that call `set_var` / `remove_var` must
    /// hold this lock for the full duration of the env read.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // -----------------------------------------------------------------------
    // rfc3339_to_unix — pure function, tests against known epoch values
    // -----------------------------------------------------------------------

    #[test]
    fn rfc3339_unix_epoch_z() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn rfc3339_unix_epoch_plus00() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00+00:00"), Some(0));
    }

    #[test]
    fn rfc3339_unix_one_day() {
        assert_eq!(rfc3339_to_unix("1970-01-02T00:00:00Z"), Some(86_400));
    }

    #[test]
    fn rfc3339_unix_y2k() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(rfc3339_to_unix("2000-01-01T00:00:00Z"), Some(946_684_800));
    }

    #[test]
    fn rfc3339_unix_leap_day_2000() {
        // 2000-02-29: Jan has 31 days, then 28 more days = 59 days from 2000-01-01.
        // 946684800 + 59 * 86400 = 946684800 + 5097600 = 951782400
        assert_eq!(rfc3339_to_unix("2000-02-29T00:00:00Z"), Some(951_782_400));
    }

    #[test]
    fn rfc3339_unix_with_subseconds() {
        // Sub-second fraction should be stripped.
        assert_eq!(
            rfc3339_to_unix("2000-01-01T00:00:00.123456Z"),
            Some(946_684_800)
        );
    }

    #[test]
    fn rfc3339_unix_non_utc_returns_none() {
        assert!(rfc3339_to_unix("2000-01-01T00:00:00+05:00").is_none());
    }

    #[test]
    fn rfc3339_unix_no_suffix_returns_none() {
        assert!(rfc3339_to_unix("2000-01-01T00:00:00").is_none());
    }

    #[test]
    fn rfc3339_unix_garbage_returns_none() {
        assert!(rfc3339_to_unix("not-a-date").is_none());
        assert!(rfc3339_to_unix("").is_none());
    }

    #[test]
    fn rfc3339_unix_invalid_month_returns_none() {
        assert!(rfc3339_to_unix("2000-13-01T00:00:00Z").is_none());
    }

    #[test]
    fn rfc3339_unix_invalid_hour_returns_none() {
        assert!(rfc3339_to_unix("2000-01-01T25:00:00Z").is_none());
    }

    #[test]
    fn rfc3339_unix_day_zero_returns_none() {
        // Day 0 is out of range; the lower bound of the `!(1..=31)` check.
        assert!(rfc3339_to_unix("2000-01-00T00:00:00Z").is_none());
    }

    // -----------------------------------------------------------------------
    // since_to_hours
    // -----------------------------------------------------------------------

    #[test]
    fn since_to_hours_y2k_is_many_hours_ago() {
        // Y2K was well over 200_000 hours ago (as of 2026).
        let h = since_to_hours("2000-01-01T00:00:00Z").expect("should parse");
        assert!(h > 200_000, "expected >200000 hours, got {h}");
    }

    #[test]
    fn since_to_hours_far_future_returns_none() {
        // Year 9999 is in the future.
        assert!(since_to_hours("9999-12-31T23:59:59Z").is_none());
    }

    #[test]
    fn since_to_hours_garbage_returns_none() {
        assert!(since_to_hours("not-a-date").is_none());
    }

    #[test]
    fn since_to_hours_epoch_returns_many_hours() {
        // Unix epoch (1970-01-01) is always ≥ 486000 hours ago (as of 2026).
        let h = since_to_hours("1970-01-01T00:00:00Z").expect("should parse");
        assert!(h > 486_000, "expected >486000, got {h}");
    }

    #[test]
    fn since_to_hours_integer_division_not_modulo() {
        // Two timestamps exactly 1 hour apart must differ by 1 in since_to_hours.
        // A `% 3600` regression would produce wildly different results for these.
        let h0 = since_to_hours("1970-01-01T00:00:00Z").unwrap();
        let h1 = since_to_hours("1970-01-01T01:00:00Z").unwrap();
        assert_eq!(h0, h1 + 1, "timestamps 1 h apart must differ by exactly 1");
    }

    // -----------------------------------------------------------------------
    // reject_unrunnable_params — plan-time parameter validation
    //
    // `authoritative_plan_risk` asks the daemon catalogue about a step by NAME
    // only, so nothing built its ActionSpec until the daemon did — at execution,
    // after the operator had already approved. A live 22.04 run showed the cost:
    // "block port 0 in the firewall" produced an approvable
    // `UfwDeny{port_or_service:"0"}` even though the daemon's
    // `validated_port_or_service` rejects port 0 outright.
    // -----------------------------------------------------------------------

    fn ufw_deny_plan(port: &str) -> Plan {
        Plan::new(
            "block a port".into(),
            "block a port".into(),
            "explanation".into(),
            vec![PlanStep::new(
                ActionName::parse("UfwDeny").unwrap(),
                "deny inbound traffic".into(),
                PlanRiskLevel::High,
                serde_json::json!({ "port_or_service": port }),
            )
            .unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn a_reserved_port_is_rejected_at_plan_time() {
        let err = reject_unrunnable_params(&ufw_deny_plan("0"))
            .expect_err("port 0 must not survive planning");
        let msg = err.to_string();
        assert!(
            msg.contains("UfwDeny") && msg.contains("port_or_service"),
            "the error must name the step and the offending param, got: {msg}"
        );
    }

    #[test]
    fn a_real_port_passes_plan_time_validation() {
        // The guard must not be a blanket refusal: the same action with a valid
        // port has to pass, or it would break every firewall plan.
        reject_unrunnable_params(&ufw_deny_plan("23")).expect("port 23 is valid");
        reject_unrunnable_params(&ufw_deny_plan("22/tcp")).expect("22/tcp is valid");
        reject_unrunnable_params(&ufw_deny_plan("OpenSSH")).expect("an app profile is valid");
    }

    #[test]
    fn a_missing_required_param_is_rejected_at_plan_time() {
        // Port 0 is one instance of a general defect: any param the daemon would
        // refuse used to reach the approval prompt. This covers the other half.
        let plan = Plan::new(
            "install".into(),
            "install a package".into(),
            "explanation".into(),
            vec![PlanStep::new(
                ActionName::parse("AptInstall").unwrap(),
                "install".into(),
                PlanRiskLevel::Medium,
                serde_json::json!({}),
            )
            .unwrap()],
        )
        .unwrap();
        let err = reject_unrunnable_params(&plan)
            .expect_err("AptInstall without a package is unrunnable");
        assert!(err.to_string().contains("AptInstall"));
    }

    #[test]
    fn every_catalogued_no_param_action_passes_plan_time_validation() {
        // Guard against the validator rejecting the ordinary case: every action
        // the daemon builds from an empty params object must still plan.
        for action in ["GetDiskUsage", "UfwStatus", "AptUpdate", "ListServices"] {
            let plan = Plan::new(
                "read".into(),
                "read state".into(),
                "explanation".into(),
                vec![PlanStep::new(
                    ActionName::parse(action).unwrap(),
                    "read".into(),
                    PlanRiskLevel::Low,
                    serde_json::json!({}),
                )
                .unwrap()],
            )
            .unwrap();
            reject_unrunnable_params(&plan)
                .unwrap_or_else(|e| panic!("{action} should plan cleanly: {e}"));
        }
    }

    // -----------------------------------------------------------------------
    // highest_risk
    // -----------------------------------------------------------------------

    fn make_step(risk: PlanRiskLevel) -> PlanStep {
        PlanStep::new(
            ActionName::parse("GetDiskUsage").unwrap(),
            "test".into(),
            risk,
            serde_json::json!({}),
        )
        .unwrap()
    }

    // The risks fed here are already the values under test, so wrap as
    // authoritative directly — highest_risk lives on AuthorizedPlan.
    fn make_plan(risks: &[PlanRiskLevel]) -> AuthorizedPlan {
        Plan::new(
            "test".into(),
            "test plan".into(),
            "explanation".into(),
            risks.iter().map(|r| make_step(r.clone())).collect(),
        )
        .unwrap()
        .assume_authorized()
    }

    // Note: Plan::new rejects empty step lists (PlanValidationError), so
    // `highest_risk` is never called on an empty plan in practice.  The return
    // type is `Option<_>` purely for type-safety against future API changes.

    #[test]
    fn highest_risk_single_low() {
        let plan = make_plan(&[PlanRiskLevel::Low]);
        assert_eq!(plan.highest_risk(), Some(&PlanRiskLevel::Low));
    }

    #[test]
    fn highest_risk_all_high() {
        let plan = make_plan(&[PlanRiskLevel::High, PlanRiskLevel::High]);
        assert_eq!(plan.highest_risk(), Some(&PlanRiskLevel::High));
    }

    #[test]
    fn highest_risk_mixed_picks_highest() {
        let plan = make_plan(&[
            PlanRiskLevel::Low,
            PlanRiskLevel::High,
            PlanRiskLevel::Medium,
        ]);
        assert_eq!(plan.highest_risk(), Some(&PlanRiskLevel::High));
    }

    #[test]
    fn highest_risk_low_medium_picks_medium() {
        let plan = make_plan(&[PlanRiskLevel::Low, PlanRiskLevel::Medium]);
        assert_eq!(plan.highest_risk(), Some(&PlanRiskLevel::Medium));
    }

    // -----------------------------------------------------------------------
    // authoritative_plan_risk — CLI approval gates on the daemon's spec risk
    // -----------------------------------------------------------------------

    #[test]
    fn authoritative_plan_risk_maps_spec_gate_risk() {
        // Values come from each action's ActionSpec via preview::gate_risk.
        assert_eq!(authoritative_plan_risk("GetDiskUsage"), PlanRiskLevel::Low);
        assert_eq!(
            authoritative_plan_risk("RestartService"),
            PlanRiskLevel::Medium
        );
        assert_eq!(authoritative_plan_risk("RebootSystem"), PlanRiskLevel::High);
        // No spec → conservative High (a missing spec never downgrades friction).
        assert_eq!(
            authoritative_plan_risk("DefinitelyNotARealAction"),
            PlanRiskLevel::High
        );
    }

    #[test]
    fn authoritative_risks_close_the_llm_under_rating_gate() {
        let mk = |name: &str, risk| {
            PlanStep::new(
                ActionName::parse(name).unwrap(),
                "s".into(),
                risk,
                serde_json::json!({}),
            )
            .unwrap()
        };
        // An LLM that under-rates a truly High-risk action (RebootSystem) as Low
        // would let `--yes --max-risk medium` auto-approve it...
        let under_rated = Plan::new(
            "i".into(),
            "s".into(),
            "e".into(),
            vec![mk("RebootSystem", PlanRiskLevel::Low)],
        )
        .unwrap();
        let policy = ApprovalPolicy::new(true, Some(MaxRisk::Medium), false, false, false);
        assert_eq!(
            policy.decide_plan(&under_rated.clone().assume_authorized()),
            ApprovalDecision::AutoApproved,
            "sanity: the LLM's Low rating alone would have auto-approved"
        );

        // ...but substituting the spec-derived risk restores the gate: RebootSystem
        // is High, which exceeds the Medium auto-approval ceiling.
        let corrected = under_rated.into_authorized(authoritative_plan_risk);
        assert_eq!(
            policy.decide_plan(&corrected),
            ApprovalDecision::ExceedsCeiling(MaxRisk::Medium),
            "spec-derived High must not auto-approve under --max-risk medium"
        );
    }

    #[test]
    fn authoritative_risks_close_the_under_rating_gate_for_bare_yes() {
        // The most common invocation: `--yes` with no `--max-risk` (auto-ceiling
        // defaults to Low). A planner under-rating a Medium action as Low would
        // otherwise auto-execute it with zero confirmation.
        let mk = |name: &str, risk| {
            PlanStep::new(
                ActionName::parse(name).unwrap(),
                "s".into(),
                risk,
                serde_json::json!({}),
            )
            .unwrap()
        };
        let plan = Plan::new(
            "i".into(),
            "s".into(),
            "e".into(),
            vec![mk("RestartService", PlanRiskLevel::Low)],
        )
        .unwrap();
        let policy = ApprovalPolicy::new(true, None, false, false, false);
        assert_eq!(
            policy.decide_plan(&plan.clone().assume_authorized()),
            ApprovalDecision::AutoApproved,
            "sanity: bare --yes would auto-approve the Low the planner claimed"
        );
        let corrected = plan.into_authorized(authoritative_plan_risk);
        assert_eq!(
            policy.decide_plan(&corrected),
            ApprovalDecision::RequiresPrompt,
            "spec-derived Medium must prompt under bare --yes"
        );
    }

    #[test]
    fn authoritative_risks_force_interaction_for_under_rated_action_non_interactive() {
        // Scripted/non-interactive runs have no human watching: an under-rated
        // action must hard-fail (RequiresInteraction), never auto-run.
        let mk = |name: &str, risk| {
            PlanStep::new(
                ActionName::parse(name).unwrap(),
                "s".into(),
                risk,
                serde_json::json!({}),
            )
            .unwrap()
        };
        let plan = Plan::new(
            "i".into(),
            "s".into(),
            "e".into(),
            vec![mk("RestartService", PlanRiskLevel::Low)],
        )
        .unwrap();
        let policy = ApprovalPolicy::new(true, None, true, false, false);
        assert_eq!(
            policy.decide_plan(&plan.clone().assume_authorized()),
            ApprovalDecision::AutoApproved,
            "sanity: the planner's Low would have auto-run unattended"
        );
        let corrected = plan.into_authorized(authoritative_plan_risk);
        assert_eq!(
            policy.decide_plan(&corrected),
            ApprovalDecision::RequiresInteraction,
            "under-rated Medium must abort a non-interactive run"
        );
    }

    #[test]
    fn authoritative_risks_open_the_over_rating_gate() {
        // Over-rating direction: a truly-Low action the planner flagged High must
        // NOT be needlessly blocked after substitution — proves the substitution
        // is a pure override, not max(planner, spec).
        let mk = |name: &str, risk| {
            PlanStep::new(
                ActionName::parse(name).unwrap(),
                "s".into(),
                risk,
                serde_json::json!({}),
            )
            .unwrap()
        };
        let plan = Plan::new(
            "i".into(),
            "s".into(),
            "e".into(),
            vec![mk("GetDiskUsage", PlanRiskLevel::High)],
        )
        .unwrap();
        let policy = ApprovalPolicy::new(true, Some(MaxRisk::Low), false, false, false);
        assert_eq!(
            policy.decide_plan(&plan.clone().assume_authorized()),
            ApprovalDecision::ExceedsCeiling(MaxRisk::Low),
            "sanity: the planner's inflated High would block a safe read-only action"
        );
        let corrected = plan.into_authorized(authoritative_plan_risk);
        assert_eq!(
            policy.decide_plan(&corrected),
            ApprovalDecision::AutoApproved,
            "spec-derived Low must auto-approve under --max-risk low"
        );
    }

    #[test]
    fn daemon_risk_within_approved_fails_closed_on_upward_skew() {
        use PlanRiskLevel::{High, Low, Medium};
        // Daemon risk == or < approved → allowed.
        assert!(daemon_risk_within_approved(&Medium, &Medium));
        assert!(daemon_risk_within_approved(&High, &Low));
        assert!(daemon_risk_within_approved(&Medium, &Low));
        // Daemon rates HIGHER than approved → must fail closed.
        assert!(!daemon_risk_within_approved(&Medium, &High));
        assert!(!daemon_risk_within_approved(&Low, &Medium));
        assert!(!daemon_risk_within_approved(&Low, &High));
    }

    // -----------------------------------------------------------------------
    // build_history_params
    // -----------------------------------------------------------------------

    #[test]
    fn build_history_params_minimal() {
        let p = build_history_params(20, None, None, None);
        assert_eq!(p["limit"], json!(20));
        assert!(p.get("status_filter").is_none());
        assert!(p.get("action_filter").is_none());
        assert!(p.get("since_hours").is_none());
    }

    #[test]
    fn build_history_params_all_fields() {
        let p = build_history_params(5, Some("succeeded"), Some("InstallPackages"), Some(48));
        assert_eq!(p["limit"], json!(5));
        assert_eq!(p["status_filter"], json!("succeeded"));
        assert_eq!(p["action_filter"], json!("InstallPackages"));
        assert_eq!(p["since_hours"], json!(48));
    }

    #[test]
    fn build_history_params_status_only() {
        let p = build_history_params(10, Some("failed"), None, None);
        assert_eq!(p["limit"], json!(10));
        assert_eq!(p["status_filter"], json!("failed"));
        assert!(p.get("action_filter").is_none());
        assert!(p.get("since_hours").is_none());
    }

    // -----------------------------------------------------------------------
    // run_history --since error mapping
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_history_invalid_since_returns_config_error() {
        // An unparseable --since must return CliError::ConfigOrDaemon without
        // ever touching the daemon socket (the socket path here is unused).
        let args = HistoryArgs {
            status: None,
            action: None,
            since: Some("not-a-date".into()),
            limit: 20,
        };
        let log = Logger::new(None).unwrap();
        let result = run_history(
            args,
            SocketTarget::Unix(PathBuf::from("/nonexistent.sock")),
            &log,
        )
        .await;
        match result {
            Err(CliError::ConfigOrDaemon(msg)) => {
                assert!(
                    msg.contains("--since"),
                    "error message must reference --since"
                );
            }
            other => panic!("expected ConfigOrDaemon, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_history_future_since_returns_config_error() {
        let args = HistoryArgs {
            status: None,
            action: None,
            since: Some("9999-12-31T23:59:59Z".into()),
            limit: 20,
        };
        let log = Logger::new(None).unwrap();
        let result = run_history(
            args,
            SocketTarget::Unix(PathBuf::from("/nonexistent.sock")),
            &log,
        )
        .await;
        match result {
            Err(CliError::ConfigOrDaemon(msg)) => {
                assert!(msg.contains("future"), "error must say 'future'");
            }
            other => panic!("expected ConfigOrDaemon, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_socket_target uses SYSKNIFE_SOCKET env var
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_socket_target_falls_back_to_core_default_listen_uri() {
        // With no explicit SYSKNIFE_SOCKET override, the CLI must resolve to the
        // same target the daemon binds — sysknife_core::default_listen_uri(),
        // whose top precedence is SYSKNIFE_LISTEN_URI. Regression guard for the
        // dev/non-systemd socket mismatch (the production path used to be
        // hardcoded here, so `sysknife doctor` could not reach a dev daemon).
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SYSKNIFE_SOCKET");
            std::env::set_var(
                "SYSKNIFE_LISTEN_URI",
                "unix:///run/user/4242/sysknife/daemon.sock",
            );
        }
        let t = resolve_socket_target();
        unsafe { std::env::remove_var("SYSKNIFE_LISTEN_URI") };
        assert_eq!(
            t,
            SocketTarget::Unix(PathBuf::from("/run/user/4242/sysknife/daemon.sock"))
        );
    }

    #[test]
    fn resolve_socket_target_parses_unix_uri() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_SOCKET", "unix:///tmp/custom.sock") };
        let t = resolve_socket_target();
        unsafe { std::env::remove_var("SYSKNIFE_SOCKET") };
        assert_eq!(t, SocketTarget::Unix(PathBuf::from("/tmp/custom.sock")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_socket_target_parses_vsock_uri() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_SOCKET", "vsock://3:7777") };
        let t = resolve_socket_target();
        unsafe { std::env::remove_var("SYSKNIFE_SOCKET") };
        assert_eq!(t, SocketTarget::Vsock { cid: 3, port: 7777 });
    }

    // ── the approval gate `run_intent` actually runs ──────────────────────

    #[test]
    fn only_an_auto_approved_decision_reaches_execution() {
        // The safety property of both gates in `run_intent`, checked over every
        // decision the policy can return. `ApprovalPolicy` itself is well
        // covered; what was untested is that `run_intent` obeys it — the two
        // gates were inline `match` blocks unreachable without an LLM provider
        // and a live daemon.
        let risk = PlanRiskLevel::High;
        let decisions = [
            ApprovalDecision::AutoApproved,
            ApprovalDecision::RequiresPrompt,
            ApprovalDecision::RequiresInteraction,
            ApprovalDecision::ExceedsCeiling(MaxRisk::Low),
        ];
        for decision in decisions {
            let expected_to_proceed = matches!(decision, ApprovalDecision::AutoApproved);
            let label = format!("{decision:?}");
            let proceeds = matches!(gate_action(decision, &risk), GateAction::Proceed);
            assert_eq!(
                proceeds, expected_to_proceed,
                "only AutoApproved may execute without asking; {label} did not match"
            );
        }
    }

    #[test]
    fn a_prompt_decision_asks_rather_than_refusing_or_running() {
        assert!(matches!(
            gate_action(ApprovalDecision::RequiresPrompt, &PlanRiskLevel::Medium),
            GateAction::AskOperator
        ));
    }

    #[test]
    fn non_interactive_refuses_without_prompting() {
        // Prompting here would block forever on a closed stdin in CI or a
        // systemd unit; the refusal must be silent and immediate.
        match gate_action(ApprovalDecision::RequiresInteraction, &PlanRiskLevel::High) {
            GateAction::Refuse(CliError::NonInteractive) => {}
            other => panic!("expected a NonInteractive refusal, got {other:?}"),
        }
    }

    #[test]
    fn exceeding_the_ceiling_reports_both_the_risk_and_the_ceiling() {
        // The error has to name both numbers or the operator cannot tell what
        // to raise `--max-risk` to.
        match gate_action(
            ApprovalDecision::ExceedsCeiling(MaxRisk::Low),
            &PlanRiskLevel::High,
        ) {
            GateAction::Refuse(CliError::RiskCeilingExceeded { highest, ceiling }) => {
                assert_eq!(highest, PlanRiskLevel::High);
                assert_eq!(ceiling, MaxRisk::Low);
            }
            other => panic!("expected a RiskCeilingExceeded refusal, got {other:?}"),
        }
    }
}
