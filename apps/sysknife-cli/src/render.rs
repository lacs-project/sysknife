//! Human-readable output for the `sysknife` CLI.
//!
//! All public functions in this module write to stdout (via [`Logger`]) or
//! stderr directly.  Every call site is guarded by `if !opts.json`, so the
//! JSON path is never affected.
//!
//! Color is emitted only when the target stream is a TTY and `NO_COLOR` is
//! unset — `owo-colors` handles this automatically via
//! `if_supports_color(Stream::…)`.  `indicatif` spinners auto-hide when
//! stderr is not a TTY (CI, pipes), so no explicit TTY guard is needed there.
//!
//! ## Chaining `color().bold()`
//!
//! Chaining two owo-colors display adapters inside a `if_supports_color`
//! closure creates a borrow of a temporary.  The safe pattern is to call
//! `.to_string()` inside the closure to materialise the string before the
//! temporary is dropped:
//!
//! ```ignore
//! "HIGH".if_supports_color(Stream::Stdout, |t| t.red().bold().to_string())
//! ```

use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::{OwoColorize, Stream};
use sysknife_brain::planner::{AuthorizedPlan, PlanRiskLevel};
use sysknife_types::{JobState, PreviewEnvelope, ResultEnvelope};

use crate::runner::Logger;

/// Spinner frame interval. Fast enough to read as motion, slow enough not to
/// flood a piped log.
const SPINNER_TICK: Duration = Duration::from_millis(80);
/// Width of the horizontal rules printed between sections.
const RULE_WIDTH: usize = 50;

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

/// Create an indeterminate spinner that ticks immediately on stderr.
///
/// `indicatif` auto-hides the spinner when stderr is not a TTY, so callers
/// never need to guard this with an `isatty` check.  Call
/// `pb.finish_and_clear()` to erase it before printing structured output.
pub fn make_spinner(msg: impl Into<String>) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.into());
    pb.enable_steady_tick(SPINNER_TICK);
    pb
}

// ---------------------------------------------------------------------------
// Risk badge
// ---------------------------------------------------------------------------

/// Return a colored `● low` / `● medium` / `● HIGH` badge string.
pub fn risk_colored(risk: &PlanRiskLevel) -> String {
    match risk {
        PlanRiskLevel::Low => format!(
            "● {}",
            "low".if_supports_color(Stream::Stdout, |t| t.green())
        ),
        PlanRiskLevel::Medium => format!(
            "● {}",
            "medium".if_supports_color(Stream::Stdout, |t| t.yellow())
        ),
        PlanRiskLevel::High => format!(
            "● {}",
            // .bold() chained after .red() borrows a temporary inside the
            // closure — materialise via .to_string() to avoid the lifetime error.
            "HIGH".if_supports_color(Stream::Stdout, |t| t.red().bold().to_string())
        ),
    }
}

// ---------------------------------------------------------------------------
// Plan display
// ---------------------------------------------------------------------------

/// Print the plan summary and step list to stdout (via `log`).
///
/// Takes an [`AuthorizedPlan`] so the risk badges shown to the operator are the
/// authoritative `ActionSpec` risks, never the LLM's proposal.
pub fn print_plan(plan: &AuthorizedPlan, log: &Logger) {
    log.println("");
    log.println(&format!(
        "  {}",
        plan.summary()
            .if_supports_color(Stream::Stdout, |t| t.bold())
    ));
    log.println(&format!(
        "  {}",
        "─"
            .repeat(RULE_WIDTH)
            .if_supports_color(Stream::Stdout, |t| t.dimmed())
    ));
    for (i, step) in plan.steps().enumerate() {
        let risk_badge = risk_colored(step.risk_level());
        let approval_label = if step.approval_required() {
            "approval required"
                .if_supports_color(Stream::Stdout, |t| t.yellow())
                .to_string()
        } else {
            "auto"
                .if_supports_color(Stream::Stdout, |t| t.dimmed())
                .to_string()
        };
        log.println(&format!(
            "  {}  {:<32}  {}  {}",
            format!("{}", i + 1).if_supports_color(Stream::Stdout, |t| t.dimmed()),
            step.action_name()
                .if_supports_color(Stream::Stdout, |t| t.bold()),
            risk_badge,
            approval_label,
        ));
        log.println(&format!(
            "     {}",
            step.summary()
                .if_supports_color(Stream::Stdout, |t| t.dimmed())
        ));
    }
    log.println("");
}

// ---------------------------------------------------------------------------
// Execution display
// ---------------------------------------------------------------------------

/// Print the `▶ ActionName  summary` step header to stderr.
///
/// Goes to stderr so it does not pollute piped stdout.
pub fn print_step_header(action: &str, preview: &PreviewEnvelope) {
    eprintln!(
        "\n  {} {}  {}",
        "▶".if_supports_color(Stream::Stderr, |t| t.cyan()),
        action.if_supports_color(Stream::Stderr, |t| t.bold()),
        preview
            .summary
            .if_supports_color(Stream::Stderr, |t| t.dimmed()),
    );
    if preview.reboot_required {
        eprintln!(
            "    {} reboot required after this step",
            "⚠".if_supports_color(Stream::Stderr, |t| t.yellow())
        );
    }
    for w in &preview.warnings {
        eprintln!(
            "    {} {w}",
            "!".if_supports_color(Stream::Stderr, |t| t.yellow())
        );
    }
}

/// Print one line of execution output with an indent, via `log`.
pub fn print_output_line(line: &str, log: &Logger) {
    log.println(&format!("  › {line}"));
}

/// Print the step result icon and summary via `log`.
pub fn print_step_done(result: &ResultEnvelope, log: &Logger) {
    let (icon, label) = match result.status {
        JobState::Succeeded => (
            "✓"
                .if_supports_color(Stream::Stdout, |t| t.green())
                .to_string(),
            "succeeded",
        ),
        JobState::Failed => (
            "✗"
                .if_supports_color(Stream::Stdout, |t| t.red())
                .to_string(),
            "failed",
        ),
        JobState::NeedsReboot => (
            "↺"
                .if_supports_color(Stream::Stdout, |t| t.yellow())
                .to_string(),
            "needs reboot",
        ),
        _ => (
            "⚠"
                .if_supports_color(Stream::Stdout, |t| t.yellow())
                .to_string(),
            "unknown",
        ),
    };
    log.println(&format!("  {icon}  {} — {label}", result.summary));
    if result.needs_reboot {
        log.println(&format!(
            "    {} reboot required",
            "⚠".if_supports_color(Stream::Stdout, |t| t.yellow())
        ));
    }
    // Surface post-execution warnings (e.g. "audit trail update failed"). These
    // are non-fatal — the action itself succeeded — but the operator must see
    // them, so they are never silently dropped.
    for w in &result.warnings {
        log.println(&format!(
            "    {} {w}",
            "!".if_supports_color(Stream::Stdout, |t| t.yellow())
        ));
    }
    if let Some(ref id) = result.job_id {
        log.println(&format!("    job  {id}"));
    }
}

/// Print the overall `✓ succeeded Xs` summary via `log`.
pub fn print_success(elapsed_secs: f32, log: &Logger) {
    log.println(&format!(
        "\n{}  succeeded  {:.1}s\n",
        "✓".if_supports_color(Stream::Stdout, |t| t.green()),
        elapsed_secs,
    ));
}

// ---------------------------------------------------------------------------
// Doctor display
// ---------------------------------------------------------------------------

/// Print a successful `sysknife doctor` report via `log`.
pub fn print_doctor_ok(
    socket: &str,
    host: &str,
    provider: &str,
    model: &str,
    distro: &str,
    log: &Logger,
) {
    log.println(&format!(
        "{}  daemon ok",
        "✓".if_supports_color(Stream::Stdout, |t| t.green())
    ));
    log.println(&format!("  socket    {socket}"));
    log.println(&format!("  host      {host}"));
    log.println(&format!("  provider  {provider}"));
    log.println(&format!("  model     {model}"));
    log.println(&format!("  distro    {distro}"));
}

/// Announce a planning request on a terminal-less stderr.
///
/// The spinner is the only thing that tells a user planning is under way, and
/// `indicatif` hides it when stderr is not a TTY. A slow provider then produced
/// no output at all for minutes (173s measured against a local Ollama), which
/// over ssh or in a log file is indistinguishable from a hung process. One line
/// is enough to tell the two apart, and it goes to stderr so `--json` consumers
/// reading stdout are unaffected.
pub fn print_planning_notice(provider: &str, model: &str, intent: &str) {
    eprintln!("→ planning \"{intent}\" with {provider}/{model}, this can take a minute…");
}

/// The lines a `sysknife doctor` failure prints, without colour.
///
/// Split out from [`print_doctor_fail`] so the wording and the ordering of the
/// remediation hints are testable. The hint order is not cosmetic: pointing
/// someone with a user-mode daemon at `sudo systemctl` sends them to a unit that
/// does not exist on their machine, and a vsock target has no local unit at all.
fn doctor_fail_lines(socket: &str, error: &str) -> Vec<String> {
    // Connect failures already name their target, so re-prefixing would print
    // the socket twice in one sentence.
    let headline = if error.contains(socket) {
        format!("daemon unreachable: {error}")
    } else {
        format!("daemon unreachable at {socket}: {error}")
    };
    let mut lines = vec![headline];

    // A remote daemon is not managed by systemd on this host, so naming local
    // units would be actively misleading.
    if socket.starts_with("vsock://") {
        lines.push("check the daemon on the target VM, and that SYSKNIFE_TOKEN matches".into());
        return lines;
    }

    // $XDG_RUNTIME_DIR is /run/user/<uid> on Ubuntu; that is where the setup
    // wizard's default (user-mode) daemon binds.
    let user_mode = socket.contains("/run/user/");

    // EACCES on a system socket is the one failure where the daemon is healthy
    // and `systemctl status` is green: /run/sysknife is 0750 sysknife:sysknife,
    // so an admin who installed the unit but never joined the group is refused
    // before any role check runs. Lead with the fix, because the unit hints
    // below will show nothing wrong. Skipped for /run/user sockets, where the
    // directory is the caller's own and group membership is not the cause.
    if !user_mode && error.to_lowercase().contains("permission denied") {
        lines.push("the daemon is listening, but this account may not open its socket".into());
        lines.push(
            "join the socket group and one role group:  \
             sudo usermod -aG sysknife,sysknife-admin \"$USER\""
                .into(),
        );
        lines.push(
            "role groups: sysknife-observer (read-only), sysknife-dev (medium risk), \
             sysknife-admin (high risk)"
                .into(),
        );
        lines.push("then log out and back in, or run:  newgrp sysknife".into());
    }

    let system_hint = "system service:  sudo systemctl status sysknife-daemon";
    let user_hint = "user service:    systemctl --user status sysknife-daemon";
    if user_mode {
        lines.push(user_hint.into());
        lines.push(system_hint.into());
    } else {
        lines.push(system_hint.into());
        lines.push(user_hint.into());
    }
    lines
}

/// Print a `sysknife doctor` failure to stderr.
pub fn print_doctor_fail(socket: &str, error: &str) {
    let mut lines = doctor_fail_lines(socket, error).into_iter();
    let headline = lines.next().expect("always at least one line");
    eprintln!(
        "{}  {headline}",
        "✗".if_supports_color(Stream::Stderr, |t| t.red()),
    );
    for hint in lines {
        eprintln!(
            "   {} {hint}",
            "→".if_supports_color(Stream::Stderr, |t| t.dimmed())
        );
    }
}

// ---------------------------------------------------------------------------
// T10 — render-layer regression tests
//
// `render.rs` drives every line a CLI user reads. Before this batch
// nothing in here had direct test coverage; the layout was held in
// place only by the developer running `sysknife` locally. These tests
// pin the contract of the leaf functions — string layout, badge
// shape, presence of every word a user sees — without colour codes
// (`if_supports_color` returns the raw string when stdout is not a
// TTY, which is always true under cargo test).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_colored_low_renders_low_with_a_dot_marker() {
        let s = risk_colored(&PlanRiskLevel::Low);
        assert!(
            s.starts_with('●'),
            "every risk badge must lead with the bullet glyph; got {s:?}"
        );
        assert!(
            s.contains("low"),
            "low-risk badge must mention 'low'; got {s:?}"
        );
    }

    #[test]
    fn risk_colored_medium_renders_medium_with_a_dot_marker() {
        let s = risk_colored(&PlanRiskLevel::Medium);
        assert!(s.starts_with('●'));
        assert!(s.contains("medium"));
    }

    #[test]
    fn risk_colored_high_renders_high_uppercase() {
        // Uppercase HIGH is a deliberate visual escalation cue —
        // anything else means a regression in the warn-loud-on-high
        // contract.
        let s = risk_colored(&PlanRiskLevel::High);
        assert!(s.starts_with('●'));
        assert!(
            s.contains("HIGH"),
            "high-risk badge must use uppercase HIGH; got {s:?}"
        );
        assert!(
            !s.contains("high "),
            "high-risk badge must NOT use lowercase 'high'; got {s:?}"
        );
    }

    // -----------------------------------------------------------------
    // `sysknife doctor` failure text
    //
    // The whole point of `doctor` is answering "why can't I reach the
    // daemon". It used to print only:
    //
    //   ✗  daemon unreachable: state unavailable: connect: No such file …
    //
    // No socket, no next step, even though the caller had the socket
    // label in hand. These tests pin both, and pin that the remediation
    // matches the kind of install the socket path implies — telling
    // someone with a user-mode daemon to run `sudo systemctl` sends them
    // to a unit that does not exist.
    // -----------------------------------------------------------------

    #[test]
    fn doctor_failure_names_the_socket_and_a_next_step() {
        let out = doctor_fail_lines("unix:///run/sysknife/daemon.sock", "connect: No such file");
        let joined = out.join("\n");
        assert!(joined.contains("unix:///run/sysknife/daemon.sock"));
        assert!(joined.contains("connect: No such file"), "keeps the cause");
        assert!(
            joined.contains("systemctl"),
            "must offer a command to run, got: {joined}"
        );
    }

    #[test]
    fn a_system_socket_suggests_the_system_unit_first() {
        let out = doctor_fail_lines("unix:///run/sysknife/daemon.sock", "boom").join("\n");
        let system_at = out.find("sudo systemctl").expect("system hint present");
        let user_at = out.find("systemctl --user").expect("user hint present");
        assert!(
            system_at < user_at,
            "system hint first for /run, got: {out}"
        );
    }

    #[test]
    fn a_per_user_runtime_socket_suggests_the_user_unit_first() {
        // $XDG_RUNTIME_DIR is /run/user/<uid> on Ubuntu, which is where the
        // wizard's default (user-mode) daemon binds.
        let out =
            doctor_fail_lines("unix:///run/user/1000/sysknife/daemon.sock", "boom").join("\n");
        let user_at = out.find("systemctl --user").expect("user hint present");
        let system_at = out.find("sudo systemctl").expect("system hint present");
        assert!(
            user_at < system_at,
            "user hint first for /run/user, got: {out}"
        );
    }

    #[test]
    fn permission_denied_names_the_group_fix_not_just_the_unit() {
        // A healthy system daemon plus a user who is not in the socket group
        // fails here. `systemctl status` looks fine in that state, so unit
        // hints alone send the operator hunting in the wrong place.
        let out = doctor_fail_lines(
            "unix:///run/sysknife/daemon.sock",
            "cannot reach the SysKnife daemon at unix:///run/sysknife/daemon.sock: \
             Permission denied (os error 13)",
        )
        .join("\n");
        assert!(
            out.contains("usermod -aG"),
            "must give the membership command, got: {out}"
        );
        assert!(
            out.contains("sysknife-admin"),
            "must name a role group, not only the socket group, got: {out}"
        );
        assert!(
            out.to_lowercase().contains("log"),
            "group changes need a new login to take effect; say so, got: {out}"
        );
    }

    #[test]
    fn permission_denied_hint_leads_the_report() {
        // Ordering is the whole point: the group fix must appear before the
        // systemd hints, because the daemon is running and the units are fine.
        let out = doctor_fail_lines(
            "unix:///run/sysknife/daemon.sock",
            "Permission denied (os error 13)",
        )
        .join("\n");
        let group_at = out.find("usermod -aG").expect("group hint present");
        let unit_at = out.find("systemctl").expect("unit hint present");
        assert!(
            group_at < unit_at,
            "the group fix must precede unit hints, got: {out}"
        );
    }

    #[test]
    fn a_missing_socket_does_not_suggest_a_group_change() {
        // "No such file" means nothing is listening — group membership is not
        // the problem, and suggesting it would be a wrong lead.
        let out = doctor_fail_lines(
            "unix:///run/sysknife/daemon.sock",
            "No such file or directory (os error 2)",
        )
        .join("\n");
        assert!(
            !out.contains("usermod"),
            "no group hint when the socket is absent, got: {out}"
        );
    }

    #[test]
    fn a_vsock_target_does_not_suggest_local_systemd_at_all() {
        // The daemon is on another host; `systemctl` here would be wrong.
        let out = doctor_fail_lines("vsock://3:7777", "boom").join("\n");
        assert!(out.contains("vsock://3:7777"));
        assert!(
            !out.contains("systemctl"),
            "local unit commands are misleading for a remote target, got: {out}"
        );
    }

    #[test]
    fn risk_badges_are_distinct_so_a_skim_can_tell_them_apart() {
        // Quick smoke: the three rendered badges must be three distinct
        // strings.  A regression that maps Medium → "low" or High → "medium"
        // (e.g. an off-by-one in a future enum reorder) collapses the set.
        use std::collections::HashSet;
        let set: HashSet<String> = [
            risk_colored(&PlanRiskLevel::Low),
            risk_colored(&PlanRiskLevel::Medium),
            risk_colored(&PlanRiskLevel::High),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            set.len(),
            3,
            "the three risk badges must render to distinct strings"
        );
    }
}
