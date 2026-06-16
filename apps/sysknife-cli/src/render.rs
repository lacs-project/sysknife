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
use sysknife_brain::planner::{Plan, PlanRiskLevel};
use sysknife_types::{JobState, PreviewEnvelope, ResultEnvelope};

use crate::runner::Logger;

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
    pb.enable_steady_tick(Duration::from_millis(80));
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
pub fn print_plan(plan: &Plan, log: &Logger) {
    log.println("");
    log.println(&format!(
        "  {}",
        plan.summary()
            .if_supports_color(Stream::Stdout, |t| t.bold())
    ));
    log.println(&format!(
        "  {}",
        "─"
            .repeat(50)
            .if_supports_color(Stream::Stdout, |t| t.dimmed())
    ));
    for (i, step) in plan.steps().iter().enumerate() {
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

/// Print a `sysknife doctor` failure to stderr.
pub fn print_doctor_fail(error: &str) {
    eprintln!(
        "{}  daemon unreachable: {error}",
        "✗".if_supports_color(Stream::Stderr, |t| t.red()),
    );
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
