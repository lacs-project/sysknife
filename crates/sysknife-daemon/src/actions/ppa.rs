//! PPA (Personal Package Archive) management actions (Ubuntu).
//!
//! Both actions call `add-apt-repository` from the `software-properties-common`
//! package.  If that package is absent the daemon process will fail with
//! `ENOENT`; the executor surfaces that as an `ExecutionFailure` with the
//! binary name in the error message, giving the operator a clear hint.
//!
//! ## PPA name validation
//!
//! A PPA identifier must follow the `<user>/<ppa>` format where both
//! components consist of alphanumeric characters, hyphens, underscores, or
//! dots.  The validator rejects names containing shell-special characters and
//! names that do not contain exactly one `/`.
//!
//! ## Rollback availability
//!
//! Both `AddPpa` and `RemovePpa` are marked `rollback_available = true`
//! because they have an exact inverse: adding a PPA can be undone by removing
//! it and vice-versa.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Binary provided by `software-properties-common`.
const ADD_APT_REPOSITORY: &str = "add-apt-repository";

/// Flag for non-interactive execution (no "press ENTER to continue" prompt).
const YES_FLAG: &str = "-y";

/// `add-apt-repository` flag used to remove rather than add a PPA.
const REMOVE_FLAG: &str = "--remove";

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per PPA action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![add_ppa("deadsnakes/ppa"), remove_ppa("deadsnakes/ppa")]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the full `ppa:<user>/<ppa>` argument string.
fn ppa_arg(name: &str) -> String {
    format!("ppa:{name}")
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Add a PPA repository (`sudo add-apt-repository -y ppa:<user>/<ppa>`).
///
/// Risk: Medium. Adds a third-party apt source; reversible with `RemovePpa`.
/// Requires `software-properties-common` to be installed.
///
/// `name` must be in `<user>/<ppa>` format (e.g. `"deadsnakes/ppa"`).
/// Validation is enforced in the executor via `validated_ppa_name` before
/// this constructor is called.
pub fn add_ppa(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AddPpa",
        mechanism: command_mechanism("sudo", [ADD_APT_REPOSITORY, YES_FLAG, &ppa_arg(name)]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: true,
    }
}

/// Remove a PPA repository (`sudo add-apt-repository -y --remove ppa:<user>/<ppa>`).
///
/// Risk: Medium. Removes the apt source entry; reversible with `AddPpa`.
/// Requires `software-properties-common` to be installed.
///
/// `name` must be in `<user>/<ppa>` format (e.g. `"deadsnakes/ppa"`).
pub fn remove_ppa(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemovePpa",
        mechanism: command_mechanism(
            "sudo",
            [ADD_APT_REPOSITORY, YES_FLAG, REMOVE_FLAG, &ppa_arg(name)],
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: true,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn extract_args(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (*program, args.clone()),
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── add_ppa ──────────────────────────────────────────────────────────────

    #[test]
    fn add_ppa_action_name() {
        assert_eq!(add_ppa("deadsnakes/ppa").action_name, "AddPpa");
    }

    #[test]
    fn add_ppa_argv_correct() {
        let spec = add_ppa("deadsnakes/ppa");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let joined = args.join(" ");
        assert!(
            joined.contains("add-apt-repository"),
            "missing add-apt-repository: {joined}"
        );
        assert!(joined.contains("-y"), "missing -y: {joined}");
        assert!(
            joined.contains("ppa:deadsnakes/ppa"),
            "missing ppa:deadsnakes/ppa: {joined}"
        );
        // Must NOT include --remove for the add variant.
        assert!(
            !joined.contains("--remove"),
            "unexpected --remove: {joined}"
        );
    }

    #[test]
    fn add_ppa_risk_is_medium() {
        assert_eq!(add_ppa("deadsnakes/ppa").risk_level, RiskLevel::Medium);
    }

    #[test]
    fn add_ppa_rollback_available() {
        assert!(add_ppa("deadsnakes/ppa").rollback_available);
    }

    // ── remove_ppa ───────────────────────────────────────────────────────────

    #[test]
    fn remove_ppa_action_name() {
        assert_eq!(remove_ppa("deadsnakes/ppa").action_name, "RemovePpa");
    }

    #[test]
    fn remove_ppa_argv_contains_remove_flag() {
        let spec = remove_ppa("deadsnakes/ppa");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let joined = args.join(" ");
        assert!(joined.contains("--remove"), "missing --remove: {joined}");
        assert!(
            joined.contains("ppa:deadsnakes/ppa"),
            "missing ppa arg: {joined}"
        );
        assert!(joined.contains("-y"), "missing -y: {joined}");
    }

    #[test]
    fn remove_ppa_risk_is_medium() {
        assert_eq!(remove_ppa("deadsnakes/ppa").risk_level, RiskLevel::Medium);
    }

    #[test]
    fn remove_ppa_rollback_available() {
        assert!(remove_ppa("deadsnakes/ppa").rollback_available);
    }

    // ── ppa_arg ──────────────────────────────────────────────────────────────

    #[test]
    fn ppa_arg_prepends_ppa_prefix() {
        assert_eq!(ppa_arg("user/repo"), "ppa:user/repo");
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["AddPpa", "RemovePpa"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
