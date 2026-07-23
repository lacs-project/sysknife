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
//! `rollback_available` means the daemon automatically reverts the action on
//! failure (`executor::rollback_spec_for` returns `Some` and the dispatcher
//! runs it as part of the same job — see `docs/automatic-rollback.md`). That
//! mechanism exists only for rpm-ostree deployment actions today, so both
//! `AddPpa` and `RemovePpa` are `rollback_available = false`: apt/PPA state is
//! mutated directly on the live filesystem and the daemon does not stage or
//! auto-revert it. `AddPpa` and `RemovePpa` remain each other's manual
//! inverse — an operator (or agent) can undo one by explicitly running the
//! other — but that is a distinct fact from automatic rollback and is not
//! what this flag communicates.

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
/// Risk: High. Adds a third-party apt source, expanding the trusted software
/// supply chain; manually reversible by running `RemovePpa`. Requires
/// `software-properties-common` to be installed.
///
/// `rollback_available` is false: the daemon has no automatic rollback for
/// apt/PPA state (see `docs/automatic-rollback.md`); manual reversibility via
/// `RemovePpa` is a separate fact from that flag.
///
/// `name` must be in `<user>/<ppa>` format (e.g. `"deadsnakes/ppa"`).
/// Validation is enforced in the executor via `validated_ppa_name` before
/// this constructor is called.
pub fn add_ppa(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AddPpa",
        mechanism: command_mechanism("sudo", [ADD_APT_REPOSITORY, YES_FLAG, &ppa_arg(name)]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a PPA repository (`sudo add-apt-repository -y --remove ppa:<user>/<ppa>`).
///
/// Risk: Medium. Removes the apt source entry; manually reversible by running
/// `AddPpa`. Requires `software-properties-common` to be installed.
///
/// `rollback_available` is false — see [`add_ppa`]'s doc for why.
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
        rollback_available: false,
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
    fn add_ppa_risk_is_high() {
        assert_eq!(add_ppa("deadsnakes/ppa").risk_level, RiskLevel::High);
    }

    #[test]
    fn add_ppa_no_automatic_rollback() {
        // apt/PPA state has no automatic-rollback mechanism; only rpm-ostree
        // deployment actions do (see docs/automatic-rollback.md).
        assert!(!add_ppa("deadsnakes/ppa").rollback_available);
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
    fn remove_ppa_no_automatic_rollback() {
        assert!(!remove_ppa("deadsnakes/ppa").rollback_available);
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
