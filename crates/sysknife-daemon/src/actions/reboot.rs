//! Pending-reboot detection action (Ubuntu / Debian).
//!
//! ## CheckPendingReboot
//!
//! Checks whether a reboot is pending by inspecting
//! `/var/run/reboot-required`.  When a kernel or glibc update is installed via
//! `apt`, the installer touches that file.  If the file exists this action also
//! cats `/var/run/reboot-required-pkgs` (which lists the packages that require
//! the reboot) so the operator sees the full picture in one step.
//!
//! ### Why Ubuntu-only?
//!
//! On Fedora/Silverblue the equivalent information is surfaced through
//! `rpm-ostree status --json` (field `deployments[0].staged`).  That path is
//! already covered by the existing `GetPendingUpdates` action in the Fedora
//! action catalogue.  Adding a cross-distro `CheckPendingReboot` action would
//! require runtime distro detection inside the executor — a 50-line refactor
//! with no architectural precedent in the codebase.  Path (b) from the spec
//! was therefore chosen: `CheckPendingReboot` covers Debian/Ubuntu, and
//! Fedora operators use `GetPendingUpdates`.  The prompt places
//! `CheckPendingReboot` in `DEBIAN_RISK_TABLES` and notes the Fedora
//! equivalent in `DEBIAN_SELECTION_RULES`.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel file written by apt/dpkg when a reboot is required.
const REBOOT_REQUIRED_FILE: &str = "/var/run/reboot-required";

/// Optional file listing the packages that triggered the reboot requirement.
const REBOOT_REQUIRED_PKGS_FILE: &str = "/var/run/reboot-required-pkgs";

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` for this module.
pub fn specs() -> Vec<ActionSpec> {
    vec![check_pending_reboot()]
}

// ---------------------------------------------------------------------------
// Action constructor
// ---------------------------------------------------------------------------

/// Check whether a system reboot is pending on a Debian/Ubuntu host.
///
/// Risk: Low. Read-only file inspection; no system changes.
///
/// Exit-code semantics depend on which script branch fires:
/// - **No `/var/run/reboot-required`**: echoes "No reboot required." and
///   exits 0.
/// - **Sentinel exists, packages file readable**: prints the sentinel
///   contents plus `/var/run/reboot-required.pkgs`; exits 0.
/// - **Sentinel exists but packages file is unreadable**: prints the
///   sentinel; the inner `cat $pkgs 2>/dev/null` suppresses stderr but
///   the script's overall exit code is the last command's status, which
///   can be non-zero. Stdout still carries the human-readable status.
///
/// Callers should treat stdout as authoritative and not rely on a clean
/// exit code as the "no reboot needed" signal.
pub fn check_pending_reboot() -> ActionSpec {
    // `test -f` returns 1 when the file is absent; the shell fragment treats
    // that as "no reboot needed" and echoes a human-readable message instead
    // of failing the whole action.  `cat pkgs` may silently fail if the
    // packages file does not exist — the `2>/dev/null` suppresses that.
    let script = format!(
        "if test -f {sentinel}; then cat {sentinel}; cat {pkgs} 2>/dev/null; else echo 'No reboot required.'; fi",
        sentinel = REBOOT_REQUIRED_FILE,
        pkgs = REBOOT_REQUIRED_PKGS_FILE,
    );
    ActionSpec {
        action_name: "CheckPendingReboot",
        mechanism: command_mechanism("bash", ["-c", &script]),
        risk_level: RiskLevel::Low,
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

    fn extract_cmd(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (*program, args.clone()),
            _ => panic!("expected Command mechanism"),
        }
    }

    #[test]
    fn check_pending_reboot_action_name() {
        assert_eq!(check_pending_reboot().action_name, "CheckPendingReboot");
    }

    #[test]
    fn check_pending_reboot_uses_bash() {
        let spec = check_pending_reboot();
        let (prog, _) = extract_cmd(&spec);
        assert_eq!(prog, "bash");
    }

    #[test]
    fn check_pending_reboot_script_references_sentinel_file() {
        let spec = check_pending_reboot();
        let (_, args) = extract_cmd(&spec);
        let joined = args.join(" ");
        assert!(
            joined.contains(REBOOT_REQUIRED_FILE),
            "missing sentinel path in script: {joined}"
        );
    }

    #[test]
    fn check_pending_reboot_script_references_pkgs_file() {
        let spec = check_pending_reboot();
        let (_, args) = extract_cmd(&spec);
        let joined = args.join(" ");
        assert!(
            joined.contains(REBOOT_REQUIRED_PKGS_FILE),
            "missing pkgs path in script: {joined}"
        );
    }

    #[test]
    fn check_pending_reboot_risk_is_low() {
        assert_eq!(check_pending_reboot().risk_level, RiskLevel::Low);
    }

    #[test]
    fn check_pending_reboot_no_reboot_no_rollback() {
        let spec = check_pending_reboot();
        assert!(!spec.reboot_required);
        assert!(!spec.rollback_available);
    }

    #[test]
    fn specs_covers_check_pending_reboot() {
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        assert!(
            spec_names.contains(&"CheckPendingReboot"),
            "specs() missing CheckPendingReboot"
        );
    }
}
