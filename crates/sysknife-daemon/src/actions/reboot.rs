//! Pending-reboot detection action (Ubuntu / Debian).
//!
//! ## CheckPendingReboot
//!
//! Checks whether a reboot is pending by inspecting
//! `/var/run/reboot-required`.  When a kernel or glibc update is installed via
//! `apt`, the installer touches that file.  If the file exists this action also
//! cats `/var/run/reboot-required.pkgs` (which lists the packages that require
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
/// Ubuntu's `update-notifier` writes the dot form (`reboot-required.pkgs`);
/// the hyphen form is not a file the distro produces.
const REBOOT_REQUIRED_PKGS_FILE: &str = "/var/run/reboot-required.pkgs";

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
/// Exit-code semantics:
/// - **No `/var/run/reboot-required`**: echoes "No reboot required." and
///   exits 0.
/// - **Sentinel exists**: prints the sentinel contents, then
///   `/var/run/reboot-required.pkgs` when that file is readable, and
///   always exits 0. A missing packages file is optional, not an error —
///   the dispatcher would otherwise turn a pending reboot into
///   `CheckPendingReboot failed with exit code 1` and drop stdout.
pub fn check_pending_reboot() -> ActionSpec {
    // `test -f` returns 1 when the file is absent; the shell fragment treats
    // that as "no reboot needed" and echoes a human-readable message instead
    // of failing the whole action.  `cat pkgs` is optional: Ubuntu writes
    // the file alongside the sentinel, but a missing copy must not become
    // the `if` block's exit status. Ending the then-branch with `true`
    // keeps the action successful whenever the sentinel is present.
    let script = format!(
        "if test -f {sentinel}; then cat {sentinel}; cat {pkgs} 2>/dev/null; true; else echo 'No reboot required.'; fi",
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
    fn check_pending_reboot_script_uses_ubuntu_dot_pkgs_filename() {
        let spec = check_pending_reboot();
        let (_, args) = extract_cmd(&spec);
        let joined = args.join(" ");
        assert!(
            joined.contains("/var/run/reboot-required.pkgs"),
            "Ubuntu writes reboot-required.pkgs, not the hyphen form: {joined}"
        );
        assert!(
            !joined.contains("reboot-required-pkgs"),
            "hyphen form is not a file Ubuntu writes: {joined}"
        );
    }

    fn run_pending_reboot_script(sentinel: Option<&str>, pkgs: Option<&str>) -> (i32, String) {
        let dir = tempfile::tempdir().unwrap();
        let sentinel_path = dir.path().join("reboot-required");
        let pkgs_path = dir.path().join("reboot-required.pkgs");
        if let Some(body) = sentinel {
            std::fs::write(&sentinel_path, body).unwrap();
        }
        if let Some(body) = pkgs {
            std::fs::write(&pkgs_path, body).unwrap();
        }

        let spec = check_pending_reboot();
        let (_, args) = extract_cmd(&spec);
        assert_eq!(args.first().map(String::as_str), Some("-c"));
        // Replace the longer pkgs path first so the sentinel prefix cannot
        // rewrite `/var/run/reboot-required-pkgs` into a fixture path + `-pkgs`.
        let script = args[1]
            .replace(REBOOT_REQUIRED_PKGS_FILE, &pkgs_path.to_string_lossy())
            .replace(REBOOT_REQUIRED_FILE, &sentinel_path.to_string_lossy());

        let output = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .expect("bash");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    #[test]
    fn pending_reboot_without_sentinel_reports_no_reboot() {
        let (code, stdout) = run_pending_reboot_script(None, None);
        assert_eq!(code, 0, "stdout={stdout:?}");
        assert_eq!(stdout.trim(), "No reboot required.");
    }

    #[test]
    fn pending_reboot_with_sentinel_and_pkgs_lists_both() {
        let (code, stdout) = run_pending_reboot_script(
            Some("*** System restart required ***\n"),
            Some("linux-image-6.8.0-40-generic\n"),
        );
        assert_eq!(code, 0, "stdout={stdout:?}");
        assert!(
            stdout.contains("*** System restart required ***"),
            "stdout={stdout:?}"
        );
        assert!(
            stdout.contains("linux-image-6.8.0-40-generic"),
            "stdout={stdout:?}"
        );
    }

    #[test]
    fn pending_reboot_with_sentinel_only_is_not_an_error() {
        let (code, stdout) =
            run_pending_reboot_script(Some("*** System restart required ***\n"), None);
        assert_eq!(
            code, 0,
            "a missing packages file must not fail the action; stdout={stdout:?}"
        );
        assert!(
            stdout.contains("*** System restart required ***"),
            "stdout={stdout:?}"
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
