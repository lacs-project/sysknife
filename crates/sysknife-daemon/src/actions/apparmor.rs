//! AppArmor profile management actions (Ubuntu / Debian).
//!
//! AppArmor is the default MAC (Mandatory Access Control) system on Ubuntu.
//! These actions invoke `aa-status` (provided by the `apparmor` base package)
//! and `aa-enforce` / `aa-complain` (provided by `apparmor-utils`, which may
//! need a separate `apt install`). On a minimal server install the base
//! package is present but `apparmor-utils` is not — `AppArmorEnforce` and
//! `AppArmorComplain` will report `command not found` until it is added.
//!
//! ## Profile modes
//!
//! - **enforce** — the profile is active; violations are blocked and logged.
//! - **complain** — the profile is in learning mode; violations are logged but
//!   not blocked. Use complain to diagnose an over-restrictive profile before
//!   deciding to fix or disable it.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per AppArmor action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        apparmor_status(),
        apparmor_enforce("/etc/apparmor.d/usr.bin.firefox"),
        apparmor_complain("/etc/apparmor.d/usr.bin.firefox"),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Show the status of all loaded AppArmor profiles (`sudo aa-status`).
///
/// Risk: Low. Read-only; lists every profile and its current mode.
pub fn apparmor_status() -> ActionSpec {
    ActionSpec {
        action_name: "AppArmorStatus",
        mechanism: command_mechanism("sudo", ["aa-status"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Put an AppArmor profile into enforce mode (`sudo aa-enforce <profile_path>`).
///
/// Risk: High. Activating enforcement can immediately block operations that
/// the application relies on, potentially causing it to fail or lose data.
/// Always test in complain mode first.
pub fn apparmor_enforce(profile_path: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AppArmorEnforce",
        mechanism: command_mechanism("sudo", ["aa-enforce", profile_path]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Put an AppArmor profile into complain (learning) mode (`sudo aa-complain <profile_path>`).
///
/// Risk: Medium. Violations are logged but not blocked; the application runs
/// with fewer restrictions than in enforce mode. Use to audit a profile before
/// enforcing it, or to temporarily relax enforcement for diagnostics.
pub fn apparmor_complain(profile_path: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AppArmorComplain",
        mechanism: command_mechanism("sudo", ["aa-complain", profile_path]),
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

    // ── apparmor_status ──────────────────────────────────────────────────────

    #[test]
    fn apparmor_status_action_name() {
        assert_eq!(apparmor_status().action_name, "AppArmorStatus");
    }

    #[test]
    fn apparmor_status_risk_is_low() {
        assert_eq!(apparmor_status().risk_level, RiskLevel::Low);
    }

    #[test]
    fn apparmor_status_argv() {
        let spec = apparmor_status();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(a, vec!["aa-status"]);
    }

    // ── apparmor_enforce ─────────────────────────────────────────────────────

    #[test]
    fn apparmor_enforce_action_name() {
        assert_eq!(
            apparmor_enforce("/etc/apparmor.d/usr.bin.firefox").action_name,
            "AppArmorEnforce"
        );
    }

    #[test]
    fn apparmor_enforce_risk_is_high() {
        assert_eq!(
            apparmor_enforce("/etc/apparmor.d/usr.bin.firefox").risk_level,
            RiskLevel::High
        );
    }

    #[test]
    fn apparmor_enforce_argv() {
        let profile = "/etc/apparmor.d/usr.bin.firefox";
        let spec = apparmor_enforce(profile);
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(a[0], "aa-enforce");
        assert_eq!(a[1], profile);
    }

    // ── apparmor_complain ────────────────────────────────────────────────────

    #[test]
    fn apparmor_complain_action_name() {
        assert_eq!(
            apparmor_complain("/etc/apparmor.d/usr.bin.firefox").action_name,
            "AppArmorComplain"
        );
    }

    #[test]
    fn apparmor_complain_risk_is_medium() {
        assert_eq!(
            apparmor_complain("/etc/apparmor.d/usr.bin.firefox").risk_level,
            RiskLevel::Medium
        );
    }

    #[test]
    fn apparmor_complain_argv() {
        let profile = "/etc/apparmor.d/usr.bin.nginx";
        let spec = apparmor_complain(profile);
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(a[0], "aa-complain");
        assert_eq!(a[1], profile);
    }

    #[test]
    fn enforce_uses_aa_enforce_not_aa_complain() {
        let spec = apparmor_enforce("/etc/apparmor.d/test");
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"aa-enforce"));
        assert!(!a.contains(&"aa-complain"));
    }

    #[test]
    fn complain_uses_aa_complain_not_aa_enforce() {
        let spec = apparmor_complain("/etc/apparmor.d/test");
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"aa-complain"));
        assert!(!a.contains(&"aa-enforce"));
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["AppArmorStatus", "AppArmorEnforce", "AppArmorComplain"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
