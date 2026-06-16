//! Ubuntu release upgrade action.
//!
//! `UbuntuReleaseUpgrade` triggers a full distribution upgrade via
//! `do-release-upgrade`. This is a Tier 3 action — it is gated behind
//! `RiskLevel::High` and always requires explicit human approval before
//! the daemon will execute it.
//!
//! ## Timeout
//!
//! A full Ubuntu release upgrade typically takes 20–45 minutes. Callers
//! SHOULD configure a long execution timeout (≥ 3 600 seconds / 1 hour) —
//! this is advisory; the daemon does not enforce a minimum. Short timeouts
//! may abort the upgrade mid-flight and leave the system in a partially-
//! upgraded state. Inform the user a reboot is required afterward.
//!
//! ## Risk
//!
//! - Upgrades to the next LTS or interim release.
//! - Non-interactive (`DistUpgradeViewNonInteractive`) but may still fail if
//!   third-party PPAs or pinned packages block the upgrade resolver.
//! - A reboot is required after the operation completes.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per release-upgrade action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![ubuntu_release_upgrade()]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Trigger a full Ubuntu distribution upgrade
/// (`do-release-upgrade -f DistUpgradeViewNonInteractive`).
///
/// Risk: High / Admin. Upgrades the entire operating system to the next
/// Ubuntu release. Takes 20–45 minutes and **requires a reboot** to
/// complete the transition.
///
/// Callers must configure an execution timeout of at least 3 600 seconds.
pub fn ubuntu_release_upgrade() -> ActionSpec {
    ActionSpec {
        action_name: "UbuntuReleaseUpgrade",
        mechanism: command_mechanism(
            "sudo",
            ["do-release-upgrade", "-f", "DistUpgradeViewNonInteractive"],
        ),
        risk_level: RiskLevel::High,
        reboot_required: true,
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

    fn extract_cmd(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    #[test]
    fn ubuntu_release_upgrade_action_name() {
        assert_eq!(ubuntu_release_upgrade().action_name, "UbuntuReleaseUpgrade");
    }

    #[test]
    fn ubuntu_release_upgrade_risk_high() {
        assert_eq!(ubuntu_release_upgrade().risk_level, RiskLevel::High);
    }

    #[test]
    fn ubuntu_release_upgrade_reboot_required() {
        // A release upgrade always requires a reboot to finish the transition.
        assert!(ubuntu_release_upgrade().reboot_required);
    }

    #[test]
    fn ubuntu_release_upgrade_no_rollback() {
        assert!(!ubuntu_release_upgrade().rollback_available);
    }

    #[test]
    fn ubuntu_release_upgrade_argv() {
        let spec = ubuntu_release_upgrade();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"do-release-upgrade"));
        assert!(args.contains(&"-f"));
        assert!(args.contains(&"DistUpgradeViewNonInteractive"));
    }

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["UbuntuReleaseUpgrade"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
