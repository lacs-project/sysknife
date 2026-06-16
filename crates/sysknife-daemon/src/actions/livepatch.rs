//! Canonical Livepatch status action (Ubuntu Pro).
//!
//! Canonical Livepatch applies kernel security patches without a reboot.
//! It requires:
//!
//! 1. The `canonical-livepatch` binary (`apt install canonical-livepatch`).
//! 2. An Ubuntu Pro subscription and an attached Livepatch token.
//!
//! If the binary is not installed, the OS returns "command not found" (exit
//! code 127). The daemon surfaces this error to the user as-is; no special
//! handling is needed.
//!
//! ## Risk classification
//!
//! `LivepatchStatus` is read-only — Low / Observer.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per livepatch action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![livepatch_status()]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Show Canonical Livepatch status (`sudo canonical-livepatch status --verbose`).
///
/// Risk: Low / Observer. Read-only; shows the patch state for the running
/// kernel. Requires the `canonical-livepatch` binary and an Ubuntu Pro
/// subscription. If the binary is not installed, the command exits with
/// "command not found" (exit 127) which is surfaced to the user.
pub fn livepatch_status() -> ActionSpec {
    ActionSpec {
        action_name: "LivepatchStatus",
        mechanism: command_mechanism("sudo", ["canonical-livepatch", "status", "--verbose"]),
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

    fn extract_cmd(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    #[test]
    fn livepatch_status_action_name() {
        assert_eq!(livepatch_status().action_name, "LivepatchStatus");
    }

    #[test]
    fn livepatch_status_risk_low() {
        assert_eq!(livepatch_status().risk_level, RiskLevel::Low);
    }

    #[test]
    fn livepatch_status_no_reboot() {
        assert!(!livepatch_status().reboot_required);
    }

    #[test]
    fn livepatch_status_no_rollback() {
        assert!(!livepatch_status().rollback_available);
    }

    #[test]
    fn livepatch_status_argv() {
        let spec = livepatch_status();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"canonical-livepatch"));
        assert!(args.contains(&"status"));
        assert!(args.contains(&"--verbose"));
    }

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["LivepatchStatus"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
