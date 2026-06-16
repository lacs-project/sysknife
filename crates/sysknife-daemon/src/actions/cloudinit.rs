//! cloud-init status action (Ubuntu / Debian).
//!
//! cloud-init is the industry-standard tool for early-boot configuration of
//! cloud instances. On Ubuntu it is installed by default; on Fedora Atomic,
//! `ignition` handles first-boot configuration instead.
//!
//! This action is marked Ubuntu-only because the gap analysis identifies
//! cloud-init as an Ubuntu-flavoured primitive: Fedora Atomic instances use
//! Ignition, not cloud-init, and querying `cloud-init status` on a Fedora
//! Atomic host is meaningless.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` for the cloud-init status action.
pub fn specs() -> Vec<ActionSpec> {
    vec![cloud_init_status()]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Show the current cloud-init run status (`cloud-init status --long`).
///
/// Risk: Low. Read-only; shows which cloud-init stages have run and whether
/// any errors occurred during instance provisioning.
pub fn cloud_init_status() -> ActionSpec {
    ActionSpec {
        action_name: "CloudInitStatus",
        mechanism: command_mechanism("cloud-init", ["status", "--long"]),
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

    fn extract_args(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (*program, args.clone()),
            _ => panic!("expected Command mechanism"),
        }
    }

    #[test]
    fn cloud_init_status_action_name() {
        assert_eq!(cloud_init_status().action_name, "CloudInitStatus");
    }

    #[test]
    fn cloud_init_status_risk_is_low() {
        assert_eq!(cloud_init_status().risk_level, RiskLevel::Low);
    }

    #[test]
    fn cloud_init_status_argv() {
        let spec = cloud_init_status();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "cloud-init");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(a, vec!["status", "--long"]);
    }

    #[test]
    fn cloud_init_status_no_sudo() {
        let (prog, _) = extract_args(&cloud_init_status());
        assert_ne!(prog, "sudo");
    }

    #[test]
    fn specs_covers_cloud_init_status() {
        let names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        assert!(
            names.contains(&"CloudInitStatus"),
            "specs() missing CloudInitStatus"
        );
    }
}
