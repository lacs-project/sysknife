//! Multipass VM management actions (Ubuntu).
//!
//! Multipass is Canonical's lightweight VM manager. It creates and manages
//! Ubuntu VMs with a single command. Typically installed via snap
//! (`snap install multipass`).
//!
//! ## Risk classification
//!
//! `MultipassList` is read-only — Low / Observer.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per multipass action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![multipass_list()]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// List all Multipass VMs and their state (`multipass list`).
///
/// Risk: Low / Observer. Read-only; shows VM names, state (Running/Stopped),
/// IPv4 addresses, and image versions. Does not start or modify any VM.
pub fn multipass_list() -> ActionSpec {
    ActionSpec {
        action_name: "MultipassList",
        mechanism: command_mechanism("multipass", ["list"]),
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
    fn multipass_list_action_name() {
        assert_eq!(multipass_list().action_name, "MultipassList");
    }

    #[test]
    fn multipass_list_risk_low() {
        assert_eq!(multipass_list().risk_level, RiskLevel::Low);
    }

    #[test]
    fn multipass_list_no_reboot() {
        assert!(!multipass_list().reboot_required);
    }

    #[test]
    fn multipass_list_no_rollback() {
        assert!(!multipass_list().rollback_available);
    }

    #[test]
    fn multipass_list_argv() {
        let spec = multipass_list();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "multipass");
        assert!(args.contains(&"list"));
    }

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["MultipassList"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
