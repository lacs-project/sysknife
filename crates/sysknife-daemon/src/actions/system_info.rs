use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![get_memory_info_spec(), get_host_state()]
}

pub fn get_memory_info_spec() -> ActionSpec {
    ActionSpec {
        action_name: "GetMemoryInfo",
        mechanism: command_mechanism("free", ["-h"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// The Debian-family answer to "what is this host?" — the counterpart to
/// Fedora's `GetSystemState`.
///
/// `GetSystemState` runs `rpm-ostree status --json`, which describes *deployments*.
/// An apt host has no deployments to snapshot, which is why it had no equivalent
/// and why `GetSystemState` was left running on every host — failing on Ubuntu
/// with `command not found`, *after* the operator had already approved it (#181).
///
/// `hostnamectl status` is the closest honest analogue: one read-only command,
/// no root, present on every systemd Ubuntu, reporting the OS release, kernel,
/// architecture, virtualization and machine identity. The two other facts the
/// issue floated — pending reboot and upgradable count — already have their own
/// actions (`CheckPendingReboot`, `AptListUpgradable`), so folding them in here
/// would have meant a shell pipeline and a second answer to a question already
/// answered. One action, one mechanism.
pub fn get_host_state() -> ActionSpec {
    ActionSpec {
        action_name: "GetHostState",
        mechanism: command_mechanism("hostnamectl", ["status"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    /// Read-only and root-free: this is the action a plan reaches for before it
    /// knows anything about the host, so it must never need privilege.
    #[test]
    fn get_host_state_is_a_read_only_unprivileged_query() {
        let spec = get_host_state();
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert!(!spec.reboot_required);
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                assert_eq!(*program, "hostnamectl");
                assert_eq!(args, &["status".to_string()]);
                assert_ne!(*program, "sudo", "a state query must not need root");
            }
            other => panic!("expected Command, got {other:?}"),
        }
    }
}
