//! sysctl kernel-parameter actions.
//!
//! `GetSysctl` is a read-only query of one key (or the full table); `SetSysctl`
//! changes a kernel parameter at runtime **and** persists it for the next boot.
//!
//! The read runs `sysctl` directly (the daemon is root). The write goes through
//! the root-owned helper `/usr/lib/sysknife/sysctl-edit`, which applies the
//! value with `sysctl -w` and rewrites the `/etc/sysctl.d/60-sysknife.conf`
//! drop-in idempotently — a narrow sudoers grant, not a bare `sysctl` grant, so
//! the daemon cannot use `sysctl -p <arbitrary-file>` to load an attacker file.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_sysctl(Some("net.ipv4.ip_forward")),
        set_sysctl("net.ipv4.ip_forward", "1"),
    ]
}

/// Read one kernel parameter (`sysctl -- <key>`) or, when `key` is `None`, the
/// entire table (`sysctl -a`). Read-only.
///
/// The `--` guard means a key can never be reparsed as an option even though
/// the validator already forbids a leading dash.
pub fn get_sysctl(key: Option<&str>) -> ActionSpec {
    let args = match key {
        Some(k) => vec!["--".to_string(), k.to_string()],
        None => vec!["-a".to_string()],
    };
    ActionSpec {
        action_name: "GetSysctl",
        mechanism: command_mechanism("sysctl", args),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Set and persist a kernel parameter via the scoped helper.
pub fn set_sysctl(key: &str, value: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SetSysctl",
        mechanism: command_mechanism(
            "sudo",
            [
                "/usr/lib/sysknife/sysctl-edit",
                "--key",
                key,
                "--value",
                value,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn args_of(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (program, args.clone()),
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn get_one_key_uses_dash_dash_guard() {
        let (program, args) = args_of(&get_sysctl(Some("net.ipv4.ip_forward")));
        assert_eq!(program, "sysctl");
        assert_eq!(args, vec!["--", "net.ipv4.ip_forward"]);
    }

    #[test]
    fn get_all_uses_minus_a() {
        let (_, args) = args_of(&get_sysctl(None));
        assert_eq!(args, vec!["-a"]);
    }

    #[test]
    fn set_delegates_to_scoped_helper() {
        let spec = set_sysctl("vm.swappiness", "10");
        let (program, args) = args_of(&spec);
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                "/usr/lib/sysknife/sysctl-edit",
                "--key",
                "vm.swappiness",
                "--value",
                "10"
            ]
        );
        assert_eq!(spec.risk_level, RiskLevel::High);
    }
}
