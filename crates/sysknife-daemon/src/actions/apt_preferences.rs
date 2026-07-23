//! apt package pinning (`/etc/apt/preferences.d/`). Debian-family only.
//!
//! `GetAptPins` is read-only (`apt-cache policy`). `SetAptPin`/`RemoveAptPin`
//! write/remove a pin drop-in via the root-owned helper
//! `/usr/lib/sysknife/apt-pin-edit`. Pinning steers which version/origin apt
//! prefers — reversible, so Dev/Medium rather than Admin.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

const HELPER: &str = "/usr/lib/sysknife/apt-pin-edit";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_apt_pins(None),
        set_apt_pin("hold-nginx", "nginx", "version 1.24.*", 990),
        remove_apt_pin("hold-nginx"),
    ]
}

/// Show apt pin priorities (`apt-cache policy [pkg]`). Read-only.
pub fn get_apt_pins(package: Option<&str>) -> ActionSpec {
    let mut args = vec!["policy".to_string()];
    if let Some(pkg) = package {
        args.push(pkg.to_string());
    }
    ActionSpec {
        action_name: "GetAptPins",
        mechanism: command_mechanism("apt-cache", args),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Write a pin drop-in (`apt-pin-edit --op set …`).
pub fn set_apt_pin(name: &str, package: &str, pin: &str, priority: i64) -> ActionSpec {
    let prio = priority.to_string();
    ActionSpec {
        action_name: "SetAptPin",
        mechanism: command_mechanism(
            "sudo",
            [
                HELPER,
                "--op",
                "set",
                "--name",
                name,
                "--package",
                package,
                "--pin",
                pin,
                "--priority",
                &prio,
            ],
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a pin drop-in (`apt-pin-edit --op remove …`).
pub fn remove_apt_pin(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveAptPin",
        mechanism: command_mechanism("sudo", [HELPER, "--op", "remove", "--name", name]),
        risk_level: RiskLevel::Medium,
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
    fn get_pins_optional_package() {
        let (program, args) = args_of(&get_apt_pins(None));
        assert_eq!(program, "apt-cache");
        assert_eq!(args, vec!["policy"]);
        let (_, with_pkg) = args_of(&get_apt_pins(Some("nginx")));
        assert_eq!(with_pkg, vec!["policy", "nginx"]);
    }

    #[test]
    fn set_and_remove_shapes() {
        let (program, set) = args_of(&set_apt_pin("hold-nginx", "nginx", "version 1.24.*", 990));
        assert_eq!(program, "sudo");
        assert_eq!(
            set,
            vec![
                HELPER,
                "--op",
                "set",
                "--name",
                "hold-nginx",
                "--package",
                "nginx",
                "--pin",
                "version 1.24.*",
                "--priority",
                "990"
            ]
        );
        assert_eq!(set_apt_pin("a", "b", "c", 1).risk_level, RiskLevel::Medium);
        let (_, rm) = args_of(&remove_apt_pin("hold-nginx"));
        assert_eq!(rm, vec![HELPER, "--op", "remove", "--name", "hold-nginx"]);
    }
}
