//! rpm-ostree and ostree deployment actions (Fedora Atomic).
//!
//! `RebaseSystem` and `SetKernelArguments` take an operand and run
//! `sudo /usr/lib/sysknife/action-steps rpm-ostree <rebase|kargs> ...`; the
//! helper validates the target or every kernel argument again and builds the
//! rpm-ostree argv itself. `/usr/bin/rpm-ostree kargs *` admitted
//! `--append=init=/bin/sh` and `rebase *` any local image, past the daemon's
//! screens. `UpdateSystem`, `RollbackDeployment` and `CleanupDeployments` take
//! no operand and keep exact grants of their own.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

/// The root-owned helper the operand-taking rpm-ostree actions go through; see
/// the same constant in `layering.rs`.
const ACTION_STEPS: &str = "/usr/lib/sysknife/action-steps";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_system_state(),
        collect_diagnostics(),
        get_deployment_history(),
        list_deployments(),
        update_system(),
        pin_deployment(0),
        unpin_deployment(0),
        rebase_system("fedora/41/x86_64/silverblue"),
        cleanup_deployments(),
        reboot_system(),
        rollback_deployment(),
        get_kernel_arguments(),
        set_kernel_arguments(&[], &[]),
    ]
}

pub fn get_system_state() -> ActionSpec {
    ActionSpec {
        action_name: "GetSystemState",
        mechanism: command_mechanism("rpm-ostree", ["status", "--json"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn collect_diagnostics() -> ActionSpec {
    ActionSpec {
        action_name: "CollectDiagnostics",
        mechanism: command_mechanism("journalctl", ["-b", "-n", "500", "--no-pager"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_deployment_history() -> ActionSpec {
    ActionSpec {
        action_name: "GetDeploymentHistory",
        mechanism: command_mechanism("rpm-ostree", ["status", "--json"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn list_deployments() -> ActionSpec {
    ActionSpec {
        action_name: "ListDeployments",
        mechanism: command_mechanism("rpm-ostree", ["status", "--json"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn update_system() -> ActionSpec {
    ActionSpec {
        action_name: "UpdateSystem",
        mechanism: command_mechanism("sudo", ["rpm-ostree", "upgrade"]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn pin_deployment(index: u32) -> ActionSpec {
    ActionSpec {
        action_name: "PinDeployment",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "ostree".to_string(),
                "admin".to_string(),
                "pin".to_string(),
                index.to_string(),
            ],
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn unpin_deployment(index: u32) -> ActionSpec {
    ActionSpec {
        action_name: "UnpinDeployment",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "ostree".to_string(),
                "admin".to_string(),
                "pin".to_string(),
                "--unpin".to_string(),
                index.to_string(),
            ],
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn rebase_system(target_ref: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RebaseSystem",
        // The helper runs `rpm-ostree rebase <target_ref>`.
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "rpm-ostree", "rebase", target_ref]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn cleanup_deployments() -> ActionSpec {
    ActionSpec {
        action_name: "CleanupDeployments",
        mechanism: command_mechanism("sudo", ["rpm-ostree", "cleanup", "--rollback", "--pending"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn reboot_system() -> ActionSpec {
    ActionSpec {
        action_name: "RebootSystem",
        mechanism: command_mechanism("sudo", ["systemctl", "reboot"]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: false,
    }
}

pub fn rollback_deployment() -> ActionSpec {
    ActionSpec {
        action_name: "RollbackDeployment",
        mechanism: command_mechanism("sudo", ["rpm-ostree", "rollback"]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: false,
    }
}

pub fn get_kernel_arguments() -> ActionSpec {
    ActionSpec {
        action_name: "GetKernelArguments",
        mechanism: command_mechanism("rpm-ostree", ["kargs"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Add and remove kernel arguments. The daemon sends `append <arg>` and
/// `delete <arg>` pairs, and the helper writes `--append=<arg>` and
/// `--delete=<arg>` itself, so no option reaches rpm-ostree from this argv. With
/// both lists empty the helper runs a bare `rpm-ostree kargs`, which prints them.
pub fn set_kernel_arguments(args_to_add: &[&str], args_to_remove: &[&str]) -> ActionSpec {
    let pairs = args_to_add
        .iter()
        .flat_map(|a| ["append", *a])
        .chain(args_to_remove.iter().flat_map(|a| ["delete", *a]));

    ActionSpec {
        action_name: "SetKernelArguments",
        mechanism: command_mechanism(
            "sudo",
            [ACTION_STEPS, "rpm-ostree", "kargs"]
                .into_iter()
                .chain(pairs),
        ),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{exclusive_resource, ActionMechanism, ExclusiveResource};

    fn argv(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            other => panic!("{} is not a command: {other:?}", spec.action_name),
        }
    }

    /// `/usr/bin/rpm-ostree rebase *` booted any image and `kargs *` took
    /// `--append=init=/bin/sh`. Both go through the helper verb now, which
    /// validates the target and every kernel argument again.
    #[test]
    fn rebase_and_kargs_go_through_the_helper_verb() {
        let rebase = rebase_system("fedora:fedora/41/x86_64/silverblue");
        let (program, args) = argv(&rebase);
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            [
                ACTION_STEPS,
                "rpm-ostree",
                "rebase",
                "fedora:fedora/41/x86_64/silverblue"
            ]
        );
        let kargs = set_kernel_arguments(&["nomodeset", "quiet"], &["rhgb"]);
        let (program, args) = argv(&kargs);
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            [
                ACTION_STEPS,
                "rpm-ostree",
                "kargs",
                "append",
                "nomodeset",
                "append",
                "quiet",
                "delete",
                "rhgb"
            ]
        );
        assert!(
            args.iter().all(|a| !a.starts_with('-')),
            "kargs sends an option; the helper writes --append=/--delete= itself: {args:?}"
        );
    }

    /// The operand-free actions keep their exact argv and exact grants.
    #[test]
    fn fixed_rpm_ostree_actions_keep_their_argv() {
        for (spec, expected) in [
            (update_system(), vec!["rpm-ostree", "upgrade"]),
            (rollback_deployment(), vec!["rpm-ostree", "rollback"]),
            (
                cleanup_deployments(),
                vec!["rpm-ostree", "cleanup", "--rollback", "--pending"],
            ),
        ] {
            let (program, args) = argv(&spec);
            assert_eq!(program, "sudo", "{}", spec.action_name);
            assert_eq!(args, expected, "{}", spec.action_name);
        }
    }

    #[test]
    fn deployment_actions_still_contend_for_the_rpm_ostree_lock() {
        for spec in [
            update_system(),
            rebase_system("fedora"),
            cleanup_deployments(),
            rollback_deployment(),
            set_kernel_arguments(&["quiet"], &[]),
            set_kernel_arguments(&[], &[]),
        ] {
            assert_eq!(
                exclusive_resource(&spec),
                Some(ExclusiveResource::RpmOstree),
                "{} lost the rpm-ostree lock",
                spec.action_name
            );
        }
    }
}
