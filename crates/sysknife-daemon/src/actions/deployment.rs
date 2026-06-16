use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

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
        mechanism: command_mechanism("sudo", ["rpm-ostree", "rebase", target_ref]),
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

pub fn set_kernel_arguments(args_to_add: &[&str], args_to_remove: &[&str]) -> ActionSpec {
    let args = std::iter::once("rpm-ostree".to_string())
        .chain(std::iter::once("kargs".to_string()))
        .chain(args_to_add.iter().map(|a| format!("--append={a}")))
        .chain(args_to_remove.iter().map(|a| format!("--delete={a}")))
        .collect();

    ActionSpec {
        action_name: "SetKernelArguments",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args,
        },
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}
