use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        list_services(),
        start_service("NetworkManager.service"),
        stop_service("NetworkManager.service"),
        restart_service("NetworkManager.service"),
        set_service_enabled("sshd.service", true),
        mask_service("cups.service"),
        unmask_service("cups.service"),
        get_service_logs("NetworkManager.service"),
        get_service_status("nginx.service"),
        reload_service("nginx.service"),
        list_timers(),
        reload_daemon(),
        create_scheduled_job("sysknife-example", "/usr/bin/true", "*-*-* 02:00:00"),
        get_service_resource_limits("nginx.service"),
        set_service_resource_limits(
            "nginx.service",
            &["MemoryMax=500M".to_string(), "CPUQuota=50%".to_string()],
        ),
    ]
}

/// Read a service's cgroup resource limits (`systemctl show --property=…`).
///
/// Read-only. `CPUQuota` is reported by systemd as `CPUQuotaPerSecUSec`, so
/// that is the property name queried here.
pub fn get_service_resource_limits(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "GetServiceResourceLimits",
        mechanism: command_mechanism(
            "systemctl",
            [
                "show",
                unit,
                "--property=MemoryMax,MemoryHigh,CPUQuotaPerSecUSec,TasksMax",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Set a service's cgroup resource limits (`sudo systemctl set-property …`).
///
/// Risk: Medium. `set-property` both applies the limit live and writes a
/// persistent drop-in under `/etc/systemd/system.control/<unit>.d/`; the change
/// is undone with `systemctl revert <unit>`. Using systemd's own verb (rather
/// than a hand-written drop-in helper) means systemd validates and manages the
/// unit files. `assignments` are pre-validated `PROPERTY=VALUE` pairs
/// (`MemoryMax=`, `CPUQuota=`, `TasksMax=`); the executor guarantees at least
/// one is present.
pub fn set_service_resource_limits(unit: &str, assignments: &[String]) -> ActionSpec {
    let mut args = vec![
        "systemctl".to_string(),
        "set-property".to_string(),
        unit.to_string(),
    ];
    args.extend(assignments.iter().cloned());
    ActionSpec {
        action_name: "SetServiceResourceLimits",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Installed path of the privileged scheduled-job helper script.
/// See `packaging/sysknife-scheduled-job-edit` and the matching NOPASSWD grant
/// in `packaging/sysknife-sudoers`.
const SCHEDULED_JOB_HELPER: &str = "/usr/lib/sysknife/scheduled-job-edit";

/// Create a recurring scheduled job as a systemd `.service` + `.timer` pair.
///
/// Risk: High. Persistent root-scheduled execution. Delegates to the root-owned
/// helper, which re-validates the job name, rejects control characters in the
/// command (blocking unit-file injection), validates the `OnCalendar`
/// expression with `systemd-analyze calendar`, writes the units,
/// `daemon-reload`s, and enables+starts the timer. The command is written to
/// `ExecStart`, which systemd argv-splits with no shell.
pub fn create_scheduled_job(name: &str, command: &str, schedule: &str) -> ActionSpec {
    ActionSpec {
        action_name: "CreateScheduledJob",
        mechanism: command_mechanism(
            "sudo",
            [
                SCHEDULED_JOB_HELPER,
                "--name",
                name,
                "--command",
                command,
                "--schedule",
                schedule,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn list_services() -> ActionSpec {
    ActionSpec {
        action_name: "ListServices",
        mechanism: command_mechanism(
            "systemctl",
            [
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn start_service(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "StartService",
        mechanism: command_mechanism("sudo", ["systemctl", "start", unit]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn stop_service(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "StopService",
        mechanism: command_mechanism("sudo", ["systemctl", "stop", unit]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn restart_service(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RestartService",
        mechanism: command_mechanism("sudo", ["systemctl", "restart", unit]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn set_service_enabled(unit: &str, enabled: bool) -> ActionSpec {
    let verb = if enabled { "enable" } else { "disable" };

    ActionSpec {
        action_name: "SetServiceEnabled",
        mechanism: command_mechanism("sudo", ["systemctl", verb, unit]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn mask_service(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "MaskService",
        mechanism: command_mechanism("sudo", ["systemctl", "mask", unit]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn unmask_service(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "UnmaskService",
        mechanism: command_mechanism("sudo", ["systemctl", "unmask", unit]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_service_status(unit: &str) -> ActionSpec {
    // Detailed unit status: active state, sub-state, loaded/enabled state,
    // recent log lines, and PID. More informative than `list-units` for
    // diagnosing a specific unit.
    ActionSpec {
        action_name: "GetServiceStatus",
        mechanism: command_mechanism("systemctl", ["status", unit, "--no-pager"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn reload_service(unit: &str) -> ActionSpec {
    // Trigger the unit's configured reload procedure (ExecReload=) without
    // stopping it. Only valid for units that define ExecReload= — attempting
    // this on a unit without it will fail with "Job type reload is not
    // applicable for unit X". Prefer over RestartService when live reload
    // is sufficient and the unit supports it.
    ActionSpec {
        action_name: "ReloadService",
        mechanism: command_mechanism("sudo", ["systemctl", "reload", unit]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn list_timers() -> ActionSpec {
    // Show all systemd timer units with their last/next trigger times.
    // Includes both active and inactive timers — useful for auditing
    // scheduled tasks.
    ActionSpec {
        action_name: "ListTimers",
        mechanism: command_mechanism(
            "systemctl",
            ["list-timers", "--all", "--no-legend", "--no-pager"],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn reload_daemon() -> ActionSpec {
    // Reload systemd manager configuration after any unit file change on disk —
    // including new files, edits to existing files, and drop-in overrides in
    // .d/ directories. Without daemon-reload, systemctl start/enable continue
    // using the previously-loaded definition even if the file has changed.
    ActionSpec {
        action_name: "ReloadDaemon",
        mechanism: command_mechanism("sudo", ["systemctl", "daemon-reload"]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_service_logs(unit: &str) -> ActionSpec {
    ActionSpec {
        action_name: "GetServiceLogs",
        mechanism: command_mechanism("journalctl", ["-u", unit, "-n", "200", "--no-pager"]),
        risk_level: RiskLevel::Low,
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
    fn get_resource_limits_is_read_only_show() {
        let spec = get_service_resource_limits("nginx.service");
        let (program, args) = args_of(&spec);
        assert_eq!(program, "systemctl");
        assert_eq!(args[0], "show");
        assert_eq!(args[1], "nginx.service");
        assert!(args[2].contains("MemoryMax") && args[2].contains("CPUQuotaPerSecUSec"));
        assert_eq!(spec.risk_level, RiskLevel::Low);
    }

    #[test]
    fn set_resource_limits_builds_set_property() {
        let spec = set_service_resource_limits(
            "nginx.service",
            &["MemoryMax=500M".to_string(), "CPUQuota=50%".to_string()],
        );
        let (program, args) = args_of(&spec);
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                "systemctl",
                "set-property",
                "nginx.service",
                "MemoryMax=500M",
                "CPUQuota=50%"
            ]
        );
        assert_eq!(spec.risk_level, RiskLevel::Medium);
    }
}
