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
    ]
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
