//! Log-management actions: logrotate drop-ins + rsyslog remote forwarding.
//!
//! `GetLogrotateStatus` is a read-only dry-run (`logrotate -d`). The mutating
//! actions delegate to the root-owned helper `/usr/lib/sysknife/log-edit`, which
//! validates each config before keeping it (`logrotate -d` for rotation,
//! `rsyslogd -N1` for forwarding) and rolls back on rejection.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

const HELPER: &str = "/usr/lib/sysknife/log-edit";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_logrotate_status(None),
        configure_log_rotation("nginx", "/var/log/nginx/*.log", "daily", 14, true),
        remove_log_rotation("nginx"),
        configure_remote_syslog("logs.example.com", 514, "tcp"),
        remove_remote_syslog(),
    ]
}

/// Dry-run logrotate to show what would rotate (`logrotate -d <conf>`).
/// Read-only — `-d` (debug) never actually rotates. Defaults to the main config.
pub fn get_logrotate_status(config: Option<&str>) -> ActionSpec {
    let conf = config.unwrap_or("/etc/logrotate.conf");
    ActionSpec {
        action_name: "GetLogrotateStatus",
        mechanism: command_mechanism("logrotate", ["-d", conf]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Write a logrotate drop-in (`log-edit --op logrotate …`).
pub fn configure_log_rotation(
    name: &str,
    path: &str,
    frequency: &str,
    rotate: u32,
    compress: bool,
) -> ActionSpec {
    let rot = rotate.to_string();
    let mut args = vec![
        HELPER.to_string(),
        "--op".to_string(),
        "logrotate".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--path".to_string(),
        path.to_string(),
        "--frequency".to_string(),
        frequency.to_string(),
        "--rotate".to_string(),
        rot,
    ];
    if compress {
        args.push("--compress".to_string());
    }
    ActionSpec {
        action_name: "ConfigureLogRotation",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a SysKnife-managed logrotate drop-in.
pub fn remove_log_rotation(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveLogRotation",
        mechanism: command_mechanism("sudo", [HELPER, "--op", "rm-logrotate", "--name", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Configure rsyslog to forward all logs to a remote collector.
pub fn configure_remote_syslog(host: &str, port: u16, protocol: &str) -> ActionSpec {
    let p = port.to_string();
    ActionSpec {
        action_name: "ConfigureRemoteSyslog",
        mechanism: command_mechanism(
            "sudo",
            [
                HELPER,
                "--op",
                "rsyslog-forward",
                "--host",
                host,
                "--port",
                &p,
                "--protocol",
                protocol,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove the rsyslog remote-forwarding drop-in.
pub fn remove_remote_syslog() -> ActionSpec {
    ActionSpec {
        action_name: "RemoveRemoteSyslog",
        mechanism: command_mechanism("sudo", [HELPER, "--op", "rm-forward"]),
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
    fn logrotate_status_dry_run() {
        let (program, args) = args_of(&get_logrotate_status(None));
        assert_eq!(program, "logrotate");
        assert_eq!(args, vec!["-d", "/etc/logrotate.conf"]);
        assert_eq!(get_logrotate_status(None).risk_level, RiskLevel::Low);
    }

    #[test]
    fn configure_rotation_with_compress() {
        let (program, args) = args_of(&configure_log_rotation(
            "nginx",
            "/var/log/nginx/*.log",
            "daily",
            14,
            true,
        ));
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                HELPER,
                "--op",
                "logrotate",
                "--name",
                "nginx",
                "--path",
                "/var/log/nginx/*.log",
                "--frequency",
                "daily",
                "--rotate",
                "14",
                "--compress"
            ]
        );
        let (_, no_comp) = args_of(&configure_log_rotation(
            "n",
            "/var/log/x",
            "weekly",
            4,
            false,
        ));
        assert!(!no_comp.iter().any(|a| a == "--compress"));
    }

    #[test]
    fn syslog_forward_tcp_and_removes() {
        let (_, fwd) = args_of(&configure_remote_syslog("logs.example.com", 514, "tcp"));
        assert_eq!(
            fwd,
            vec![
                HELPER,
                "--op",
                "rsyslog-forward",
                "--host",
                "logs.example.com",
                "--port",
                "514",
                "--protocol",
                "tcp"
            ]
        );
        assert_eq!(
            configure_remote_syslog("h", 1, "udp").risk_level,
            RiskLevel::High
        );
        let (_, rm) = args_of(&remove_remote_syslog());
        assert_eq!(rm, vec![HELPER, "--op", "rm-forward"]);
    }
}
