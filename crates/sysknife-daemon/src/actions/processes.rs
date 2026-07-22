use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![list_processes_spec(), signal_process(1234, "TERM")]
}

pub fn list_processes_spec() -> ActionSpec {
    ActionSpec {
        action_name: "ListProcesses",
        mechanism: command_mechanism("ps", ["aux", "--sort=-%mem"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Send `signal` to process `pid` (`sudo kill -s <signal> <pid>`).
///
/// High risk: terminating an arbitrary process as root can take down services
/// or lose in-flight work. The caller must have validated `signal` against the
/// allowlist and rejected `pid < 2` (0 = whole process group, 1 = init) before
/// calling — the `-s <name> <pid>` argv form carries no shell.
pub fn signal_process(pid: u32, signal: &str) -> ActionSpec {
    let pid_str = pid.to_string();
    ActionSpec {
        action_name: "SignalProcess",
        mechanism: command_mechanism("sudo", ["kill", "-s", signal, pid_str.as_str()]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
