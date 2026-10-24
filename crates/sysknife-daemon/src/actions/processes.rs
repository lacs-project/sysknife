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

/// Send `signal` to process `pid`
/// (`sudo /usr/lib/sysknife/action-steps signal <signal> <pid>`).
///
/// High risk: terminating an arbitrary process as root can take down services
/// or lose in-flight work. The caller must have validated `signal` against the
/// allowlist and rejected `pid < 2` (0 = whole process group, 1 = init) before
/// calling. The helper checks both again, because its sudoers grant is also
/// reachable without the daemon; a `kill -s *` grant could not refuse a target.
pub fn signal_process(pid: u32, signal: &str) -> ActionSpec {
    let pid_str = pid.to_string();
    ActionSpec {
        action_name: "SignalProcess",
        mechanism: command_mechanism(
            "sudo",
            [
                "/usr/lib/sysknife/action-steps",
                "signal",
                signal,
                pid_str.as_str(),
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
