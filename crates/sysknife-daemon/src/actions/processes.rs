use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![list_processes_spec()]
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
