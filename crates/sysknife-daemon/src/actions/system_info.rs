use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![get_memory_info_spec()]
}

pub fn get_memory_info_spec() -> ActionSpec {
    ActionSpec {
        action_name: "GetMemoryInfo",
        mechanism: command_mechanism("free", ["-h"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}
