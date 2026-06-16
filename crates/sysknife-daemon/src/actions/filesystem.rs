use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![disk_usage_spec()]
}

pub fn disk_usage_spec() -> ActionSpec {
    ActionSpec {
        action_name: "GetDiskUsage",
        mechanism: command_mechanism(
            "df",
            [
                "-h",
                "--output=source,fstype,size,used,avail,pcent,target",
                "--exclude-type=composefs",
                "--exclude-type=tmpfs",
                "--exclude-type=devtmpfs",
                "--exclude-type=efivarfs",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}
