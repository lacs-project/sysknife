//! LVM (Logical Volume Manager) storage actions.
//!
//! `GetLvmReport` is a read-only inventory of logical volumes in JSON;
//! `ExtendLogicalVolume`, `CreateLogicalVolume`, and `CreateLvSnapshot` mutate
//! storage layout and are therefore Admin/High.
//!
//! `lvs` is run directly (the daemon is root, so it reads the metadata without
//! `sudo`); the mutating verbs go through `sudo lvextend`/`sudo lvcreate`
//! (narrow sudoers grants — see `packaging/sysknife-sudoers`).
//!
//! **Grow-with-filesystem is one atomic step.** `ExtendLogicalVolume` uses
//! `lvextend -r` (`--resizefs`): LVM's own `lvresize_fs_helper.sh` runs
//! `resize2fs`/`xfs_growfs` after the extent change, and ext4 grows online while
//! mounted (verified via context7 against gitlab.com/lvmteam/lvm2). We
//! deliberately do NOT issue a separate `resize2fs` — that would race the
//! extent change and can only be less safe than the LVM-managed path.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_lvm_report(),
        extend_logical_volume("ubuntu-vg", "ubuntu-lv", "+10G"),
        create_logical_volume("ubuntu-vg", "data", "20G"),
        create_lv_snapshot("ubuntu-vg", "ubuntu-lv", "ubuntu-lv-snap", "5G"),
    ]
}

/// Read-only LV inventory as JSON (`lvs --reportformat json …`).
///
/// Emits name, VG, size, attributes, snapshot origin, and data-usage percent so
/// the caller can answer "how full is this thin volume / snapshot?" without a
/// second call.
pub fn get_lvm_report() -> ActionSpec {
    ActionSpec {
        action_name: "GetLvmReport",
        mechanism: command_mechanism(
            "lvs",
            [
                "--reportformat",
                "json",
                "--units",
                "b",
                "-o",
                "lv_name,vg_name,lv_size,lv_attr,origin,data_percent",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Grow an LV and its filesystem in one step (`sudo lvextend -L <size> -r <vg>/<lv>`).
///
/// `size` is a validated LVM size expression, typically relative (`+10G`) but an
/// absolute target (`50G`) is also accepted. `-r` resizes the filesystem after
/// the extent change (see module docs).
pub fn extend_logical_volume(vg: &str, lv: &str, size: &str) -> ActionSpec {
    ActionSpec {
        action_name: "ExtendLogicalVolume",
        mechanism: command_mechanism(
            "sudo",
            ["lvextend", "-L", size, "-r", &format!("{vg}/{lv}")],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Create a new LV in a volume group (`sudo lvcreate -L <size> -n <name> <vg>`).
pub fn create_logical_volume(vg: &str, name: &str, size: &str) -> ActionSpec {
    ActionSpec {
        action_name: "CreateLogicalVolume",
        mechanism: command_mechanism("sudo", ["lvcreate", "-L", size, "-n", name, vg]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Snapshot an existing LV (`sudo lvcreate -s -L <size> -n <snapshot> <vg>/<origin>`).
///
/// `size` is the copy-on-write space reserved for the snapshot, not the size of
/// the origin.
pub fn create_lv_snapshot(vg: &str, origin: &str, snapshot: &str, size: &str) -> ActionSpec {
    ActionSpec {
        action_name: "CreateLvSnapshot",
        mechanism: command_mechanism(
            "sudo",
            [
                "lvcreate",
                "-s",
                "-L",
                size,
                "-n",
                snapshot,
                &format!("{vg}/{origin}"),
            ],
        ),
        risk_level: RiskLevel::Medium,
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
    fn report_is_read_only_json() {
        let spec = get_lvm_report();
        let (program, args) = args_of(&spec);
        assert_eq!(program, "lvs");
        assert!(args.contains(&"--reportformat".to_string()));
        assert!(args.contains(&"json".to_string()));
        assert_eq!(spec.risk_level, RiskLevel::Low);
    }

    #[test]
    fn extend_uses_resizefs_flag_and_vg_lv_ref() {
        let spec = extend_logical_volume("ubuntu-vg", "root", "+10G");
        let (program, args) = args_of(&spec);
        assert_eq!(program, "sudo");
        assert_eq!(args, vec!["lvextend", "-L", "+10G", "-r", "ubuntu-vg/root"]);
        assert_eq!(spec.risk_level, RiskLevel::High);
    }

    #[test]
    fn create_lv_and_snapshot_shapes() {
        let (_, create) = args_of(&create_logical_volume("vg0", "data", "20G"));
        assert_eq!(create, vec!["lvcreate", "-L", "20G", "-n", "data", "vg0"]);

        let (_, snap) = args_of(&create_lv_snapshot("vg0", "root", "root-snap", "5G"));
        assert_eq!(
            snap,
            vec!["lvcreate", "-s", "-L", "5G", "-n", "root-snap", "vg0/root"]
        );
    }
}
