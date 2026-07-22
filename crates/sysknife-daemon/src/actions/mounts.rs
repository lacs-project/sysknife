//! Filesystem mount + swap actions.
//!
//! `GetMounts` is a read-only inventory (`findmnt --json`). The four mutating
//! actions (`AddMount`, `RemoveMount`, `AddSwap`, `RemoveSwap`) all delegate to
//! the root-owned helper `/usr/lib/sysknife/mount-edit`, which keeps `/etc/fstab`
//! in sync and — crucially — writes every managed entry with `nofail`, so a bad
//! or absent device can never wedge the boot. See `packaging/sysknife-mount-edit`.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

const HELPER: &str = "/usr/lib/sysknife/mount-edit";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_mounts(),
        add_mount("/dev/sdb1", "/mnt/data", "ext4", Some("defaults")),
        remove_mount("/mnt/data"),
        add_swap("/swapfile", 2048),
        remove_swap("/swapfile"),
    ]
}

/// List mounted filesystems as JSON (`findmnt --json`). Read-only.
pub fn get_mounts() -> ActionSpec {
    ActionSpec {
        action_name: "GetMounts",
        mechanism: command_mechanism("findmnt", ["--json"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Mount a device and persist it to `/etc/fstab` (with `nofail`).
pub fn add_mount(
    device: &str,
    mountpoint: &str,
    fstype: &str,
    options: Option<&str>,
) -> ActionSpec {
    let mut args = vec![
        HELPER.to_string(),
        "--op".to_string(),
        "mount".to_string(),
        "--device".to_string(),
        device.to_string(),
        "--mountpoint".to_string(),
        mountpoint.to_string(),
        "--fstype".to_string(),
        fstype.to_string(),
    ];
    if let Some(opts) = options {
        args.push("--options".to_string());
        args.push(opts.to_string());
    }
    ActionSpec {
        action_name: "AddMount",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Unmount and remove the `/etc/fstab` entry for a mountpoint.
pub fn remove_mount(mountpoint: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveMount",
        mechanism: command_mechanism(
            "sudo",
            [HELPER, "--op", "unmount", "--mountpoint", mountpoint],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Create a swap file, enable it, and persist it to `/etc/fstab`.
pub fn add_swap(file: &str, size_mb: u32) -> ActionSpec {
    let size = size_mb.to_string();
    ActionSpec {
        action_name: "AddSwap",
        mechanism: command_mechanism(
            "sudo",
            [
                HELPER,
                "--op",
                "addswap",
                "--file",
                file,
                "--size-mb",
                &size,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Disable a swap file, remove it, and drop its `/etc/fstab` entry.
pub fn remove_swap(file: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveSwap",
        mechanism: command_mechanism("sudo", [HELPER, "--op", "rmswap", "--file", file]),
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
    fn get_mounts_is_read_only_json() {
        let (program, args) = args_of(&get_mounts());
        assert_eq!(program, "findmnt");
        assert_eq!(args, vec!["--json"]);
        assert_eq!(get_mounts().risk_level, RiskLevel::Low);
    }

    #[test]
    fn add_mount_passes_op_and_optional_options() {
        let (program, args) = args_of(&add_mount(
            "/dev/sdb1",
            "/mnt/data",
            "ext4",
            Some("noatime"),
        ));
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                HELPER,
                "--op",
                "mount",
                "--device",
                "/dev/sdb1",
                "--mountpoint",
                "/mnt/data",
                "--fstype",
                "ext4",
                "--options",
                "noatime"
            ]
        );
        // options omitted → no --options flag
        let (_, no_opts) = args_of(&add_mount("/dev/sdb1", "/mnt/data", "ext4", None));
        assert!(!no_opts.iter().any(|a| a == "--options"));
    }

    #[test]
    fn swap_ops_shapes() {
        let (_, add) = args_of(&add_swap("/swapfile", 2048));
        assert_eq!(
            add,
            vec![
                HELPER,
                "--op",
                "addswap",
                "--file",
                "/swapfile",
                "--size-mb",
                "2048"
            ]
        );
        let (_, rm) = args_of(&remove_swap("/swapfile"));
        assert_eq!(rm, vec![HELPER, "--op", "rmswap", "--file", "/swapfile"]);
        assert_eq!(add_swap("/s", 1).risk_level, RiskLevel::High);
    }
}
