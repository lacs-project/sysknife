//! Removing a kernel argument is a policy decision, not a free operation.
//!
//! Both boot-line editors — `SetKernelArguments` (rpm-ostree, Fedora) and
//! `GrubSetKargs` (GRUB, Debian) — screened only the ADD list, on the stated
//! premise that "removing a dangerous arg is always safe". The premise inverts
//! the actual risk: the dangerous move is removing a *protective* arg. Stripping
//! `module.sig_enforce=1` reaches the same end state as adding an unsigned-module
//! loader, and the add-path already refuses that.
//!
//! These tests pin the screen at the executor boundary, where both editors and
//! every caller of `build_action_spec` must pass through it.

use serde_json::json;
use sysknife_daemon::executor::{build_action_spec, ExecutorError};

/// Arguments whose protection is their presence. Removing any one of them is a
/// boot-security downgrade, so both editors must refuse.
const PROTECTIVE: &[&str] = &[
    "lockdown=confidentiality",
    "module.sig_enforce=1",
    "selinux=1",
    "enforcing=1",
    "pti=on",
    "mitigations=auto,nosmt",
    "init_on_alloc=1",
    "slab_nomerge",
    "randomize_kstack_offset=on",
    "vsyscall=none",
];

/// Arguments that are themselves a weakening. The add-path refuses them, so
/// removal must stay possible or SysKnife could never harden a host that already
/// boots with one.
const WEAKENING: &[&str] = &["mitigations=off", "selinux=0", "pti=off", "init=/bin/sh"];

// `GrubSetKargs` runs its arguments through `validated_safe_arg`, whose charset
// excludes `=`, so that action can only ever carry bare tokens — the `key=value`
// sets above are unrepresentable there. These are the charset-legal members of
// each class, so the GRUB tests isolate the removal screen instead of tripping
// over the charset check first.
const PROTECTIVE_BARE: &[&str] = &["slab_nomerge", "nosmt", "kaslr"];
const WEAKENING_BARE: &[&str] = &["single", "nosmap", "nosmep"];

#[test]
fn set_kernel_arguments_refuses_to_remove_a_protective_arg() {
    for arg in PROTECTIVE {
        let params = json!({ "add": [], "remove": [arg] });
        let result = build_action_spec("SetKernelArguments", &params);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("remove"))),
            "SetKernelArguments must refuse to remove {arg}, got {result:?}"
        );
    }
}

#[test]
fn set_kernel_arguments_still_removes_a_weakening_arg() {
    for arg in WEAKENING {
        let params = json!({ "add": [], "remove": [arg] });
        assert!(
            build_action_spec("SetKernelArguments", &params).is_ok(),
            "SetKernelArguments must still be able to remove {arg}"
        );
    }
}

#[test]
fn grub_set_kargs_refuses_to_delete_a_protective_arg() {
    for arg in PROTECTIVE_BARE {
        let params = json!({ "append": [], "delete": [arg] });
        let result = build_action_spec("GrubSetKargs", &params);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("delete"))),
            "GrubSetKargs must refuse to delete {arg}, got {result:?}"
        );
    }
}

#[test]
fn grub_set_kargs_still_deletes_a_weakening_arg() {
    for arg in WEAKENING_BARE {
        let params = json!({ "append": [], "delete": [arg] });
        assert!(
            build_action_spec("GrubSetKargs", &params).is_ok(),
            "GrubSetKargs must still be able to delete {arg}"
        );
    }
}

/// Two lists encode the same idea — "units that hand back a root shell" — and
/// they drifted. `validate.rs::ROOT_SHELL_UNITS` blocks activating
/// `debug-shell` and `runlevel1`; `executor.rs::BLOCKED_UNIT_PREFIXES` did not
/// block booting into them via `systemd.unit=`.
///
/// So `StartService debug-shell.service` was refused while
/// `SetKernelArguments add=["systemd.unit=debug-shell.service"]` was accepted —
/// and the second one is worse, because it persists across a reboot and hands
/// out a root shell on tty9 before anyone logs in.
#[test]
fn no_root_shell_unit_can_be_reached_through_a_kernel_argument() {
    for unit in [
        "systemd.unit=emergency.target",
        "systemd.unit=rescue.target",
        "systemd.unit=single",
        "systemd.unit=debug-shell.service",
        "systemd.unit=runlevel1.target",
        // Case must not launder it.
        "systemd.unit=Debug-Shell.service",
    ] {
        let params = json!({ "add": [unit], "remove": [] });
        let result = build_action_spec("SetKernelArguments", &params);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("add"))),
            "{unit} boots the host into a root shell and must be refused, got {result:?}"
        );
    }
}

/// The drift guard. Two screens refuse root-shell units from opposite
/// directions: one refuses to START such a unit, the other refuses to BOOT into
/// it via `systemd.unit=`. They are only as good as the weaker list, so this
/// asserts every unit blocked on one path is blocked on the other.
///
/// Without this, the lists agree today and silently diverge the next time
/// somebody adds a unit to one of them — which is exactly how `debug-shell` came
/// to be refused by `StartService` and accepted by `SetKernelArguments`.
#[test]
fn the_two_root_shell_screens_cannot_drift_apart() {
    for unit in ["debug-shell", "emergency", "rescue", "runlevel1", "single"] {
        // Boot path: as a kernel argument.
        let karg = json!({ "add": [format!("systemd.unit={unit}.target")], "remove": [] });
        assert!(
            build_action_spec("SetKernelArguments", &karg).is_err(),
            "{unit} is reachable as a kernel argument"
        );

        // Activation path: as a unit to start. `single` is not a real unit, so
        // it is exempt from this half — the shared list is a superset.
        if unit == "single" {
            continue;
        }
        let start = json!({ "unit": format!("{unit}.service") });
        assert!(
            build_action_spec("StartService", &start).is_err(),
            "{unit} is startable as a service"
        );
    }
}
