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
