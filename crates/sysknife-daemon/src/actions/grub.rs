//! GRUB kernel argument actions (Ubuntu).
//!
//! ## GrubGetKargs
//!
//! Read-only inspection of `GRUB_CMDLINE_LINUX` in `/etc/default/grub`.
//! No system changes are made.
//!
//! ## GrubSetKargs
//!
//! Modifies `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`, then runs
//! `update-grub` to regenerate the GRUB config.
//!
//! **Backup:** before the edit, the current `/etc/default/grub` is backed up
//! to `/etc/default/grub.sysknife.bak` by the helper.  On `update-grub`
//! failure the helper restores the backup automatically.
//!
//! **Helper script:** the entire operation is delegated to the root-owned
//! helper script `/usr/lib/sysknife/grub-kargs-edit` (installed from
//! `packaging/sysknife-grub-kargs-edit`).  This replaces the previous
//! `bash -c` pipeline approach and eliminates the three unconstrained sudo
//! grants for `python3`, `cp`, and `update-grub` (red-team HI1/HI2/HI3).
//! The sudoers entry grants NOPASSWD only on the exact helper path:
//!   `sysknife ALL=(root) NOPASSWD: /usr/lib/sysknife/grub-kargs-edit *`
//!
//! **Reboot required:** kernel argument changes do not take effect until the
//! next boot.
//!
//! **Params:**
//! - `append`: `Vec<String>` — args to add (merged into the existing line).
//! - `delete`: `Vec<String>` — args to remove from the existing line.
//!   Either list may be empty; at least one must be non-empty.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Installed path of the privileged GRUB kargs helper script.
///
/// The helper is installed to this path with mode 0755 and owned by root.
/// See `packaging/sysknife-grub-kargs-edit` for the source and
/// `packaging/sysknife-sudoers` for the corresponding NOPASSWD grant.
const GRUB_KARGS_HELPER: &str = "/usr/lib/sysknife/grub-kargs-edit";

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per GRUB action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        grub_get_kargs(),
        grub_set_kargs(&["quiet"], &["splash"]).expect("non-empty kargs"),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Read the `GRUB_CMDLINE_LINUX` line from `/etc/default/grub`.
///
/// Risk: Low. Read-only file inspection; no system changes.
pub fn grub_get_kargs() -> ActionSpec {
    ActionSpec {
        action_name: "GrubGetKargs",
        mechanism: command_mechanism("grep", ["-E", r"^GRUB_CMDLINE_LINUX", "/etc/default/grub"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Modify kernel arguments in `GRUB_CMDLINE_LINUX_DEFAULT`, back up the
/// original file, then run `update-grub`.
///
/// Risk: High. Kernel argument changes affect every boot. Incorrect arguments
/// can prevent the system from booting. The helper script writes a backup to
/// `/etc/default/grub.sysknife.bak` and restores it on `update-grub` failure.
///
/// `append` — arguments to add (validated before call).
/// `delete` — arguments to remove (validated before call).
///
/// At least one of `append` / `delete` MUST be non-empty — calling with both
/// empty is a no-op that still rewrites the GRUB config and runs `update-grub`,
/// which is wasteful and misleading. The constructor returns
/// `Err(KargsError::BothEmpty)` in that case.
///
/// The underlying mechanism is a single `sudo` invocation of the root-owned
/// helper script `GRUB_KARGS_HELPER` (no shell involved), which closes the
/// unconstrained `python3`, `cp`, and `update-grub` sudoers grants.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KargsError {
    #[error("at least one of append or delete must be non-empty")]
    BothEmpty,
}

pub fn grub_set_kargs(append: &[&str], delete: &[&str]) -> Result<ActionSpec, KargsError> {
    if append.is_empty() && delete.is_empty() {
        return Err(KargsError::BothEmpty);
    }

    // The helper accepts comma-separated lists. Empty list → empty string after
    // the flag (the helper treats "" as "no tokens in this set").
    let append_csv = append.join(",");
    let delete_csv = delete.join(",");

    Ok(ActionSpec {
        action_name: "GrubSetKargs",
        mechanism: command_mechanism(
            "sudo",
            [
                GRUB_KARGS_HELPER,
                "--append",
                &append_csv,
                "--delete",
                &delete_csv,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn extract_cmd(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (*program, args.clone()),
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── grub_get_kargs ────────────────────────────────────────────────────────

    #[test]
    fn grub_get_kargs_action_name() {
        assert_eq!(grub_get_kargs().action_name, "GrubGetKargs");
    }

    #[test]
    fn grub_get_kargs_uses_grep_on_grub_default() {
        let spec = grub_get_kargs();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "grep");
        let joined = args.join(" ");
        assert!(
            joined.contains("/etc/default/grub"),
            "missing grub path: {joined}"
        );
        assert!(
            joined.contains("GRUB_CMDLINE_LINUX"),
            "missing pattern: {joined}"
        );
    }

    #[test]
    fn grub_get_kargs_risk_is_low() {
        assert_eq!(grub_get_kargs().risk_level, RiskLevel::Low);
    }

    #[test]
    fn grub_get_kargs_no_reboot_no_rollback() {
        let spec = grub_get_kargs();
        assert!(!spec.reboot_required);
        assert!(!spec.rollback_available);
    }

    // ── grub_set_kargs ────────────────────────────────────────────────────────

    #[test]
    fn grub_set_kargs_action_name() {
        assert_eq!(
            grub_set_kargs(&["quiet"], &[]).unwrap().action_name,
            "GrubSetKargs"
        );
    }

    #[test]
    fn grub_set_kargs_invokes_sudo_helper() {
        // The mechanism must be: program=sudo, args[0]=GRUB_KARGS_HELPER.
        // No bash, no python3, no cp — those are now inside the helper itself.
        let spec = grub_set_kargs(&["quiet"], &["splash"]).unwrap();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo", "program must be sudo");
        assert_eq!(
            args[0], GRUB_KARGS_HELPER,
            "first arg must be the helper path"
        );
    }

    #[test]
    fn grub_set_kargs_argv_shape_append_only() {
        // sudo /usr/lib/sysknife/grub-kargs-edit --append quiet --delete ""
        let spec = grub_set_kargs(&["quiet"], &[]).unwrap();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args[0], GRUB_KARGS_HELPER);
        assert_eq!(args[1], "--append");
        assert_eq!(args[2], "quiet");
        assert_eq!(args[3], "--delete");
        assert_eq!(args[4], "");
    }

    #[test]
    fn grub_set_kargs_argv_shape_delete_only() {
        // sudo /usr/lib/sysknife/grub-kargs-edit --append "" --delete splash
        let spec = grub_set_kargs(&[], &["splash"]).unwrap();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args[0], GRUB_KARGS_HELPER);
        assert_eq!(args[1], "--append");
        assert_eq!(args[2], "");
        assert_eq!(args[3], "--delete");
        assert_eq!(args[4], "splash");
    }

    #[test]
    fn grub_set_kargs_argv_shape_both() {
        // Multiple kargs join as comma-separated CSV.
        let spec = grub_set_kargs(&["nomodeset", "quiet"], &["splash", "quiet"]).unwrap();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args[0], GRUB_KARGS_HELPER);
        assert_eq!(args[2], "nomodeset,quiet", "append CSV");
        assert_eq!(args[4], "splash,quiet", "delete CSV");
    }

    #[test]
    fn grub_set_kargs_risk_is_high() {
        assert_eq!(
            grub_set_kargs(&["quiet"], &[]).unwrap().risk_level,
            RiskLevel::High
        );
    }

    #[test]
    fn grub_set_kargs_reboot_required() {
        assert!(grub_set_kargs(&["quiet"], &[]).unwrap().reboot_required);
    }

    #[test]
    fn grub_set_kargs_rollback_available() {
        assert!(grub_set_kargs(&["quiet"], &[]).unwrap().rollback_available);
    }

    #[test]
    fn grub_set_kargs_rejects_both_empty() {
        // The constructor — not just the executor — enforces "at least one of
        // append/delete must be non-empty". A direct Rust caller can't bypass.
        let err = grub_set_kargs(&[], &[]).unwrap_err();
        assert_eq!(err, KargsError::BothEmpty);
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["GrubGetKargs", "GrubSetKargs"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
