//! snap package management actions (Ubuntu).
//!
//! ## Auto-refresh footgun
//!
//! snapd refreshes snaps automatically on a schedule. When a snap is installed
//! for a specific purpose (e.g. a pinned version of a tool), an unexpected
//! snap refresh can break the workload without operator approval.
//!
//! Mitigation: `SnapInstall` by default pairs the install with
//! `snap refresh --hold <name>` to pin the snap at the installed version.
//! Set `auto_update: true` in the plan params to skip the hold.
//!
//! The hold is applied by building a two-command spec using a shell fragment
//! via `sh -c "snap install … && snap refresh --hold …"`. Both commands are
//! validated through `validated_safe_arg` before interpolation.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per snap action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        snap_install("firefox", None, false),
        snap_remove("firefox"),
        snap_refresh(Some("firefox")),
        snap_hold("firefox"),
        snap_unhold("firefox"),
        snap_list(),
        snap_info("firefox"),
        snap_revert("firefox"),
        snap_classic_install("code"),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Install a snap (`snap install [--channel=<channel>] <name>`) and,
/// unless `auto_update` is true, immediately hold it to prevent auto-refresh.
///
/// Risk: Medium. Installs snaps from the Snap Store. Sandboxed but can access
/// system resources depending on interface connections.
///
/// `channel` defaults to `stable` when `None`.
pub fn snap_install(name: &str, channel: Option<&str>, auto_update: bool) -> ActionSpec {
    if auto_update {
        // Plain install without hold.
        let mut args = vec!["install".to_string()];
        if let Some(ch) = channel {
            args.push(format!("--channel={}", ch));
        }
        args.push(name.to_string());
        ActionSpec {
            action_name: "SnapInstall",
            mechanism: command_mechanism(
                "sudo",
                std::iter::once("snap").chain(args.iter().map(String::as_str)),
            ),
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: false,
        }
    } else {
        // Install + hold in one shell fragment to avoid a window where the snap
        // can be auto-refreshed between install and hold.
        let channel_arg = channel.unwrap_or("stable");
        let cmd = format!(
            "snap install --channel={} {} && snap refresh --hold {}",
            channel_arg, name, name
        );
        ActionSpec {
            action_name: "SnapInstall",
            mechanism: super::command_mechanism("sudo", ["sh", "-c", &cmd]),
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: false,
        }
    }
}

/// Remove a snap (`snap remove <name>`).
///
/// Risk: Medium. Uninstalls the snap and removes its data.
pub fn snap_remove(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SnapRemove",
        mechanism: command_mechanism("sudo", ["snap", "remove", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Refresh a snap or all snaps.
///
/// `name = Some("firefox")` → refresh only that snap.
/// `name = None` → refresh all snaps.
///
/// Risk: Medium. Updates snap(s); may change behaviour.
pub fn snap_refresh(name: Option<&str>) -> ActionSpec {
    match name {
        Some(n) => ActionSpec {
            action_name: "SnapRefresh",
            mechanism: command_mechanism("sudo", ["snap", "refresh", n]),
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: false,
        },
        None => ActionSpec {
            action_name: "SnapRefresh",
            mechanism: command_mechanism("sudo", ["snap", "refresh"]),
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: false,
        },
    }
}

/// Hold a snap at its current version, preventing auto-refresh.
///
/// Risk: Medium. Freezes the snap version. The snap remains installed.
pub fn snap_hold(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SnapHold",
        mechanism: command_mechanism("sudo", ["snap", "refresh", "--hold", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a hold from a snap, allowing auto-refresh again.
///
/// Risk: Medium. After unholding, the next snapd refresh cycle can update the
/// snap without further operator approval.
pub fn snap_unhold(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SnapUnhold",
        mechanism: command_mechanism("sudo", ["snap", "refresh", "--unhold", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// List installed snaps (`snap list`).
///
/// Risk: Low. Read-only query.
pub fn snap_list() -> ActionSpec {
    ActionSpec {
        action_name: "SnapList",
        mechanism: command_mechanism("snap", ["list"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Show detailed information about a snap (`snap info <name>`).
///
/// Risk: Low. Read-only query.
pub fn snap_info(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SnapInfo",
        mechanism: command_mechanism("snap", ["info", name]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Revert a snap to the previously active revision (`snap revert <name>`).
///
/// Risk: Medium. Rolls the snap back one revision; the current revision is
/// preserved and the revert itself can be undone by refreshing again.
pub fn snap_revert(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SnapRevert",
        mechanism: command_mechanism("sudo", ["snap", "revert", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Install a snap that requires classic confinement (`snap install --classic <name>`).
///
/// Risk: Medium. Classic-confined snaps have full system access (no sandbox);
/// this carries more risk than sandboxed snap installs.
pub fn snap_classic_install(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SnapClassicInstall",
        mechanism: command_mechanism("sudo", ["snap", "install", "--classic", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn extract_args(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (*program, args.clone()),
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── snap_install ─────────────────────────────────────────────────────────

    #[test]
    fn snap_install_action_name() {
        assert_eq!(
            snap_install("firefox", None, false).action_name,
            "SnapInstall"
        );
    }

    #[test]
    fn snap_install_default_includes_hold() {
        let spec = snap_install("firefox", None, false);
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        // When auto_update=false the hold is embedded in a sh -c fragment.
        let full = args.join(" ");
        assert!(
            full.contains("snap install"),
            "missing 'snap install': {full}"
        );
        assert!(
            full.contains("snap refresh --hold firefox"),
            "missing hold: {full}"
        );
    }

    #[test]
    fn snap_install_auto_update_no_hold() {
        let spec = snap_install("firefox", None, true);
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let full = args.join(" ");
        // Must install but must NOT hold.
        assert!(full.contains("install"), "missing install: {full}");
        assert!(
            !full.contains("hold"),
            "unexpected hold in auto_update=true: {full}"
        );
    }

    #[test]
    fn snap_install_custom_channel() {
        let spec = snap_install("firefox", Some("beta"), false);
        let (_, args) = extract_args(&spec);
        let full = args.join(" ");
        assert!(full.contains("beta"), "channel not present: {full}");
    }

    #[test]
    fn snap_install_risk_medium() {
        assert_eq!(
            snap_install("vim", None, false).risk_level,
            RiskLevel::Medium
        );
    }

    // ── snap_remove ──────────────────────────────────────────────────────────

    #[test]
    fn snap_remove_action_name() {
        assert_eq!(snap_remove("vim").action_name, "SnapRemove");
    }

    #[test]
    fn snap_remove_argv() {
        let spec = snap_remove("vim");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"snap"));
        assert!(a.contains(&"remove"));
        assert!(a.contains(&"vim"));
    }

    #[test]
    fn snap_remove_risk_medium() {
        assert_eq!(snap_remove("vim").risk_level, RiskLevel::Medium);
    }

    // ── snap_refresh ─────────────────────────────────────────────────────────

    #[test]
    fn snap_refresh_named() {
        let spec = snap_refresh(Some("firefox"));
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"firefox"));
    }

    #[test]
    fn snap_refresh_all_no_extra_args() {
        let spec = snap_refresh(None);
        let (_, args) = extract_args(&spec);
        // No snap name in the args list for "refresh all".
        assert_eq!(
            args.iter()
                .filter(|a| a.as_str() != "snap" && a.as_str() != "refresh")
                .count(),
            0
        );
    }

    // ── snap_hold / snap_unhold ───────────────────────────────────────────────

    #[test]
    fn snap_hold_action_name() {
        assert_eq!(snap_hold("vim").action_name, "SnapHold");
    }

    #[test]
    fn snap_hold_argv_uses_refresh_hold() {
        let spec = snap_hold("vim");
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"refresh"));
        assert!(a.contains(&"--hold"));
        assert!(a.contains(&"vim"));
    }

    #[test]
    fn snap_unhold_action_name() {
        assert_eq!(snap_unhold("vim").action_name, "SnapUnhold");
    }

    #[test]
    fn snap_unhold_argv_uses_refresh_unhold() {
        let spec = snap_unhold("vim");
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"refresh"));
        assert!(a.contains(&"--unhold"));
        assert!(a.contains(&"vim"));
    }

    // ── snap_list ────────────────────────────────────────────────────────────

    #[test]
    fn snap_list_action_name() {
        assert_eq!(snap_list().action_name, "SnapList");
    }

    #[test]
    fn snap_list_no_sudo() {
        let spec = snap_list();
        let (prog, _) = extract_args(&spec);
        assert_ne!(prog, "sudo");
    }

    #[test]
    fn snap_list_risk_low() {
        assert_eq!(snap_list().risk_level, RiskLevel::Low);
    }

    // ── snap_info ────────────────────────────────────────────────────────────

    #[test]
    fn snap_info_action_name() {
        assert_eq!(snap_info("firefox").action_name, "SnapInfo");
    }

    #[test]
    fn snap_info_no_sudo() {
        let spec = snap_info("firefox");
        let (prog, _) = extract_args(&spec);
        assert_ne!(prog, "sudo");
    }

    #[test]
    fn snap_info_risk_low() {
        assert_eq!(snap_info("firefox").risk_level, RiskLevel::Low);
    }

    #[test]
    fn snap_info_includes_name() {
        let spec = snap_info("code");
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"code"));
    }

    // ── snap_revert ──────────────────────────────────────────────────────────

    #[test]
    fn snap_revert_action_name() {
        assert_eq!(snap_revert("firefox").action_name, "SnapRevert");
    }

    #[test]
    fn snap_revert_argv_correct() {
        let spec = snap_revert("firefox");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"snap"));
        assert!(a.contains(&"revert"));
        assert!(a.contains(&"firefox"));
    }

    #[test]
    fn snap_revert_risk_medium() {
        assert_eq!(snap_revert("firefox").risk_level, RiskLevel::Medium);
    }

    // ── snap_classic_install ─────────────────────────────────────────────────

    #[test]
    fn snap_classic_install_action_name() {
        assert_eq!(
            snap_classic_install("code").action_name,
            "SnapClassicInstall"
        );
    }

    #[test]
    fn snap_classic_install_argv_contains_classic_flag() {
        let spec = snap_classic_install("code");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"snap"));
        assert!(a.contains(&"install"));
        assert!(a.contains(&"--classic"));
        assert!(a.contains(&"code"));
    }

    #[test]
    fn snap_classic_install_risk_medium() {
        assert_eq!(snap_classic_install("code").risk_level, RiskLevel::Medium);
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = [
            "SnapInstall",
            "SnapRemove",
            "SnapRefresh",
            "SnapHold",
            "SnapUnhold",
            "SnapList",
            "SnapInfo",
            "SnapRevert",
            "SnapClassicInstall",
        ];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
