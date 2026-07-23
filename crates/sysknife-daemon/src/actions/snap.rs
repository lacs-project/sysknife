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
//! via `sh -c "snap install … && snap refresh --hold …"`. `name` and
//! `channel` are validated by [`snap_install`] itself before interpolation
//! (in addition to, not instead of, the executor's own `validated_safe_arg`
//! check) — see the `SnapInstallError` doc below.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Returned when `snap_install`'s `name` or `channel` fails validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapInstallError {
    /// `name`/`channel` contains a shell metacharacter or otherwise fails the
    /// safe-arg allowlist. Carries the offending parameter and value.
    ///
    /// Defense in depth: the executor already validates both via
    /// `validated_safe_arg` before calling this constructor, but the
    /// `auto_update: false` path interpolates `name`/`channel` into a
    /// `sh -c "snap install … && snap refresh --hold …"` fragment — a future
    /// internal Rust caller (fleet plan/execute path) that skipped the
    /// executor could not otherwise be blocked from injecting through it.
    InvalidArg { param: &'static str, value: String },
}

impl std::fmt::Display for SnapInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArg { param, value } => write!(f, "invalid {param}: '{value}'"),
        }
    }
}

impl std::error::Error for SnapInstallError {}

/// Allowlist for `name`/`channel`: alphanumeric plus `._:/+@-`, no leading
/// dash, 1-254 bytes. Mirrors `validated_safe_arg`'s charset exactly, kept as
/// a self-contained check here (rather than depending on `crate::executor`)
/// so this action module has no dependency on the executor's error type —
/// the same pattern `fail2ban::jail_is_valid` uses.
fn safe_snap_arg_is_valid(s: &str) -> bool {
    if s.is_empty() || s.len() > 254 || s.starts_with('-') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '+' | '@' | '-'))
}

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per snap action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        snap_install("firefox", None, false).expect("firefox is a valid snap arg"),
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
///
/// Returns `Err(SnapInstallError::InvalidArg)` if `name` or `channel` fails
/// the safe-arg allowlist — see [`SnapInstallError`].
pub fn snap_install(
    name: &str,
    channel: Option<&str>,
    auto_update: bool,
) -> Result<ActionSpec, SnapInstallError> {
    if !safe_snap_arg_is_valid(name) {
        return Err(SnapInstallError::InvalidArg {
            param: "name",
            value: name.to_string(),
        });
    }
    if let Some(ch) = channel {
        if !safe_snap_arg_is_valid(ch) {
            return Err(SnapInstallError::InvalidArg {
                param: "channel",
                value: ch.to_string(),
            });
        }
    }

    if auto_update {
        // Plain install without hold.
        let mut args = vec!["install".to_string()];
        if let Some(ch) = channel {
            args.push(format!("--channel={}", ch));
        }
        args.push(name.to_string());
        Ok(ActionSpec {
            action_name: "SnapInstall",
            mechanism: command_mechanism(
                "sudo",
                std::iter::once("snap").chain(args.iter().map(String::as_str)),
            ),
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: false,
        })
    } else {
        // Install + hold in one shell fragment to avoid a window where the snap
        // can be auto-refreshed between install and hold.
        let channel_arg = channel.unwrap_or("stable");
        let cmd = format!(
            "snap install --channel={} {} && snap refresh --hold {}",
            channel_arg, name, name
        );
        Ok(ActionSpec {
            action_name: "SnapInstall",
            mechanism: super::command_mechanism("sudo", ["sh", "-c", &cmd]),
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: false,
        })
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
            snap_install("firefox", None, false).unwrap().action_name,
            "SnapInstall"
        );
    }

    #[test]
    fn snap_install_default_includes_hold() {
        let spec = snap_install("firefox", None, false).unwrap();
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
        let spec = snap_install("firefox", None, true).unwrap();
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
        let spec = snap_install("firefox", Some("beta"), false).unwrap();
        let (_, args) = extract_args(&spec);
        let full = args.join(" ");
        assert!(full.contains("beta"), "channel not present: {full}");
    }

    #[test]
    fn snap_install_risk_medium() {
        assert_eq!(
            snap_install("vim", None, false).unwrap().risk_level,
            RiskLevel::Medium
        );
    }

    #[test]
    fn snap_install_rejects_shell_metacharacters_in_name() {
        let err = snap_install("firefox; rm -rf /", None, false).unwrap_err();
        assert!(matches!(
            err,
            SnapInstallError::InvalidArg { param: "name", .. }
        ));
    }

    #[test]
    fn snap_install_rejects_shell_metacharacters_in_channel() {
        let err = snap_install("firefox", Some("beta && evil"), false).unwrap_err();
        assert!(matches!(
            err,
            SnapInstallError::InvalidArg {
                param: "channel",
                ..
            }
        ));
    }

    #[test]
    fn snap_install_rejects_leading_dash_name() {
        // Option-injection guard: mirrors validated_safe_arg's leading-dash rule.
        let err = snap_install("--classic", None, false).unwrap_err();
        assert!(matches!(
            err,
            SnapInstallError::InvalidArg { param: "name", .. }
        ));
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
