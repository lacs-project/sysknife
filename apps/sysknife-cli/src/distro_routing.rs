//! Distro-family routing guard for action names.
//!
//! Some actions in the SysKnife catalogue are distro-specific — they are only
//! meaningful on a particular package-manager family:
//!
//! - `Apt*`, `Snap*`, `Ufw*`, `Distrobox*`, `Netplan*` require a Debian-family
//!   distro (Ubuntu or Debian).
//! - rpm-ostree shaped actions (`RebaseSystem`, `AddLayeredPackage`, …) require
//!   a Fedora-family distro.
//!
//! [`check_action_distro`] returns a human-readable error when a plan step's
//! action name is incompatible with the detected distro.  It is called after
//! planning, before execution, so the user sees a clear message instead of a
//! cryptic daemon error.

use sysknife_core::distro::{DistroFamily, DistroId};

// ---------------------------------------------------------------------------
// Action families
// ---------------------------------------------------------------------------

/// Action names that are only valid on Debian-family distros.
///
/// Grouped by underlying tool: apt, snap, ufw, distrobox, netplan.
const DEBIAN_ONLY_ACTIONS: &[&str] = &[
    // apt
    "AptUpdate",
    "AptUpgrade",
    "AptInstall",
    "AptRemove",
    "AptPurge",
    "AptAutoremove",
    "AptHold",
    "AptUnhold",
    "AptSearch",
    "AptListInstalled",
    "AptShow",
    // snap
    "SnapInstall",
    "SnapRemove",
    "SnapRefresh",
    "SnapHold",
    "SnapUnhold",
    "SnapList",
    "SnapInfo",
    // ufw
    "UfwEnable",
    "UfwDisable",
    "UfwAllow",
    "UfwDeny",
    "UfwReset",
    "UfwStatus",
    // distrobox
    "DistroboxList",
    "DistroboxCreate",
    "DistroboxRemove",
    // netplan
    "NetplanGetConfig",
    "NetplanApply",
];

/// Action names that are only valid on Fedora-family distros.
///
/// These are rpm-ostree or DNF shaped actions.
const FEDORA_ONLY_ACTIONS: &[&str] = &[
    "RebaseSystem",
    "AddLayeredPackage",
    "RemoveLayeredPackage",
    "ReplaceLayeredPackage",
    "RemoveBasePackage",
    "ResetLayeredPackageOverride",
    "GetLayeredPackages",
    "GetDeploymentHistory",
    "ListDeployments",
    "CleanupDeployments",
    "RollbackDeployment",
    "PinDeployment",
    "UnpinDeployment",
    "GetKernelArguments",
    "SetKernelArguments",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether `action_name` is compatible with `distro`.
///
/// Returns `Ok(())` when the action is generic (valid on all distros), or when
/// the action's required family matches `distro`'s family.
///
/// Returns `Err(String)` with a human-readable routing error when the action
/// is family-restricted and `distro` is from the wrong family.
///
/// When `distro` is `None` (detection failed), all actions are allowed — the
/// daemon will surface the real error at execution time.
pub fn check_action_distro(action_name: &str, distro: Option<&DistroId>) -> Result<(), String> {
    let distro = match distro {
        Some(d) => d,
        None => return Ok(()), // detection failed; let daemon handle it
    };

    let family = distro.family();

    if DEBIAN_ONLY_ACTIONS.contains(&action_name) && family != DistroFamily::Debian {
        return Err(format!(
            "{action_name} is only valid on Debian-family distros (apt/snap/ufw); \
             current distro is {distro} ({family_name})",
            family_name = family_label(&family),
        ));
    }

    if FEDORA_ONLY_ACTIONS.contains(&action_name) && family != DistroFamily::Fedora {
        return Err(format!(
            "{action_name} is only valid on Fedora-family distros (rpm-ostree/dnf); \
             current distro is {distro} ({family_name})",
            family_name = family_label(&family),
        ));
    }

    Ok(())
}

fn family_label(f: &DistroFamily) -> &'static str {
    match f {
        DistroFamily::Fedora => "Fedora family",
        DistroFamily::Debian => "Debian family",
        DistroFamily::Other => "unknown family",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sysknife_core::distro::DistroId;

    // -----------------------------------------------------------------------
    // Fedora routing
    // -----------------------------------------------------------------------

    #[test]
    fn apt_install_on_fedora_returns_error() {
        let distro = DistroId::Fedora { version: 41 };
        let result = check_action_distro("AptInstall", Some(&distro));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Debian-family"),
            "error must mention Debian-family; got: {msg}"
        );
        assert!(
            msg.contains("Fedora 41"),
            "error must mention current distro; got: {msg}"
        );
    }

    #[test]
    fn snap_install_on_fedora_silverblue_returns_error() {
        let distro = DistroId::FedoraSilverblue { version: 41 };
        let result = check_action_distro("SnapInstall", Some(&distro));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Debian-family"), "got: {msg}");
        assert!(msg.contains("FedoraSilverblue 41"), "got: {msg}");
    }

    #[test]
    fn ufw_allow_on_fedora_returns_error() {
        let distro = DistroId::Fedora { version: 41 };
        let result = check_action_distro("UfwAllow", Some(&distro));
        assert!(result.is_err());
    }

    #[test]
    fn netplan_apply_on_fedora_returns_error() {
        let distro = DistroId::Fedora { version: 41 };
        let result = check_action_distro("NetplanApply", Some(&distro));
        assert!(result.is_err());
    }

    #[test]
    fn distrobox_create_on_fedora_returns_error() {
        let distro = DistroId::Fedora { version: 41 };
        let result = check_action_distro("DistroboxCreate", Some(&distro));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Ubuntu routing
    // -----------------------------------------------------------------------

    #[test]
    fn apt_install_on_ubuntu_is_ok() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        assert!(check_action_distro("AptInstall", Some(&distro)).is_ok());
    }

    #[test]
    fn snap_install_on_ubuntu_is_ok() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        assert!(check_action_distro("SnapInstall", Some(&distro)).is_ok());
    }

    #[test]
    fn rebase_system_on_ubuntu_returns_error() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        let result = check_action_distro("RebaseSystem", Some(&distro));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Fedora-family"), "got: {msg}");
        assert!(msg.contains("Ubuntu 24.04"), "got: {msg}");
    }

    #[test]
    fn add_layered_package_on_ubuntu_returns_error() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        let result = check_action_distro("AddLayeredPackage", Some(&distro));
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // UnknownDistro / None passes through
    // -----------------------------------------------------------------------

    #[test]
    fn no_distro_allows_all_actions() {
        // When detection failed, we must not block execution.
        assert!(check_action_distro("AptInstall", None).is_ok());
        assert!(check_action_distro("RebaseSystem", None).is_ok());
        assert!(check_action_distro("GetSystemState", None).is_ok());
    }

    // -----------------------------------------------------------------------
    // Generic actions are allowed everywhere
    // -----------------------------------------------------------------------

    #[test]
    fn get_system_state_allowed_on_fedora() {
        let distro = DistroId::Fedora { version: 41 };
        assert!(check_action_distro("GetSystemState", Some(&distro)).is_ok());
    }

    #[test]
    fn get_system_state_allowed_on_ubuntu() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        assert!(check_action_distro("GetSystemState", Some(&distro)).is_ok());
    }

    #[test]
    fn install_flatpak_allowed_on_fedora() {
        let distro = DistroId::Fedora { version: 41 };
        assert!(check_action_distro("InstallFlatpak", Some(&distro)).is_ok());
    }

    #[test]
    fn install_flatpak_allowed_on_ubuntu() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        assert!(check_action_distro("InstallFlatpak", Some(&distro)).is_ok());
    }

    // -----------------------------------------------------------------------
    // All Debian-only actions reject Fedora
    // -----------------------------------------------------------------------

    #[test]
    fn all_debian_only_actions_rejected_on_fedora() {
        let distro = DistroId::Fedora { version: 41 };
        for action in super::DEBIAN_ONLY_ACTIONS {
            let result = check_action_distro(action, Some(&distro));
            assert!(
                result.is_err(),
                "{action} should be rejected on Fedora but was allowed"
            );
        }
    }

    #[test]
    fn all_fedora_only_actions_rejected_on_ubuntu() {
        let distro = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        for action in super::FEDORA_ONLY_ACTIONS {
            let result = check_action_distro(action, Some(&distro));
            assert!(
                result.is_err(),
                "{action} should be rejected on Ubuntu but was allowed"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Display impl for DistroId
    // -----------------------------------------------------------------------

    #[test]
    fn distro_id_display_fedora() {
        assert_eq!(format!("{}", DistroId::Fedora { version: 41 }), "Fedora 41");
    }

    #[test]
    fn distro_id_display_fedora_silverblue() {
        assert_eq!(
            format!("{}", DistroId::FedoraSilverblue { version: 41 }),
            "FedoraSilverblue 41"
        );
    }

    #[test]
    fn distro_id_display_ubuntu() {
        assert_eq!(
            format!(
                "{}",
                DistroId::Ubuntu {
                    major: 24,
                    minor: 4
                }
            ),
            "Ubuntu 24.04"
        );
    }

    #[test]
    fn distro_id_display_debian() {
        assert_eq!(
            format!("{}", DistroId::Debian { version: Some(12) }),
            "Debian 12"
        );
    }
}
