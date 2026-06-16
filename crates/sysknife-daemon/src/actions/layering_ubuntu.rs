//! Ubuntu package management actions (apt-based).
//!
//! These are the Ubuntu equivalents of the rpm-ostree layering actions in
//! [`layering`]. Action *names* are identical — the executor dispatches to
//! this module when [`distro::current()`] returns [`Distro::Ubuntu`].
//!
//! Key differences from Fedora Atomic layering:
//! - Changes take effect **immediately** — no reboot required (`reboot_required: false`).
//! - No deployment staging or rollback — apt writes directly to the live system.
//! - `AddLayeredPackage` / `RemoveLayeredPackage` map to `apt-get install/remove`.
//! - `UpdateSystem` maps to `apt-get dist-upgrade`.
//! - rpm-ostree-specific actions (`RebaseSystem`, `PinDeployment`, rollback ops,
//!   etc.) have no Ubuntu equivalent and are handled in the executor by returning
//!   an unsupported-on-distro error.
//!
//! [`layering`]: super::layering
//! [`distro::current()`]: crate::distro::current
//! [`Distro::Ubuntu`]: crate::distro::Distro::Ubuntu

use super::{command_mechanism, ActionMechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Package install / remove
// ---------------------------------------------------------------------------

/// Install a single package immediately (`apt-get install -y`).
///
/// Ubuntu equivalent of [`layering::add_layered_package`].
///
/// [`layering::add_layered_package`]: super::layering::add_layered_package
pub fn install_package(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AddLayeredPackage",
        mechanism: command_mechanism("sudo", ["apt-get", "install", "-y", package]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a single package (`apt-get remove -y`).
///
/// Ubuntu equivalent of [`layering::remove_layered_package`].
///
/// [`layering::remove_layered_package`]: super::layering::remove_layered_package
pub fn remove_package(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveLayeredPackage",
        mechanism: command_mechanism("sudo", ["apt-get", "remove", "-y", package]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Install multiple packages in a single `apt-get install -y` call.
///
/// Ubuntu equivalent of [`layering::install_packages`].
///
/// [`layering::install_packages`]: super::layering::install_packages
pub fn install_packages(packages: &[&str]) -> ActionSpec {
    let mut args = vec![
        "apt-get".to_string(),
        "install".to_string(),
        "-y".to_string(),
    ];
    args.extend(packages.iter().map(|s| s.to_string()));

    ActionSpec {
        action_name: "InstallPackages",
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args,
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove multiple packages in a single `apt-get remove -y` call.
///
/// Ubuntu equivalent of [`layering::remove_packages`].
///
/// [`layering::remove_packages`]: super::layering::remove_packages
pub fn remove_packages(packages: &[&str]) -> ActionSpec {
    let mut args = vec![
        "apt-get".to_string(),
        "remove".to_string(),
        "-y".to_string(),
    ];
    args.extend(packages.iter().map(|s| s.to_string()));

    ActionSpec {
        action_name: "RemovePackages",
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args,
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
