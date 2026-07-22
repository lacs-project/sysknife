//! Canonical mapping of action names to the distro family they require.
//!
//! # Why this lives in `sysknife-core`
//!
//! Three components need to know which actions are family-specific:
//!
//! - `sysknife-brain` (`prompt.rs`) — per-distro prompt isolation.
//! - `sysknife-cli` (`distro_routing.rs`) — client-side routing guard.
//! - `sysknife-daemon` (`dispatcher.rs`) — the privileged execution fence.
//!
//! Keeping three hand-maintained copies caused the daemon fence to silently
//! drift out of parity with the authoritative prompt list, so a Debian-only
//! mutating action could reach a supported Fedora host without a family
//! mismatch being flagged. These constants are the **single source of truth**;
//! every consumer references them so the lists can never diverge again.
//!
//! When you add or rename a family-specific action, edit it here and nowhere
//! else.

/// Fedora-family action names that are NOT available on Debian-family distros.
///
/// These are rpm-ostree shaped actions.
pub const FEDORA_ONLY_ACTIONS: &[&str] = &[
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
    "RebaseSystem",
    "GetKernelArguments",
    "SetKernelArguments",
];

/// Debian-family action names that are NOT available on Fedora-family distros.
///
/// Grouped by underlying tool: apt, snap, ufw, distrobox, netplan, grub, plus
/// the Ubuntu-only tiers (AppArmor, cloud-init, flatpak, fail2ban, Pro, …).
pub const DEBIAN_ONLY_ACTIONS: &[&str] = &[
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
    "AptListUpgradable",
    "AptHistoryList",
    "ConfigureUnattendedUpgrades",
    "GetAptPins",
    "SetAptPin",
    "RemoveAptPin",
    "AddPpa",
    "RemovePpa",
    "SnapInstall",
    "SnapRemove",
    "SnapRefresh",
    "SnapHold",
    "SnapUnhold",
    "SnapList",
    "SnapInfo",
    "SnapRevert",
    "SnapClassicInstall",
    "UfwEnable",
    "UfwDisable",
    "UfwAllow",
    "UfwDeny",
    "UfwReset",
    "UfwStatus",
    "DistroboxList",
    "DistroboxCreate",
    "DistroboxRemove",
    "NetplanGetConfig",
    "NetplanApply",
    "NetplanSet",
    "NetplanGenerate",
    "GrubGetKargs",
    "GrubSetKargs",
    "CheckPendingReboot",
    // Tier 2 — Ubuntu-only
    "AppArmorStatus",
    "AppArmorEnforce",
    "AppArmorComplain",
    "CloudInitStatus",
    "UbuntuInstallFlatpak",
    "UbuntuRemoveFlatpak",
    "UbuntuUpdateFlatpak",
    "UbuntuListFlatpaks",
    "Fail2banStatus",
    "Fail2banBanIp",
    "Fail2banUnbanIp",
    // Tier 3
    "UbuntuReleaseUpgrade",
    "ProStatus",
    "ProAttach",
    "ProDetach",
    "LivepatchStatus",
    "MultipassList",
    "UfwDeleteRule",
    "UfwLimit",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The two families must be disjoint: an action that is both Fedora-only
    /// and Debian-only would make the family fence contradict itself.
    #[test]
    fn family_lists_are_disjoint() {
        for action in FEDORA_ONLY_ACTIONS {
            assert!(
                !DEBIAN_ONLY_ACTIONS.contains(action),
                "{action} is listed as both Fedora-only and Debian-only"
            );
        }
    }

    /// No accidental duplicate entries within a single list.
    #[test]
    fn family_lists_have_no_duplicates() {
        for list in [FEDORA_ONLY_ACTIONS, DEBIAN_ONLY_ACTIONS] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            let unique = sorted.len();
            sorted.dedup();
            assert_eq!(unique, sorted.len(), "duplicate action in family list");
        }
    }
}
