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
/// Membership means **impossibility**, not preference: the action's mechanism
/// cannot work on the other family, so the daemon fence and the CLI routing
/// guard refuse it there. For "runnable but not this family's canonical tool",
/// see [`NON_CANONICAL_ON_DEBIAN`].
///
/// These are the rpm-ostree and dnf shaped actions, derived from each action's
/// own argv by `family_fence_agrees_with_each_action_s_mechanism` in
/// `sysknife-daemon/tests/action_consistency.rs` — so an action that drives
/// `rpm-ostree` and is missing from this list fails the build rather than being
/// quietly offered to an apt host.
///
/// One documented exception: `GetSystemState` also runs `rpm-ostree status`, but
/// it is woven through fifteen places in the shared, empirically-validated prompt
/// blocks as *the* state action, with no Ubuntu equivalent to put in its place.
/// Fencing it needs a prompt restructure validated against the story suite, so it
/// is tracked separately rather than done blind.
///
/// Flatpak is deliberately NOT in here: the un-prefixed `InstallFlatpak` family
/// covers remotes, search, and app info, which the `Ubuntu*Flatpak` actions do
/// not, so scoping it to Fedora would remove capability from Ubuntu rather than
/// redirect it.
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
    // rpm-ostree, reached through names that do not say so. These sat outside the
    // fence while `AddLayeredPackage` — the single-package twin of
    // `InstallPackages`, same `rpm-ostree install` argv — sat inside it, so an
    // Ubuntu host was offered `UpdateSystem` (High, reboot) and four actions that
    // write under `/etc/yum.repos.d/`. `family_fence_agrees_with_each_action_s_mechanism`
    // now derives this from each action's argv so the list cannot drift again.
    "UpdateSystem",
    "InstallPackages",
    "RemovePackages",
    "GetPendingUpdates",
    // dnf repository files under /etc/yum.repos.d.
    "ListPackageRepositories",
    "AddPackageRepository",
    "RemovePackageRepository",
    "EnablePackageRepository",
    "DisablePackageRepository",
];

/// Actions the **planner** must not offer on a Debian-family host, even though
/// the daemon can still run them there.
///
/// This is a different question from the family fence above, and conflating the
/// two caused a regression. `firewall-cmd` and `toolbox` are installable on
/// Ubuntu, so "cannot run here" is false — but they are not the family's
/// canonical tooling, and offering them is how the planner answered "show the
/// current firewall rules" on Ubuntu with `GetFirewallState` and "what
/// development containers do I have" with `ListToolboxes`.
///
/// Putting them in `FEDORA_ONLY_ACTIONS` fixed the planning defect and broke two
/// other things: the daemon fence and the CLI routing guard then *refused* them,
/// so an Ubuntu host running firewalld lost firewall management entirely, and
/// `UfwStatus` answered `Status: inactive` — a confident wrong answer instead of
/// a refusal.
///
/// Consumed only by `sysknife-brain`'s catalogue filter. The fence must not read
/// it: preference is not impossibility.
pub const NON_CANONICAL_ON_DEBIAN: &[&str] = &[
    // Ubuntu's canonical firewall is ufw (UfwStatus, UfwAllow/UfwDeny).
    "GetFirewallState",
    "ConfigureFirewall",
    // Ubuntu's canonical container environment is distrobox.
    "ListToolboxes",
    "CreateToolbox",
    "RemoveToolbox",
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
    "ConfigureFail2banJail",
    // Tier 3
    "UbuntuReleaseUpgrade",
    "ProStatus",
    "ProAttach",
    "ProDetach",
    "EnableProService",
    "DisableProService",
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
