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
/// There are no exceptions. `GetSystemState` was the last one: it runs
/// `rpm-ostree status --json` and was reachable from every host because it was
/// woven through the shared prompt blocks as *the* state action, with nothing on
/// the Ubuntu side to put in its place. `GetHostState` is now that counterpart,
/// so the fence is complete and `UNFENCED_BY_DECISION` is empty (#181).
///
/// Flatpak is deliberately NOT in here: the un-prefixed `InstallFlatpak` family
/// covers remotes, search, and app info, which the `Ubuntu*Flatpak` actions do
/// not, so scoping it to Fedora would remove capability from Ubuntu rather than
/// redirect it.
pub const FEDORA_ONLY_ACTIONS: &[&str] = &[
    // Reports rpm-ostree *deployments*, which an apt host does not have. Its
    // Debian counterpart is `GetHostState`.
    "GetSystemState",
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
/// Used by catalogue filtering and the conservative supported-host routing
/// guard, never as a mechanism incompatibility on an eligible host.
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
/// These drive apt/dpkg or Debian's GRUB configuration/update interface.
/// Ubuntu-specific services live in [`UBUNTU_ONLY_ACTIONS`]; installable tools
/// are planner preferences, not execution fences.
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
    "GrubGetKargs",
    "GrubSetKargs",
];

/// Ubuntu-specific services and repository formats. A Debian-family hint alone
/// is insufficient: PPAs serve packages built for an Ubuntu series, even when
/// add-apt-repository itself is installed on Debian.
///
/// CheckPendingReboot relies on Ubuntu's update-notifier sentinel. Until a
/// Debian producer is validated, do not interpret a missing sentinel there as
/// evidence that no reboot is needed. Debian eligibility is unchanged.
pub const UBUNTU_ONLY_ACTIONS: &[&str] = &[
    "AddPpa",
    "RemovePpa",
    "CheckPendingReboot",
    "UbuntuReleaseUpgrade",
    "ProStatus",
    "ProAttach",
    "ProDetach",
    "EnableProService",
    "DisableProService",
    "LivepatchStatus",
];

/// Installable on Debian itself, but not its default administrative tools.
/// Unlike [`NON_CANONICAL_ON_DEBIAN`], this applies only to non-Ubuntu members
/// of the Debian family. It does not impose a mechanism execution fence.
pub const NON_CANONICAL_ON_DEBIAN_HOST: &[&str] = &[
    "SnapInstall",
    "SnapRemove",
    "SnapRefresh",
    "SnapHold",
    "SnapUnhold",
    "SnapList",
    "SnapInfo",
    "SnapRevert",
    "SnapClassicInstall",
    "NetplanGetConfig",
    "NetplanApply",
    "NetplanSet",
    "NetplanGenerate",
    "MultipassList",
];

/// Ubuntu's default catalogue contains these portable tools. Keep the Fedora
/// planner on its existing defaults while allowing operators to execute tools
/// they installed. Mechanism-derived tests prevent preference from creeping
/// back into either hard family fence.
pub const NON_CANONICAL_ON_FEDORA: &[&str] = &[
    "GetHostState",
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
    "MultipassList",
    "UfwDeleteRule",
    "UfwLimit",
];

/// Whether the action requires a detected distro before even a read can run.
pub fn action_requires_distro(action: &str) -> bool {
    [
        FEDORA_ONLY_ACTIONS,
        DEBIAN_ONLY_ACTIONS,
        UBUNTU_ONLY_ACTIONS,
    ]
    .iter()
    .any(|list| list.contains(&action))
}

/// Whether planning and client routing require a supported host for this action.
///
/// Includes portable tools with distro-specific defaults, not just hard
/// mechanism fences. Splitting those tools out of a hard fence must not let
/// an ineligible host reach approval for a mutation the daemon will refuse.
/// On eligible hosts, only [`action_matches_distro`] restricts mechanisms.
/// This conservative client/catalogue gate also withholds portable reads;
/// the daemon's read-only detection exemption remains separate.
pub fn action_requires_supported_host(action: &str) -> bool {
    action_requires_distro(action)
        || [
            NON_CANONICAL_ON_DEBIAN,
            NON_CANONICAL_ON_DEBIAN_HOST,
            NON_CANONICAL_ON_FEDORA,
        ]
        .iter()
        .any(|list| list.contains(&action))
}

/// Mechanism compatibility only; callers must separately check host eligibility.
/// Unknown action names remain the catalogue validator's responsibility.
pub fn action_matches_distro(action: &str, distro: &crate::distro::DistroId) -> bool {
    use crate::distro::{DistroFamily, DistroId};
    if UBUNTU_ONLY_ACTIONS.contains(&action) {
        matches!(distro, DistroId::Ubuntu { .. })
    } else if DEBIAN_ONLY_ACTIONS.contains(&action) {
        distro.family() == DistroFamily::Debian
    } else if FEDORA_ONLY_ACTIONS.contains(&action) {
        distro.family() == DistroFamily::Fedora
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two families must be disjoint: an action that is both Fedora-only
    /// and Debian-only would make the family fence contradict itself.
    #[test]
    fn family_lists_are_disjoint() {
        let lists = [
            FEDORA_ONLY_ACTIONS,
            DEBIAN_ONLY_ACTIONS,
            UBUNTU_ONLY_ACTIONS,
        ];
        for (index, list) in lists.iter().enumerate() {
            for action in *list {
                for other in &lists[index + 1..] {
                    assert!(
                        !other.contains(action),
                        "{action} has conflicting hard fences"
                    );
                }
            }
        }
    }

    /// No accidental duplicate entries within a single list.
    #[test]
    fn family_lists_have_no_duplicates() {
        for list in [
            FEDORA_ONLY_ACTIONS,
            DEBIAN_ONLY_ACTIONS,
            UBUNTU_ONLY_ACTIONS,
            NON_CANONICAL_ON_DEBIAN,
            NON_CANONICAL_ON_DEBIAN_HOST,
            NON_CANONICAL_ON_FEDORA,
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            let unique = sorted.len();
            sorted.dedup();
            assert_eq!(unique, sorted.len(), "duplicate action in family list");
        }
    }

    #[test]
    fn planner_preferences_are_not_execution_fences() {
        for action in NON_CANONICAL_ON_DEBIAN
            .iter()
            .chain(NON_CANONICAL_ON_DEBIAN_HOST)
            .chain(NON_CANONICAL_ON_FEDORA)
        {
            for fence in [
                FEDORA_ONLY_ACTIONS,
                DEBIAN_ONLY_ACTIONS,
                UBUNTU_ONLY_ACTIONS,
            ] {
                assert!(
                    !fence.contains(action),
                    "{action} is both portable and hard-fenced"
                );
            }
        }
    }

    #[test]
    fn ubuntu_identity_is_stricter_than_debian_family() {
        use crate::distro::DistroId;
        let ubuntu = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        let debian = DistroId::Debian { version: Some(13) };
        let derivative = DistroId::Other {
            id: "linuxmint".into(),
            version_id: None,
            id_like: vec!["ubuntu".into(), "debian".into()],
        };
        // #237: name the expected boundaries independently of the production
        // lists, so moving a PPA back to the Debian fence fails this test.
        for action in [
            "AddPpa",
            "RemovePpa",
            "ProAttach",
            "LivepatchStatus",
            "CheckPendingReboot",
        ] {
            assert!(action_matches_distro(action, &ubuntu), "{action}");
            assert!(!action_matches_distro(action, &debian), "{action}");
            assert!(!action_matches_distro(action, &derivative), "{action}");
            assert!(action_requires_distro(action), "{action}");
        }
        for action in ["AptInstall", "AptUpdate"] {
            assert!(action_matches_distro(action, &ubuntu), "{action}");
            assert!(action_matches_distro(action, &debian), "{action}");
        }
        assert!(
            !derivative.is_supported(),
            "Debian-family membership must not enable an unrecognised derivative"
        );
    }
}
