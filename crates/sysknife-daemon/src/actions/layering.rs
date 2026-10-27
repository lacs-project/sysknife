//! rpm-ostree package layering actions (Fedora Atomic).
//!
//! The actions that take a package (`InstallPackages`, `AddLayeredPackage`,
//! `RemovePackages`, `RemoveLayeredPackage`, `ReplaceLayeredPackage`,
//! `RemoveBasePackage`) run `sudo /usr/lib/sysknife/action-steps rpm-ostree
//! <verb> <package>...`. The helper validates every package again and builds the
//! rpm-ostree argv itself. A direct `/usr/bin/rpm-ostree install *` grant
//! admitted a local `.rpm`, whose scriptlets run as root in the next
//! deployment, and every rpm-ostree option; sudoers cannot forbid the options
//! that follow a wildcard, so no operand-taking rpm-ostree call has a grant of
//! its own. `ResetLayeredPackageOverride` takes no operand and keeps the exact
//! grant `rpm-ostree override reset --all`.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

/// The root-owned helper every operand-taking rpm-ostree action goes through.
///
/// `tests/sudoers_grants_match_argv.rs` checks the packaged sudoers file admits
/// every argv built here, and `tests/release/action-steps.test.sh` reads the
/// verbs below out of this file and checks the helper accepts exactly those.
const ACTION_STEPS: &str = "/usr/lib/sysknife/action-steps";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        install_packages(&["podman"]),
        remove_packages(&["podman"]),
        get_layered_packages(),
        add_layered_package("podman"),
        remove_layered_package("podman"),
        replace_layered_package("vim", "neovim"),
        reset_layered_package_override(),
        remove_base_package("gedit"),
        get_pending_updates(),
    ]
}

pub fn install_packages(packages: &[&str]) -> ActionSpec {
    ActionSpec {
        action_name: "InstallPackages",
        // The helper runs `rpm-ostree install --idempotent <package>...`.
        mechanism: command_mechanism(
            "sudo",
            [ACTION_STEPS, "rpm-ostree", "install"]
                .into_iter()
                .chain(packages.iter().copied()),
        ),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn remove_packages(packages: &[&str]) -> ActionSpec {
    ActionSpec {
        action_name: "RemovePackages",
        // The helper runs `rpm-ostree uninstall <package>...`.
        mechanism: command_mechanism(
            "sudo",
            [ACTION_STEPS, "rpm-ostree", "uninstall"]
                .into_iter()
                .chain(packages.iter().copied()),
        ),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn get_layered_packages() -> ActionSpec {
    ActionSpec {
        action_name: "GetLayeredPackages",
        mechanism: command_mechanism("rpm-ostree", ["status", "--json"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn add_layered_package(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AddLayeredPackage",
        // The helper runs `rpm-ostree install --idempotent <package>`.
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "rpm-ostree", "install", package]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn remove_layered_package(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveLayeredPackage",
        // The helper runs `rpm-ostree uninstall <package>`.
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "rpm-ostree", "uninstall", package]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn replace_layered_package(old: &str, new: &str) -> ActionSpec {
    // Atomically swap one layered package for another in a single transaction.
    // `rpm-ostree install NEW --uninstall OLD` produces one pending deployment
    // that contains both changes — no intermediate deployment exists where
    // neither package is present. The running system is unchanged until reboot.
    // The helper verb `replace OLD NEW` builds that argv.
    ActionSpec {
        action_name: "ReplaceLayeredPackage",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "rpm-ostree", "replace", old, new]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn remove_base_package(package: &str) -> ActionSpec {
    // Override-remove a package that ships in the base OS image.
    // Unlike `uninstall` (which removes layered packages), `override remove`
    // hides the base package from the deployment without it ever having been
    // explicitly installed by the user.
    ActionSpec {
        action_name: "RemoveBasePackage",
        // The helper runs `rpm-ostree override remove <package>`.
        mechanism: command_mechanism(
            "sudo",
            [ACTION_STEPS, "rpm-ostree", "override-remove", package],
        ),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn get_pending_updates() -> ActionSpec {
    // Check for available OS updates without applying them.
    // `--check` exits 77 when updates ARE available, 0 when up-to-date.
    // Both exit codes produce informative stdout. The dispatcher special-cases
    // exit 77 as informational (not an error) so the update list reaches the
    // caller in both the "updates available" and "up-to-date" cases.
    ActionSpec {
        action_name: "GetPendingUpdates",
        mechanism: command_mechanism("rpm-ostree", ["upgrade", "--check"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn reset_layered_package_override() -> ActionSpec {
    ActionSpec {
        action_name: "ResetLayeredPackageOverride",
        mechanism: command_mechanism("sudo", ["rpm-ostree", "override", "reset", "--all"]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{exclusive_resource, ActionMechanism, ExclusiveResource};

    fn argv(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            other => panic!("{} is not a command: {other:?}", spec.action_name),
        }
    }

    /// The six layering actions that take a package go through the helper verb:
    /// `/usr/bin/rpm-ostree install *` and its siblings admitted a local `.rpm`
    /// (scriptlets run as root) and every rpm-ostree option.
    #[test]
    fn layering_actions_with_an_operand_go_through_the_helper_verb() {
        for (spec, expected) in [
            (
                install_packages(&["podman", "vim"]),
                vec![ACTION_STEPS, "rpm-ostree", "install", "podman", "vim"],
            ),
            (
                add_layered_package("podman"),
                vec![ACTION_STEPS, "rpm-ostree", "install", "podman"],
            ),
            (
                remove_packages(&["podman", "vim"]),
                vec![ACTION_STEPS, "rpm-ostree", "uninstall", "podman", "vim"],
            ),
            (
                remove_layered_package("podman"),
                vec![ACTION_STEPS, "rpm-ostree", "uninstall", "podman"],
            ),
            (
                replace_layered_package("vim", "neovim"),
                vec![ACTION_STEPS, "rpm-ostree", "replace", "vim", "neovim"],
            ),
            (
                remove_base_package("gedit"),
                vec![ACTION_STEPS, "rpm-ostree", "override-remove", "gedit"],
            ),
        ] {
            let (program, args) = argv(&spec);
            assert_eq!(program, "sudo", "{}", spec.action_name);
            assert_eq!(args, expected, "{}", spec.action_name);
            assert!(
                args.iter().all(|a| !a.starts_with('-')),
                "{} sends an option; the helper adds rpm-ostree's flags itself: {args:?}",
                spec.action_name
            );
        }
    }

    /// `override reset --all` takes no operand, so it keeps an exact grant.
    #[test]
    fn reset_override_keeps_its_fixed_argv() {
        let reset = reset_layered_package_override();
        let (program, args) = argv(&reset);
        assert_eq!(program, "sudo");
        assert_eq!(args, ["rpm-ostree", "override", "reset", "--all"]);
    }

    /// The dispatcher serialises on the lock named by the argv, so the helper
    /// verb has to keep naming rpm-ostree first, whatever the package is called.
    #[test]
    fn layering_actions_still_contend_for_the_rpm_ostree_lock() {
        for spec in specs().into_iter().chain([
            add_layered_package("apt-get"),
            install_packages(&["flatpak"]),
        ]) {
            assert_eq!(
                exclusive_resource(&spec),
                Some(ExclusiveResource::RpmOstree),
                "{} lost the rpm-ostree lock",
                spec.action_name
            );
        }
    }
}
