use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

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
        mechanism: command_mechanism(
            "sudo",
            std::iter::once("rpm-ostree")
                .chain(std::iter::once("install"))
                .chain(std::iter::once("--idempotent"))
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
        mechanism: command_mechanism(
            "sudo",
            std::iter::once("rpm-ostree")
                .chain(std::iter::once("uninstall"))
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
        mechanism: command_mechanism("sudo", ["rpm-ostree", "install", "--idempotent", package]),
        risk_level: RiskLevel::High,
        reboot_required: true,
        rollback_available: true,
    }
}

pub fn remove_layered_package(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveLayeredPackage",
        mechanism: command_mechanism("sudo", ["rpm-ostree", "uninstall", package]),
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
    ActionSpec {
        action_name: "ReplaceLayeredPackage",
        mechanism: command_mechanism("sudo", ["rpm-ostree", "install", new, "--uninstall", old]),
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
        mechanism: command_mechanism("sudo", ["rpm-ostree", "override", "remove", package]),
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
