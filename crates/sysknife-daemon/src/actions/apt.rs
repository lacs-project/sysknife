//! apt-family package management actions (Ubuntu / Debian).
//!
//! All apt commands run with `DEBIAN_FRONTEND=noninteractive` and
//! `NEEDRESTART_MODE=a` so they never block waiting for a TUI prompt.
//!
//! ## Lock contention
//!
//! Before any mutating apt command the executor should detect dpkg lock
//! contention via `fuser /var/lib/dpkg/lock`. That check lives in the
//! executor; this module only builds the `ActionSpec` for the apt
//! command itself. The executor layer is responsible for the retry-after
//! hint when the lock is held.
//!
//! ## Environment variables
//!
//! `DEBIAN_FRONTEND=noninteractive` suppresses all debconf prompts.
//! `NEEDRESTART_MODE=a` tells the `needrestart` post-install hook to
//! automatically restart services instead of prompting the operator.
//! Both are required for daemon-driven apt invocations; omitting them
//! causes apt to hang waiting for terminal input that never arrives.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// apt binary path.
const APT_GET: &str = "apt-get";

/// `DEBIAN_FRONTEND` value that suppresses all debconf interactive prompts.
/// Required for non-interactive daemon invocations.
const DEBIAN_FRONTEND_VALUE: &str = "DEBIAN_FRONTEND=noninteractive";

/// `NEEDRESTART_MODE` value that makes needrestart automatically restart
/// services. Without this, apt post-install hooks spawn an interactive TUI
/// that blocks the daemon indefinitely.
const NEEDRESTART_MODE_VALUE: &str = "NEEDRESTART_MODE=a";

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per action name so the consistency
/// test can verify policy + preview + executor coverage.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        apt_update(),
        apt_upgrade(),
        apt_install("curl"),
        apt_remove("curl"),
        apt_purge("curl"),
        apt_autoremove(),
        apt_hold("curl"),
        apt_unhold("curl"),
        apt_search("curl"),
        apt_list_installed(),
        apt_show("curl"),
        apt_list_upgradable(),
        apt_history_list(),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Refresh the apt package index (`apt-get update`).
///
/// Risk: Low. No packages are changed, no lock contention for writes.
/// Requires network access to reach configured APT sources.
pub fn apt_update() -> ActionSpec {
    ActionSpec {
        action_name: "AptUpdate",
        mechanism: command_mechanism(
            "sudo",
            [
                "env",
                DEBIAN_FRONTEND_VALUE,
                NEEDRESTART_MODE_VALUE,
                APT_GET,
                "update",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Upgrade all installed packages (`apt-get dist-upgrade -y`).
///
/// Risk: High. `dist-upgrade` may remove packages to resolve dependency
/// conflicts (unlike `upgrade`). Can trigger `needrestart` service restarts.
pub fn apt_upgrade() -> ActionSpec {
    ActionSpec {
        action_name: "AptUpgrade",
        mechanism: command_mechanism(
            "sudo",
            [
                "env",
                DEBIAN_FRONTEND_VALUE,
                NEEDRESTART_MODE_VALUE,
                APT_GET,
                "dist-upgrade",
                "-y",
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Install a single package (`apt-get install -y <package>`).
///
/// Risk: Medium. Installs a package and its dependencies; reversible with
/// `apt-get remove` but not transactionally atomic.
pub fn apt_install(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptInstall",
        mechanism: command_mechanism(
            "sudo",
            [
                "env",
                DEBIAN_FRONTEND_VALUE,
                NEEDRESTART_MODE_VALUE,
                APT_GET,
                "install",
                "-y",
                package,
            ],
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a package but keep its configuration files (`apt-get remove -y <package>`).
///
/// Risk: Medium. Configuration files remain in `/etc`; reversible by
/// reinstalling the package. Use `apt_purge` to also remove config files.
pub fn apt_remove(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptRemove",
        mechanism: command_mechanism(
            "sudo",
            [
                "env",
                DEBIAN_FRONTEND_VALUE,
                NEEDRESTART_MODE_VALUE,
                APT_GET,
                "remove",
                "-y",
                package,
            ],
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a package AND its configuration files (`apt-get purge -y <package>`).
///
/// Risk: Medium. Configuration files are deleted; harder to reverse than
/// `remove`. Choose `purge` when a clean reinstall is the goal.
pub fn apt_purge(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptPurge",
        mechanism: command_mechanism(
            "sudo",
            [
                "env",
                DEBIAN_FRONTEND_VALUE,
                NEEDRESTART_MODE_VALUE,
                APT_GET,
                "purge",
                "-y",
                package,
            ],
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove automatically-installed packages no longer needed (`apt-get autoremove -y`).
///
/// Risk: Low. Only removes packages that were installed as dependencies and
/// are no longer required by any explicitly-installed package.
pub fn apt_autoremove() -> ActionSpec {
    ActionSpec {
        action_name: "AptAutoremove",
        mechanism: command_mechanism(
            "sudo",
            [
                "env",
                DEBIAN_FRONTEND_VALUE,
                NEEDRESTART_MODE_VALUE,
                APT_GET,
                "autoremove",
                "-y",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Pin a package at its current version (`apt-mark hold <package>`).
///
/// Risk: Medium. Prevents upgrades for the named package until unheld.
/// Useful to freeze a known-good version when upstream upgrades are risky.
pub fn apt_hold(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptHold",
        mechanism: command_mechanism("sudo", ["apt-mark", "hold", package]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove the hold on a package, allowing upgrades again (`apt-mark unhold <package>`).
///
/// Risk: Medium. After unholding, the next `apt upgrade` can update the package.
pub fn apt_unhold(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptUnhold",
        mechanism: command_mechanism("sudo", ["apt-mark", "unhold", package]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Search apt repositories for packages matching a term (`apt-cache search <term>`).
///
/// Risk: Low. Read-only query; no system changes.
pub fn apt_search(term: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptSearch",
        mechanism: command_mechanism("apt-cache", ["search", term]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// List all installed packages (`dpkg -l`).
///
/// Risk: Low. Read-only query; no system changes.
pub fn apt_list_installed() -> ActionSpec {
    ActionSpec {
        action_name: "AptListInstalled",
        mechanism: command_mechanism("dpkg", ["-l"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Show detailed information about a package (`apt-cache show <package>`).
///
/// Risk: Low. Read-only query showing version, dependencies, description.
pub fn apt_show(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptShow",
        mechanism: command_mechanism("apt-cache", ["show", package]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// List packages that have upgrades available (`apt list --upgradable`).
///
/// Risk: Low. Read-only query; no packages are installed or changed.
/// Stderr suppressed via `2>/dev/null` to hide the "WARNING: apt does not
/// have a stable CLI interface" notice that apt emits on non-interactive
/// invocations. The script is tee'd through `bash -c` because `apt list`
/// writes its "Listing..." header to stderr.
pub fn apt_list_upgradable() -> ActionSpec {
    ActionSpec {
        action_name: "AptListUpgradable",
        mechanism: command_mechanism("bash", ["-c", "apt list --upgradable 2>/dev/null"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Show recent apt transaction history from `/var/log/apt/history.log`.
///
/// Risk: Low. Read-only file inspection; no packages are changed.
/// Retrieves the 80 most recent log lines covering the last few Start-Date
/// entries so the user can audit what was installed, removed, or upgraded.
pub fn apt_history_list() -> ActionSpec {
    ActionSpec {
        action_name: "AptHistoryList",
        mechanism: command_mechanism(
            "bash",
            [
                "-c",
                "grep -A 4 '^Start-Date' /var/log/apt/history.log | tail -n 80",
            ],
        ),
        risk_level: RiskLevel::Low,
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

    fn extract_args(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── apt_update ───────────────────────────────────────────────────────────

    #[test]
    fn apt_update_action_name() {
        assert_eq!(apt_update().action_name, "AptUpdate");
    }

    #[test]
    fn apt_update_argv_correct() {
        let spec = apt_update();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"apt-get"));
        assert!(args.contains(&"update"));
        assert!(args.contains(&DEBIAN_FRONTEND_VALUE));
        assert!(args.contains(&NEEDRESTART_MODE_VALUE));
    }

    #[test]
    fn apt_update_risk_is_low() {
        assert_eq!(apt_update().risk_level, RiskLevel::Low);
    }

    #[test]
    fn apt_update_no_reboot_no_rollback() {
        let spec = apt_update();
        assert!(!spec.reboot_required);
        assert!(!spec.rollback_available);
    }

    // ── apt_upgrade ──────────────────────────────────────────────────────────

    #[test]
    fn apt_upgrade_action_name() {
        assert_eq!(apt_upgrade().action_name, "AptUpgrade");
    }

    #[test]
    fn apt_upgrade_argv_correct() {
        let spec = apt_upgrade();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"apt-get"));
        assert!(args.contains(&"dist-upgrade"));
        assert!(args.contains(&"-y"));
        assert!(args.contains(&DEBIAN_FRONTEND_VALUE));
        assert!(args.contains(&NEEDRESTART_MODE_VALUE));
    }

    #[test]
    fn apt_upgrade_risk_is_high() {
        assert_eq!(apt_upgrade().risk_level, RiskLevel::High);
    }

    // ── apt_install ──────────────────────────────────────────────────────────

    #[test]
    fn apt_install_action_name() {
        assert_eq!(apt_install("vim").action_name, "AptInstall");
    }

    #[test]
    fn apt_install_includes_package_name() {
        let spec = apt_install("vim");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"vim"));
        assert!(args.contains(&"install"));
        assert!(args.contains(&"-y"));
        assert!(args.contains(&DEBIAN_FRONTEND_VALUE));
        assert!(args.contains(&NEEDRESTART_MODE_VALUE));
    }

    #[test]
    fn apt_install_risk_is_medium() {
        assert_eq!(apt_install("vim").risk_level, RiskLevel::Medium);
    }

    // ── apt_remove ───────────────────────────────────────────────────────────

    #[test]
    fn apt_remove_action_name() {
        assert_eq!(apt_remove("vim").action_name, "AptRemove");
    }

    #[test]
    fn apt_remove_argv_contains_remove_not_purge() {
        let spec = apt_remove("vim");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"remove"));
        // Must NOT contain purge — that's a different action.
        assert!(!args.contains(&"purge"));
        assert!(args.contains(&"vim"));
        assert!(args.contains(&DEBIAN_FRONTEND_VALUE));
        assert!(args.contains(&NEEDRESTART_MODE_VALUE));
    }

    #[test]
    fn apt_remove_risk_is_medium() {
        assert_eq!(apt_remove("vim").risk_level, RiskLevel::Medium);
    }

    // ── apt_purge ────────────────────────────────────────────────────────────

    #[test]
    fn apt_purge_action_name() {
        assert_eq!(apt_purge("vim").action_name, "AptPurge");
    }

    #[test]
    fn apt_purge_argv_uses_purge_subcommand() {
        let spec = apt_purge("vim");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"purge"));
        assert!(args.contains(&"vim"));
        assert!(args.contains(&DEBIAN_FRONTEND_VALUE));
        assert!(args.contains(&NEEDRESTART_MODE_VALUE));
    }

    #[test]
    fn apt_purge_risk_is_medium() {
        assert_eq!(apt_purge("vim").risk_level, RiskLevel::Medium);
    }

    // ── apt_autoremove ───────────────────────────────────────────────────────

    #[test]
    fn apt_autoremove_action_name() {
        assert_eq!(apt_autoremove().action_name, "AptAutoremove");
    }

    #[test]
    fn apt_autoremove_argv_correct() {
        let spec = apt_autoremove();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"autoremove"));
        assert!(args.contains(&"-y"));
        assert!(args.contains(&DEBIAN_FRONTEND_VALUE));
        assert!(args.contains(&NEEDRESTART_MODE_VALUE));
    }

    #[test]
    fn apt_autoremove_risk_is_low() {
        assert_eq!(apt_autoremove().risk_level, RiskLevel::Low);
    }

    // ── apt_hold ─────────────────────────────────────────────────────────────

    #[test]
    fn apt_hold_action_name() {
        assert_eq!(apt_hold("nginx").action_name, "AptHold");
    }

    #[test]
    fn apt_hold_uses_apt_mark_hold() {
        let spec = apt_hold("nginx");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"apt-mark"));
        assert!(args.contains(&"hold"));
        assert!(args.contains(&"nginx"));
    }

    #[test]
    fn apt_hold_risk_is_medium() {
        assert_eq!(apt_hold("nginx").risk_level, RiskLevel::Medium);
    }

    // ── apt_unhold ───────────────────────────────────────────────────────────

    #[test]
    fn apt_unhold_action_name() {
        assert_eq!(apt_unhold("nginx").action_name, "AptUnhold");
    }

    #[test]
    fn apt_unhold_uses_apt_mark_unhold() {
        let spec = apt_unhold("nginx");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"apt-mark"));
        assert!(args.contains(&"unhold"));
        assert!(args.contains(&"nginx"));
    }

    #[test]
    fn apt_unhold_risk_is_medium() {
        assert_eq!(apt_unhold("nginx").risk_level, RiskLevel::Medium);
    }

    // ── apt_search ───────────────────────────────────────────────────────────

    #[test]
    fn apt_search_action_name() {
        assert_eq!(apt_search("docker").action_name, "AptSearch");
    }

    #[test]
    fn apt_search_uses_apt_cache_search() {
        let spec = apt_search("docker");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "apt-cache");
        assert!(args.contains(&"search"));
        assert!(args.contains(&"docker"));
    }

    #[test]
    fn apt_search_risk_is_low() {
        assert_eq!(apt_search("docker").risk_level, RiskLevel::Low);
    }

    #[test]
    fn apt_search_no_sudo() {
        // Read-only search must not require sudo.
        let spec = apt_search("docker");
        let (prog, _) = extract_args(&spec);
        assert_ne!(prog, "sudo");
    }

    // ── apt_list_installed ───────────────────────────────────────────────────

    #[test]
    fn apt_list_installed_action_name() {
        assert_eq!(apt_list_installed().action_name, "AptListInstalled");
    }

    #[test]
    fn apt_list_installed_uses_dpkg() {
        let spec = apt_list_installed();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "dpkg");
        assert!(args.contains(&"-l"));
    }

    #[test]
    fn apt_list_installed_risk_is_low() {
        assert_eq!(apt_list_installed().risk_level, RiskLevel::Low);
    }

    // ── apt_show ─────────────────────────────────────────────────────────────

    #[test]
    fn apt_show_action_name() {
        assert_eq!(apt_show("openssh-server").action_name, "AptShow");
    }

    #[test]
    fn apt_show_uses_apt_cache_show() {
        let spec = apt_show("openssh-server");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "apt-cache");
        assert!(args.contains(&"show"));
        assert!(args.contains(&"openssh-server"));
    }

    #[test]
    fn apt_show_risk_is_low() {
        assert_eq!(apt_show("openssh-server").risk_level, RiskLevel::Low);
    }

    // ── apt_list_upgradable ──────────────────────────────────────────────────

    #[test]
    fn apt_list_upgradable_action_name() {
        assert_eq!(apt_list_upgradable().action_name, "AptListUpgradable");
    }

    #[test]
    fn apt_list_upgradable_uses_bash_and_apt_list() {
        let spec = apt_list_upgradable();
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                assert_eq!(*program, "bash");
                let joined = args.join(" ");
                assert!(joined.contains("apt list --upgradable"), "argv: {joined}");
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    #[test]
    fn apt_list_upgradable_risk_is_low() {
        assert_eq!(apt_list_upgradable().risk_level, RiskLevel::Low);
    }

    // ── apt_history_list ─────────────────────────────────────────────────────

    #[test]
    fn apt_history_list_action_name() {
        assert_eq!(apt_history_list().action_name, "AptHistoryList");
    }

    #[test]
    fn apt_history_list_uses_bash_and_grep() {
        let spec = apt_history_list();
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                assert_eq!(*program, "bash");
                let joined = args.join(" ");
                assert!(
                    joined.contains("/var/log/apt/history.log"),
                    "argv: {joined}"
                );
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    #[test]
    fn apt_history_list_risk_is_low() {
        assert_eq!(apt_history_list().risk_level, RiskLevel::Low);
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected_names = [
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
        ];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected_names {
            assert!(
                spec_names.contains(name),
                "specs() is missing action {name}"
            );
        }
    }

    // ── env var injection regression ─────────────────────────────────────────

    #[test]
    fn mutating_apt_commands_carry_env_vars() {
        let mutating = [
            apt_upgrade(),
            apt_install("vim"),
            apt_remove("vim"),
            apt_purge("vim"),
            apt_autoremove(),
        ];
        for spec in &mutating {
            let (_, args) = extract_args(spec);
            assert!(
                args.contains(&DEBIAN_FRONTEND_VALUE),
                "{} missing DEBIAN_FRONTEND",
                spec.action_name
            );
            assert!(
                args.contains(&NEEDRESTART_MODE_VALUE),
                "{} missing NEEDRESTART_MODE",
                spec.action_name
            );
        }
    }
}
