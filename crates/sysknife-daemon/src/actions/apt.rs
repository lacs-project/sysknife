//! apt-family package management actions (Ubuntu / Debian).
//!
//! The eight actions that run `apt-get` or `apt-mark` as root (`AptUpdate`,
//! `AptUpgrade`, `AptInstall`, `AptRemove`, `AptPurge`, `AptAutoremove`,
//! `AptHold`, `AptUnhold`) run
//! `sudo /usr/lib/sysknife/action-steps apt <subcommand> [<package>]`. The
//! helper builds the `apt-get` or `apt-mark` argv from an allowlist and sets
//! `DEBIAN_FRONTEND=noninteractive` and `NEEDRESTART_MODE=a` itself, so the
//! commands never block waiting for a TUI prompt. A direct sudoers grant on
//! `apt-get` or `apt-mark` admitted apt's own options
//! (`-o APT::Update::Pre-Invoke::=<cmd>` runs `<cmd>` as root), and sudoers
//! cannot forbid the options that follow a wildcard, so neither has a grant.
//!
//! The package operand is validated here by `validated_install_package` and
//! `validated_unmodified_package` (character set, and no trailing `-`, `+` or
//! `^`), and again in the helper. A name containing `.` or `+` can still be a
//! regular expression to apt, so the helper also passes
//! `-o APT::Cmd::Pattern-Only=1` and refuses an operand that does not name
//! exactly one existing package, which only the host's package database can say.
//!
//! ## Lock contention
//!
//! Concurrent apt runs are prevented by the dispatcher's exclusion gate, not
//! by a pre-flight probe: every action whose argv names an apt/dpkg tool maps
//! to [`ExclusiveResource::Dpkg`](super::ExclusiveResource::Dpkg), and a second
//! one submitted while the first holds that lock gets a `ConflictResponse`.
//!
//! An earlier version of this doc claimed the executor ran
//! `fuser /var/lib/dpkg/lock` before each mutating command. It never did —
//! there is no such probe anywhere in the daemon. The gate above covers
//! contention *between SysKnife actions*, which is what SysKnife can actually
//! control; it does not detect a dpkg lock held by something outside SysKnife
//! (an operator's own `apt` session, or unattended-upgrades). In that case apt
//! itself reports the lock and the action fails with apt's own message.
//!
//! ## Environment variables
//!
//! `DEBIAN_FRONTEND=noninteractive` suppresses all debconf prompts.
//! `NEEDRESTART_MODE=a` tells the `needrestart` post-install hook to
//! automatically restart services instead of prompting the operator.
//! Both are required for daemon-driven apt invocations; omitting them
//! causes apt to hang waiting for terminal input that never arrives. The
//! `apt` verb of `packaging/sysknife-action-steps` provides both.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The root-owned helper every `apt-get` and `apt-mark` action goes through.
///
/// `tests/sudoers_grants_match_argv.rs` checks that the packaged sudoers file
/// grants exactly this verb, and `tests/release/action-steps.test.sh` reads the
/// subcommands below out of this file and checks the helper accepts each one and
/// nothing else.
const ACTION_STEPS: &str = "/usr/lib/sysknife/action-steps";

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
        configure_unattended_upgrades(true),
    ]
}

/// Installed path of the privileged unattended-upgrades helper script.
/// See `packaging/sysknife-unattended-upgrades-edit` and the matching NOPASSWD
/// grant in `packaging/sysknife-sudoers`.
const UNATTENDED_UPGRADES_HELPER: &str = "/usr/lib/sysknife/unattended-upgrades-edit";

/// Enable or disable Ubuntu automatic (unattended) security updates.
///
/// Risk: High. Delegates to the root-owned helper, which writes the fixed
/// `/etc/apt/apt.conf.d/20auto-upgrades` content (no free-form input) and, when
/// enabling, ensures the `unattended-upgrades` package is installed. Changing
/// the automatic-update posture is a security-relevant, system-wide operation.
pub fn configure_unattended_upgrades(enabled: bool) -> ActionSpec {
    let flag = if enabled { "--enable" } else { "--disable" };
    ActionSpec {
        action_name: "ConfigureUnattendedUpgrades",
        mechanism: command_mechanism("sudo", [UNATTENDED_UPGRADES_HELPER, flag]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Refresh the apt package index (`action-steps apt update`, which runs `apt-get update`).
///
/// Risk: Low. No packages are changed, no lock contention for writes.
/// Requires network access to reach configured APT sources.
pub fn apt_update() -> ActionSpec {
    ActionSpec {
        action_name: "AptUpdate",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "update"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Upgrade all installed packages (`action-steps apt dist-upgrade`, which runs
/// `apt-get dist-upgrade -y`).
///
/// Risk: High. `dist-upgrade` may remove packages to resolve dependency
/// conflicts (unlike `upgrade`). Can trigger `needrestart` service restarts.
pub fn apt_upgrade() -> ActionSpec {
    ActionSpec {
        action_name: "AptUpgrade",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "dist-upgrade"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Install a single package (`action-steps apt install <package>`, which runs
/// `apt-get -o APT::Cmd::Pattern-Only=1 install -y -- <package>`).
///
/// The package name is validated by `validated_install_package`, which refuses a
/// trailing `-` (apt-get reads `pkg-` on `install` as "remove pkg").
///
/// Risk: Medium. Installs a package and its dependencies; reversible with
/// `apt-get remove` but not transactionally atomic.
pub fn apt_install(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptInstall",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "install", package]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a package but keep its configuration files
/// (`action-steps apt remove <package>`, which runs `apt-get -o APT::Cmd::Pattern-Only=1 remove -y -- <package>`).
///
/// The package name is validated by `validated_unmodified_package`, which refuses
/// a trailing `+` (apt-get reads `pkg+` on `remove` as "install pkg") and a
/// trailing `-`.
///
/// Risk: Medium. Configuration files remain in `/etc`; reversible by
/// reinstalling the package. Use `apt_purge` to also remove config files.
pub fn apt_remove(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptRemove",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "remove", package]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a package AND its configuration files (`action-steps apt purge
/// <package>`, which runs `apt-get -o APT::Cmd::Pattern-Only=1 purge -y -- <package>`). Validated like
/// [`apt_remove`].
///
/// Risk: Medium. Configuration files are deleted; harder to reverse than
/// `remove`. Choose `purge` when a clean reinstall is the goal.
pub fn apt_purge(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptPurge",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "purge", package]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove automatically-installed packages no longer needed
/// (`action-steps apt autoremove`, which runs `apt-get autoremove -y`).
///
/// Risk: Medium. The set of packages actually removed is chosen by the
/// dependency resolver at execution time, not named by the caller, so the
/// approved preview (`apt-get autoremove -y`) cannot show what will go. In
/// practice that set has been known to include old kernels and driver or
/// bootloader metapackages that were marked auto-installed. It stays below
/// `AptUpgrade`'s High only because it never *installs* or upgrades anything.
pub fn apt_autoremove() -> ActionSpec {
    ActionSpec {
        action_name: "AptAutoremove",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "autoremove"]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Pin a package at its current version (`action-steps apt hold <package>`,
/// which runs `apt-mark -o APT::Cmd::Pattern-Only=1 hold -- <package>`).
///
/// The helper builds the argv because `apt-mark` takes apt's own options after
/// the subcommand (`-o Dir::Bin::dpkg=<path>` runs `<path>` as root) and, for an
/// operand that is not an exact package name, falls back to a regular
/// expression and holds every package it matches. The package name is validated
/// by `validated_unmodified_package`: `apt-mark` strips a trailing `+`, so the
/// package held would not be the one previewed.
///
/// Risk: Medium. Prevents upgrades for the named package until unheld.
/// Useful to freeze a known-good version when upstream upgrades are risky.
pub fn apt_hold(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptHold",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "hold", package]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove the hold on a package, allowing upgrades again
/// (`action-steps apt unhold <package>`; see [`apt_hold`]).
///
/// Risk: Medium. After unholding, the next `apt upgrade` can update the package.
pub fn apt_unhold(package: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AptUnhold",
        mechanism: command_mechanism("sudo", [ACTION_STEPS, "apt", "unhold", package]),
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

/// The set of packages `apt-get -s autoremove` would remove, parsed from its
/// simulate (`-s`) output.
///
/// apt prints one `Remv <package> [<version>]` line per package it would remove
/// (the package token may carry an `:arch` suffix, which we keep verbatim). This
/// is used to bind `AptAutoremove`'s approval to the exact set the operator saw
/// at preview time — `apt-get autoremove -y` otherwise resolves the deletion set
/// at run time, so the executed effect is unbound by the approval (#151).
pub fn parse_autoremove_removals(simulate_stdout: &str) -> std::collections::BTreeSet<String> {
    simulate_stdout
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("Remv ")?;
            rest.split_whitespace().next().map(str::to_string)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn removals(s: &str) -> Vec<String> {
        parse_autoremove_removals(s).into_iter().collect()
    }

    #[test]
    fn parse_autoremove_extracts_the_remv_package_set() {
        let out = "Reading package lists... Done\n\
                   Building dependency tree... Done\n\
                   The following packages will be REMOVED:\n\
                   \x20 linux-image-5.4.0-100 linux-modules-5.4.0-100\n\
                   0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n\
                   Remv linux-image-5.4.0-100 [5.4.0-100.113]\n\
                   Remv linux-modules-5.4.0-100 [5.4.0-100.113]\n";
        assert_eq!(
            removals(out),
            vec![
                "linux-image-5.4.0-100".to_string(),
                "linux-modules-5.4.0-100".to_string()
            ]
        );
    }

    #[test]
    fn parse_autoremove_keeps_arch_suffix_and_ignores_non_remv_lines() {
        let out = "Inst libkeep [1.0] (2.0 amd64)\n\
                   Remv libfoo:amd64 [1.2-3]\n\
                   Conf libbar [4.5]\n";
        assert_eq!(removals(out), vec!["libfoo:amd64".to_string()]);
    }

    #[test]
    fn parse_autoremove_on_empty_or_nothing_to_remove_is_empty() {
        assert!(parse_autoremove_removals("").is_empty());
        assert!(parse_autoremove_removals(
            "Reading package lists... Done\n0 to remove and 0 not upgraded.\n"
        )
        .is_empty());
    }

    #[test]
    fn parse_autoremove_deduplicates_and_sorts() {
        // A BTreeSet gives a stable, deduplicated order regardless of apt's.
        let out = "Remv b [1]\nRemv a [1]\nRemv b [1]\n";
        assert_eq!(removals(out), vec!["a".to_string(), "b".to_string()]);
    }

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
        assert_eq!(args, vec![ACTION_STEPS, "apt", "update"]);
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
        assert_eq!(args, vec![ACTION_STEPS, "apt", "dist-upgrade"]);
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
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args, vec![ACTION_STEPS, "apt", "install", "vim"]);
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
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        // Must NOT be purge — that's a different action.
        assert_eq!(args, vec![ACTION_STEPS, "apt", "remove", "vim"]);
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
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args, vec![ACTION_STEPS, "apt", "purge", "vim"]);
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
        assert_eq!(args, vec![ACTION_STEPS, "apt", "autoremove"]);
    }

    #[test]
    fn apt_autoremove_risk_is_medium() {
        assert_eq!(apt_autoremove().risk_level, RiskLevel::Medium);
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
        assert_eq!(args, vec![ACTION_STEPS, "apt", "hold", "nginx"]);
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
        assert_eq!(args, vec![ACTION_STEPS, "apt", "unhold", "nginx"]);
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

    // ── helper routing ───────────────────────────────────────────────────────

    /// The eight actions that run apt-get or apt-mark as root, built with an
    /// operand that is a legal package name, so every argv below is one the
    /// daemon can really send.
    fn apt_get_actions() -> Vec<ActionSpec> {
        vec![
            apt_update(),
            apt_upgrade(),
            apt_install("vim"),
            apt_remove("vim"),
            apt_purge("vim"),
            apt_autoremove(),
            apt_hold("vim"),
            apt_unhold("vim"),
        ]
    }

    /// `env DEBIAN_FRONTEND=… NEEDRESTART_MODE=a /usr/bin/apt-get *` was a sudoers
    /// grant, and a trailing `*` takes apt's own options: `apt-get -o
    /// APT::Update::Pre-Invoke::=<cmd> update` runs <cmd> as root. The actions go
    /// through `action-steps apt`, which sets the environment and builds the argv,
    /// so nothing the daemon sends names apt-get, env or an option.
    #[test]
    fn apt_get_actions_go_through_the_helper_and_carry_no_option() {
        for spec in apt_get_actions() {
            let (prog, args) = extract_args(&spec);
            assert_eq!(prog, "sudo", "{}", spec.action_name);
            assert_eq!(
                args[..2],
                [ACTION_STEPS, "apt"],
                "{} must go through the helper verb: {args:?}",
                spec.action_name
            );
            for arg in &args {
                assert!(
                    !arg.starts_with('-'),
                    "{} sends an option {arg:?}; the helper adds the flags itself",
                    spec.action_name
                );
                assert!(
                    !arg.contains("apt-get")
                        && !arg.contains("apt-mark")
                        && *arg != "env"
                        && !arg.contains('='),
                    "{} still builds a direct apt-get or apt-mark argv: {args:?}",
                    spec.action_name
                );
            }
        }
    }

    /// The dispatcher serialises actions on the lock named by the argv, so the
    /// helper verb has to keep naming a tool `exclusive_resource` recognises.
    #[test]
    fn apt_get_actions_still_contend_for_the_dpkg_lock() {
        for spec in apt_get_actions() {
            assert_eq!(
                crate::actions::exclusive_resource(&spec),
                Some(crate::actions::ExclusiveResource::Dpkg),
                "{} lost the dpkg lock when it moved to the helper",
                spec.action_name
            );
        }
    }

    /// `apt install` of a package named like another tool (`snap`, `flatpak`)
    /// must still resolve to dpkg: the verb comes first in the argv.
    #[test]
    fn a_package_named_like_another_tool_does_not_change_the_lock() {
        for operand in ["snap", "flatpak", "rpm-ostree"] {
            assert_eq!(
                crate::actions::exclusive_resource(&apt_install(operand)),
                Some(crate::actions::ExclusiveResource::Dpkg),
                "apt install {operand} must hold the dpkg lock"
            );
        }
    }
}
