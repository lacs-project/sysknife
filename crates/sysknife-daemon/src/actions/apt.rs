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
        unattended_upgrades_status(),
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

const UNATTENDED_UPGRADES_STATUS_SCRIPT: &str = r#"export LC_ALL=C; config=/etc/apt/apt.conf.d/20auto-upgrades; log_dir=/var/log/unattended-upgrades; printf '%s\n' '__SYSKNIFE_CONFIG_BEGIN__'; if [ -r "$config" ]; then cat -- "$config"; else printf '%s\n' '__MISSING_CONFIG__'; fi; printf '%s\n' '__SYSKNIFE_CONFIG_END__'; printf '%s\n' '__SYSKNIFE_TIMERS_BEGIN__'; systemctl list-timers --all --no-pager apt-daily.timer apt-daily-upgrade.timer 2>&1 || true; printf '%s\n' '__SYSKNIFE_TIMERS_END__'; printf '%s\n' '__SYSKNIFE_TIMER_STATES_BEGIN__'; for unit in apt-daily.timer apt-daily-upgrade.timer; do state=$(systemctl is-enabled "$unit" 2>/dev/null || true); [ -n "$state" ] || state=unknown; printf '%s: %s\n' "$unit" "$state"; done; printf '%s\n' '__SYSKNIFE_TIMER_STATES_END__'; printf '%s\n' '__SYSKNIFE_LOG_BEGIN__'; if [ ! -d "$log_dir" ]; then printf '%s\n' '__MISSING_LOG_DIR__'; elif [ -r "$log_dir" ] && [ -x "$log_dir" ]; then zcat -f -- "$log_dir"/*.log* 2>/dev/null | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2} ' | sort | tail -n 1; else printf '%s\n' '__UNREADABLE_LOG_DIR__'; fi; printf '%s\n' '__SYSKNIFE_LOG_END__'"#;

/// Read the automatic-upgrade schedule and most recent unattended-upgrades log
/// entry without taking the apt lock or changing host state.
pub fn unattended_upgrades_status() -> ActionSpec {
    ActionSpec {
        action_name: "UnattendedUpgradesStatus",
        mechanism: command_mechanism("bash", ["-c", UNATTENDED_UPGRADES_STATUS_SCRIPT]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Convert the fixed-section output from `UNATTENDED_UPGRADES_STATUS_SCRIPT`
/// into an operator-facing summary. Missing inputs remain unknown and identify
/// their source path or systemd unit instead of implying the feature is off.
pub fn parse_unattended_upgrades_status(output: &str) -> String {
    const CONFIG_PATH: &str = "/etc/apt/apt.conf.d/20auto-upgrades";
    const LOG_DIR: &str = "/var/log/unattended-upgrades";
    const UNITS: [&str; 2] = ["apt-daily.timer", "apt-daily-upgrade.timer"];

    let config = section(output, "CONFIG");
    let timers = section(output, "TIMERS");
    let states = section(output, "TIMER_STATES");
    let log = section(output, "LOG");
    let mut summary = Vec::new();

    for (key, label) in [
        (
            "Update-Package-Lists",
            "APT::Periodic::Update-Package-Lists",
        ),
        ("Unattended-Upgrade", "APT::Periodic::Unattended-Upgrade"),
    ] {
        let value = config.and_then(|text| parse_apt_periodic_value(text, key));
        match value.as_deref().and_then(|value| value.parse::<u64>().ok()) {
            Some(0) => summary.push(format!("{label}: 0 (off)")),
            Some(value) => summary.push(format!("{label}: {value} (enabled)")),
            None if value.is_some() => summary.push(format!(
                "{label}: {} (status unknown: unrecognized value)",
                value.as_deref().unwrap_or_default()
            )),
            None => {
                let reason = if config.is_none_or(|text| text.contains("__MISSING_CONFIG__")) {
                    "file missing or unreadable"
                } else {
                    "value not configured"
                };
                summary.push(format!("{label}: unknown ({CONFIG_PATH}: {reason})"));
            }
        }
    }

    for unit in UNITS {
        let state = states.and_then(|text| parse_timer_state(text, unit));
        let run_times = timers.and_then(|text| parse_timer_runs(text, unit));
        if state.as_deref() == Some("disabled") {
            let (next, last) = run_times.unwrap_or_else(|| ("n/a".into(), "n/a".into()));
            summary.push(format!(
                "{unit}: disabled; last run: {last}; next run: {next}"
            ));
        } else {
            match (state.as_deref(), run_times) {
                (Some("masked"), _) => summary.push(format!("{unit}: masked; last run: n/a; next run: n/a")),
                (None, Some((next, last))) => summary.push(format!(
                    "{unit}: unknown (systemctl is-enabled did not report {unit}); last run: {last}; next run: {next}"
                )),
                (Some(state), Some((next, last))) => summary.push(format!(
                    "{unit}: {state}; last run: {last}; next run: {next}"
                )),
                (Some(state), None) if state != "unknown" && state != "not-found" => summary.push(
                    format!("{unit}: {state}; last run: unknown; next run: unknown (systemctl list-timers did not report {unit})"),
                ),
                _ => summary.push(format!(
                    "{unit}: unknown (systemd did not report {unit}; last and next run unavailable)"
                )),
            }
        }
    }

    match log.map(str::trim) {
        Some("__MISSING_LOG_DIR__") => summary.push(format!(
            "Latest unattended-upgrades log entry: unknown ({LOG_DIR}: directory missing)"
        )),
        Some("__UNREADABLE_LOG_DIR__") => summary.push(format!(
            "Latest unattended-upgrades log entry: unknown ({LOG_DIR}: directory not readable by the daemon user)"
        )),
        Some(entry) if !entry.is_empty() => summary.push(format!(
            "Latest unattended-upgrades log entry: {}",
            entry.chars().take(512).collect::<String>()
        )),
        _ => summary.push(format!(
            "Latest unattended-upgrades log entry: unknown ({LOG_DIR}: no timestamped log entry)"
        )),
    }

    summary.join("\n")
}

fn section<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    let start = format!("__SYSKNIFE_{name}_BEGIN__");
    let end = format!("__SYSKNIFE_{name}_END__");
    output
        .split_once(&start)?
        .1
        .split_once(&end)
        .map(|(body, _)| body)
}

fn parse_apt_periodic_value(config: &str, suffix: &str) -> Option<String> {
    let key = format!("APT::Periodic::{suffix}");
    config.lines().find_map(|line| {
        let value = line.trim().strip_prefix(&key)?.trim();
        if value.is_empty() || value.starts_with('#') {
            return None;
        }
        Some(
            value
                .trim_end_matches(';')
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string(),
        )
    })
}

fn parse_timer_state(states: &str, unit: &str) -> Option<String> {
    states.lines().find_map(|line| {
        let (candidate, state) = line.split_once(':')?;
        (candidate.trim() == unit).then(|| state.trim().to_string())
    })
}

fn parse_timer_runs(timers: &str, unit: &str) -> Option<(String, String)> {
    timers.lines().find_map(|line| {
        let tokens: Vec<_> = line.split_whitespace().collect();
        let unit_index = tokens.iter().position(|token| *token == unit)?;
        let before_unit = &tokens[..unit_index];
        if before_unit.is_empty() {
            return None;
        }
        let dates: Vec<usize> = before_unit
            .iter()
            .enumerate()
            .filter_map(|(index, token)| is_iso_date(token).then_some(index))
            .collect();
        let (next, last) = match dates.as_slice() {
            [next_date, last_date] => (
                timestamp_at(before_unit, *next_date),
                timestamp_at(before_unit, *last_date),
            ),
            // systemd prints `n/a` for an empty NEXT column, and newer releases (259 on
            // Ubuntu 26.04) print `-`. `-` also fills LEFT and PASSED, so only the first
            // token tells whether the single date is the last run.
            [only_date] if matches!(before_unit.first(), Some(&"n/a" | &"-")) => {
                ("n/a".into(), timestamp_at(before_unit, *only_date))
            }
            [only_date] => (timestamp_at(before_unit, *only_date), "n/a".into()),
            [] => ("n/a".into(), "n/a".into()),
            _ => return None,
        };
        Some((next, last))
    })
}

fn is_iso_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
}

fn timestamp_at(tokens: &[&str], date_index: usize) -> String {
    let start = date_index.saturating_sub(1);
    let end = (date_index + 3).min(tokens.len());
    tokens[start..end].join(" ")
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

    // ── unattended_upgrades_status ──────────────────────────────────────────

    const UNATTENDED_UPGRADES_FIXTURE: &str = r#"__SYSKNIFE_CONFIG_BEGIN__
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
__SYSKNIFE_CONFIG_END__
__SYSKNIFE_TIMERS_BEGIN__
NEXT                        LEFT          LAST                         PASSED       UNIT                    ACTIVATES
Mon 2026-10-26 04:36:12 CST 6h            Sun 2026-10-25 13:22:57 CST  8h ago       apt-daily.timer         apt-daily.service
Mon 2026-10-26 06:08:07 CST 8h            Sun 2026-10-25 06:05:00 CST 15h ago      apt-daily-upgrade.timer apt-daily-upgrade.service
__SYSKNIFE_TIMERS_END__
__SYSKNIFE_TIMER_STATES_BEGIN__
apt-daily.timer: enabled
apt-daily-upgrade.timer: enabled
__SYSKNIFE_TIMER_STATES_END__
__SYSKNIFE_LOG_BEGIN__
2026-10-25 06:05:00,123 INFO Initial blacklisted packages:
__SYSKNIFE_LOG_END__"#;

    #[test]
    fn unattended_upgrades_parser_reports_values_schedules_and_newest_log_entry() {
        let output = parse_unattended_upgrades_status(UNATTENDED_UPGRADES_FIXTURE);
        assert!(output.contains("APT::Periodic::Update-Package-Lists: 1 (enabled)"));
        assert!(output.contains("APT::Periodic::Unattended-Upgrade: 1 (enabled)"));
        assert!(output.contains("apt-daily.timer: enabled; last run: Sun 2026-10-25 13:22:57 CST; next run: Mon 2026-10-26 04:36:12 CST"));
        assert!(output.contains("apt-daily-upgrade.timer: enabled; last run: Sun 2026-10-25 06:05:00 CST; next run: Mon 2026-10-26 06:08:07 CST"));
        assert!(
            output.contains("Latest unattended-upgrades log entry: 2026-10-25 06:05:00,123 INFO")
        );
    }

    #[test]
    fn unattended_upgrades_parser_reports_zero_as_off() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE.replace(
            r#"APT::Periodic::Update-Package-Lists "1";"#,
            r#"APT::Periodic::Update-Package-Lists "0";"#,
        );
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(output.contains("APT::Periodic::Update-Package-Lists: 0 (off)"));
    }

    #[test]
    fn unattended_upgrades_parser_reports_disabled_timer() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE
            .replace(
                "Mon 2026-10-26 06:08:07 CST 8h            Sun 2026-10-25 06:05:00 CST 15h ago      apt-daily-upgrade.timer apt-daily-upgrade.service",
                "n/a                         n/a           n/a                         n/a          apt-daily-upgrade.timer apt-daily-upgrade.service",
            )
            .replace(
            "apt-daily-upgrade.timer: enabled",
            "apt-daily-upgrade.timer: disabled",
            );
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(output.contains("apt-daily-upgrade.timer: disabled; last run: n/a; next run: n/a"));
    }

    #[test]
    fn a_timer_with_a_dash_for_next_has_no_next_run() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE.replace(
            "Mon 2026-10-26 06:08:07 CST 8h            Sun 2026-10-25 06:05:00 CST 15h ago      apt-daily-upgrade.timer apt-daily-upgrade.service",
            "-                              - Sun 2026-10-25 06:05:00 CST      15h ago apt-daily-upgrade.timer apt-daily-upgrade.service",
        );
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(
            output.contains("apt-daily-upgrade.timer: enabled; last run: Sun 2026-10-25 06:05:00 CST; next run: n/a"),
            "{output}"
        );
    }

    #[test]
    fn a_timer_with_dashes_in_every_column_has_no_runs() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE.replace(
            "Mon 2026-10-26 06:08:07 CST 8h            Sun 2026-10-25 06:05:00 CST 15h ago      apt-daily-upgrade.timer apt-daily-upgrade.service",
            "-                              -                           -       - apt-daily-upgrade.timer apt-daily-upgrade.service",
        );
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(
            output.contains("apt-daily-upgrade.timer: enabled; last run: n/a; next run: n/a"),
            "{output}"
        );
    }

    #[test]
    fn unattended_upgrades_parser_reports_missing_log_directory_as_unknown() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE.replace(
            "2026-10-25 06:05:00,123 INFO Initial blacklisted packages:",
            "__MISSING_LOG_DIR__",
        );
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(output.contains("Latest unattended-upgrades log entry: unknown (/var/log/unattended-upgrades: directory missing)"));
        assert!(!output.contains("Latest unattended-upgrades log entry: ok"));
    }

    #[test]
    fn unattended_upgrades_parser_reports_unreadable_log_directory_as_unknown() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE.replace(
            "2026-10-25 06:05:00,123 INFO Initial blacklisted packages:",
            "__UNREADABLE_LOG_DIR__",
        );
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(output.contains("Latest unattended-upgrades log entry: unknown (/var/log/unattended-upgrades: directory not readable by the daemon user)"));
        assert!(!output.contains("no timestamped log entry"));
    }

    #[test]
    fn unattended_upgrades_script_checks_log_directory_access_before_reading_it() {
        let spec = unattended_upgrades_status();
        let (_, args) = extract_args(&spec);
        let script = args.last().expect("bash -c script");
        assert!(script.contains(r#"[ -r "$log_dir" ] && [ -x "$log_dir" ]"#));
        assert!(script.contains("__UNREADABLE_LOG_DIR__"));
    }

    #[test]
    fn unattended_upgrades_parser_reports_missing_config_as_unknown_for_both_keys() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE.replace(
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";",
            "__MISSING_CONFIG__",
        );
        assert!(fixture.contains("__MISSING_CONFIG__"));
        let output = parse_unattended_upgrades_status(&fixture);
        for key in [
            "APT::Periodic::Update-Package-Lists",
            "APT::Periodic::Unattended-Upgrade",
        ] {
            assert!(
                output.contains(&format!(
                    "{key}: unknown (/etc/apt/apt.conf.d/20auto-upgrades: file missing or unreadable)"
                )),
                "{key} not reported unknown: {output}"
            );
        }
        assert!(!output.contains("(enabled)"));
    }

    #[test]
    fn unattended_upgrades_parser_reports_disabled_timer_without_a_list_timers_row() {
        let fixture = UNATTENDED_UPGRADES_FIXTURE
            .replace(
                "Mon 2026-10-26 06:08:07 CST 8h            Sun 2026-10-25 06:05:00 CST 15h ago      apt-daily-upgrade.timer apt-daily-upgrade.service\n",
                "",
            )
            .replace(
                "apt-daily-upgrade.timer: enabled",
                "apt-daily-upgrade.timer: disabled",
            );
        assert!(!fixture.contains("apt-daily-upgrade.service"));
        let output = parse_unattended_upgrades_status(&fixture);
        assert!(output.contains("apt-daily-upgrade.timer: disabled; last run: n/a; next run: n/a"));
    }

    #[test]
    fn unattended_upgrades_status_is_a_low_risk_read_only_query() {
        let spec = unattended_upgrades_status();
        assert_eq!(spec.risk_level, RiskLevel::Low);
        let (program, args) = extract_args(&spec);
        assert_eq!(program, "bash");
        assert!(args.iter().any(|arg| arg.contains("systemctl list-timers")));
        assert!(args.iter().any(|arg| arg.contains("20auto-upgrades")));
        assert!(args.iter().all(|arg| !arg.contains("--dry-run")));
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
            "UnattendedUpgradesStatus",
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
