//! journald query + maintenance actions.
//!
//! `GetJournalLog` is a read-only, filtered read of the systemd journal in
//! structured JSON (`journalctl --output=json`); `VacuumJournal` reclaims disk
//! by trimming old journal files (`journalctl --vacuum-size` / `--vacuum-time`).
//!
//! Both run the `journalctl` binary directly (no `sudo`): the daemon runs as
//! root, so it can already read every journal and write the journal files.
//! Every filter is passed in **attached** `--flag=value` form so a value that
//! begins with `-` can never be reparsed as a separate option (option
//! injection); there is no shell involved, so spaces/regex metacharacters in a
//! value are inert.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_journal_log(&JournalQuery {
            lines: 100,
            unit: Some("ssh.service"),
            priority: Some("err"),
            boot: true,
            ..JournalQuery::default()
        }),
        vacuum_journal_by_size(500),
    ]
}

/// A validated journal query. All string fields are assumed to have passed the
/// executor's validators before reaching here.
#[derive(Default)]
pub struct JournalQuery<'a> {
    /// Number of most-recent lines to return (`--lines=`). Always set.
    pub lines: u32,
    /// Restrict to a single systemd unit (`--unit=`).
    pub unit: Option<&'a str>,
    /// Restrict by priority level or range (`--priority=`), e.g. `err`, `3`, `0..3`.
    pub priority: Option<&'a str>,
    /// Restrict to the current boot (`--boot`).
    pub boot: bool,
    /// Kernel ring-buffer messages only (`--dmesg`).
    pub kernel: bool,
    /// Entries at or after this time (`--since=`).
    pub since: Option<&'a str>,
    /// Entries at or before this time (`--until=`).
    pub until: Option<&'a str>,
    /// Regex filter on the MESSAGE field (`--grep=`).
    pub grep: Option<&'a str>,
}

/// Read filtered journal entries as JSON (`journalctl --output=json …`).
///
/// Read-only. JSON gives the caller structured fields (`__REALTIME_TIMESTAMP`,
/// `MESSAGE`, `_TRANSPORT`, `PRIORITY`, …) rather than a preformatted line, so a
/// model can reason over the entries.
pub fn get_journal_log(q: &JournalQuery) -> ActionSpec {
    let mut args = vec![
        "--output=json".to_string(),
        "--no-pager".to_string(),
        format!("--lines={}", q.lines),
    ];
    if let Some(unit) = q.unit {
        args.push(format!("--unit={unit}"));
    }
    if let Some(priority) = q.priority {
        args.push(format!("--priority={priority}"));
    }
    if q.boot {
        args.push("--boot".to_string());
    }
    if q.kernel {
        args.push("--dmesg".to_string());
    }
    if let Some(since) = q.since {
        args.push(format!("--since={since}"));
    }
    if let Some(until) = q.until {
        args.push(format!("--until={until}"));
    }
    if let Some(grep) = q.grep {
        args.push(format!("--grep={grep}"));
    }
    ActionSpec {
        action_name: "GetJournalLog",
        mechanism: command_mechanism("journalctl", args),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Trim the journal to at most `megabytes` MB on disk (`--vacuum-size=<n>M`).
pub fn vacuum_journal_by_size(megabytes: u32) -> ActionSpec {
    vacuum_journal(format!("--vacuum-size={megabytes}M"))
}

/// Trim journal files older than `days` days (`--vacuum-time=<n>d`).
pub fn vacuum_journal_by_time(days: u32) -> ActionSpec {
    vacuum_journal(format!("--vacuum-time={days}d"))
}

fn vacuum_journal(vacuum_flag: String) -> ActionSpec {
    ActionSpec {
        action_name: "VacuumJournal",
        mechanism: command_mechanism("journalctl", [vacuum_flag]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn args_of(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (program, args.clone()),
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn get_journal_log_builds_attached_filters() {
        let spec = get_journal_log(&JournalQuery {
            lines: 50,
            unit: Some("nginx.service"),
            priority: Some("err"),
            boot: true,
            kernel: false,
            since: Some("2026-07-22 10:00:00"),
            until: None,
            grep: Some("timeout"),
        });
        let (program, args) = args_of(&spec);
        assert_eq!(program, "journalctl");
        assert_eq!(args[0], "--output=json");
        assert!(args.contains(&"--lines=50".to_string()));
        assert!(args.contains(&"--unit=nginx.service".to_string()));
        assert!(args.contains(&"--priority=err".to_string()));
        assert!(args.contains(&"--boot".to_string()));
        assert!(args.contains(&"--since=2026-07-22 10:00:00".to_string()));
        assert!(args.contains(&"--grep=timeout".to_string()));
        // omitted filters must not appear
        assert!(!args.iter().any(|a| a.starts_with("--until=")));
        assert!(!args.iter().any(|a| a == "--dmesg"));
        assert_eq!(spec.risk_level, RiskLevel::Low);
    }

    #[test]
    fn kernel_query_uses_dmesg() {
        let spec = get_journal_log(&JournalQuery {
            lines: 10,
            kernel: true,
            ..JournalQuery::default()
        });
        let (_, args) = args_of(&spec);
        assert!(args.contains(&"--dmesg".to_string()));
    }

    #[test]
    fn vacuum_by_size_and_time() {
        let (_, size_args) = args_of(&vacuum_journal_by_size(200));
        assert_eq!(size_args, vec!["--vacuum-size=200M"]);
        let (_, time_args) = args_of(&vacuum_journal_by_time(7));
        assert_eq!(time_args, vec!["--vacuum-time=7d"]);
        assert_eq!(vacuum_journal_by_size(1).risk_level, RiskLevel::Medium);
    }
}
