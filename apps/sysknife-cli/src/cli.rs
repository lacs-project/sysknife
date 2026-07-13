//! CLI argument parser for the `sysknife` binary.
//!
//! Structure:
//! - [`Cli`] — top-level struct carrying all global flags
//! - [`Command`] — named subcommands; [`Command::Intent`] catches free-form words
//! - [`HistoryArgs`] — arguments specific to `sysknife history`
//! - [`MaxRiskArg`] — `--max-risk` value-enum bridging to `approval::MaxRisk`
//!
//! Free-form intents work because `Command::Intent` uses `external_subcommand`:
//! any first argument that does not match a named subcommand is captured there.
//! `sysknife "check disk usage"` and `sysknife check disk usage` both produce an
//! `Intent` variant; the words are joined with spaces to form the intent string.

use std::ffi::OsString;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::approval::MaxRisk;

/// Linux System Management CLI.
///
/// With no arguments, starts an interactive REPL.
/// Pass a natural-language intent to plan and execute in one shot.
#[derive(Parser, Debug)]
#[command(name = "sysknife", version, about = "Linux System Management CLI")]
pub struct Cli {
    /// Auto-approve steps up to the effective risk ceiling.
    ///
    /// Alone, approves LOW only. With `--max-risk medium`, approves up to
    /// MEDIUM. HIGH steps always require explicit human confirmation —
    /// `--yes` cannot auto-approve them regardless of `--max-risk`.
    #[arg(long, global = true)]
    pub yes: bool,

    /// Maximum risk level to allow; abort if the plan exceeds this ceiling.
    #[arg(long, value_name = "LEVEL", global = true)]
    pub max_risk: Option<MaxRiskArg>,

    /// Fail immediately if any step would require interactive approval.
    #[arg(long, global = true)]
    pub non_interactive: bool,

    /// Display the plan without executing anything.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Emit NDJSON instead of human-readable output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Hard timeout in seconds; abort the whole operation after this.
    #[arg(long, value_name = "SECS", global = true)]
    pub timeout: Option<u64>,

    /// Append all output to FILE in addition to stdout.
    #[arg(long, value_name = "FILE", global = true)]
    pub log_to: Option<std::path::PathBuf>,

    /// Confirm each step individually instead of the whole plan at once.
    #[arg(long, global = true)]
    pub step_by_step: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Named subcommands for `sysknife`.
///
/// Any first argument that does not match a named subcommand is collected
/// by `Command::Intent` via clap's `external_subcommand` mechanism.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Check daemon connectivity and print configuration.
    Doctor,

    /// Query past SysKnife execution history.
    History(HistoryArgs),

    /// Print shell completion script to stdout.
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Start an MCP server over stdio.
    ///
    /// Exposes `sysknife_plan` and `sysknife_execute` tools so Claude Code,
    /// Claude Desktop, Cursor, and any other MCP-capable agent can plan and
    /// execute Linux administration tasks via the SysKnife daemon.
    ///
    /// Add to `claude_desktop_config.json`:
    ///   { "mcpServers": { "sysknife": { "command": "sysknife", "args": ["mcp-server"] } } }
    #[command(name = "mcp-server")]
    McpServer,

    /// Audit log integrity tools.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },

    /// Execute a natural-language intent.
    ///
    /// Words not matching any named subcommand are captured here.
    /// `sysknife "check disk usage"` and `sysknife check disk usage` both work.
    #[command(external_subcommand)]
    Intent(Vec<OsString>),
}

impl Command {
    /// If this command is `Intent`, join the captured words into a single
    /// intent string. Returns `None` for any other variant.
    pub fn intent_string(&self) -> Option<String> {
        match self {
            Command::Intent(words) => Some(
                words
                    .iter()
                    .map(|w| w.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            _ => None,
        }
    }
}

/// `sysknife audit <subcommand>` subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum AuditCommand {
    /// Verify the tamper-evident Ed25519-signed hash chain over the audit log.
    ///
    /// Exits 0 if the chain is intact, 1 if any row is broken, and 2 if the
    /// chain cannot be verified (missing key file, retired key not on disk,
    /// unreadable database, etc.). The 1/2 split matters: a CI pipeline
    /// expecting 0 or 1 must not silently pass on a missing key file.
    Verify(AuditVerifyArgs),
}

/// Arguments for `sysknife audit verify`.
#[derive(Args, Debug, Clone)]
pub struct AuditVerifyArgs {
    /// Emit a machine-readable JSON report instead of human-friendly text.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `sysknife history`.
#[derive(Args, Debug, Clone)]
pub struct HistoryArgs {
    /// Filter by job status (succeeded, failed, canceled, …).
    #[arg(long, value_name = "STATUS")]
    pub status: Option<String>,

    /// Filter by action name.
    #[arg(long, value_name = "ACTION")]
    pub action: Option<String>,

    /// Show only entries after this ISO-8601 datetime.
    #[arg(long, value_name = "DATETIME")]
    pub since: Option<String>,

    /// Maximum number of entries to return.
    #[arg(long, default_value = "20", value_name = "N")]
    pub limit: u32,
}

/// Clap value-enum for `--max-risk`.
///
/// Converts to [`MaxRisk`] via [`From`] so the rest of the codebase
/// uses the domain type directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum MaxRiskArg {
    Low,
    Medium,
    High,
}

impl From<MaxRiskArg> for MaxRisk {
    fn from(arg: MaxRiskArg) -> MaxRisk {
        match arg {
            MaxRiskArg::Low => MaxRisk::Low,
            MaxRiskArg::Medium => MaxRisk::Medium,
            MaxRiskArg::High => MaxRisk::High,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn no_args_parses_with_no_command_and_no_flags() {
        let cli = Cli::try_parse_from(["sysknife"]).unwrap();
        assert!(cli.command.is_none());
        assert!(!cli.yes);
        assert!(!cli.dry_run);
        assert!(!cli.non_interactive);
        assert!(!cli.json);
        assert!(!cli.step_by_step);
        assert!(cli.timeout.is_none());
        assert!(cli.max_risk.is_none());
        assert!(cli.log_to.is_none());
    }

    #[test]
    fn multi_word_intent_captured_as_intent_variant() {
        let cli = Cli::try_parse_from(["sysknife", "check", "disk", "usage"]).unwrap();
        let intent = cli.command.as_ref().unwrap().intent_string().unwrap();
        assert_eq!(intent, "check disk usage");
    }

    #[test]
    fn quoted_single_arg_intent_captured_verbatim() {
        let cli = Cli::try_parse_from(["sysknife", "check disk usage"]).unwrap();
        let intent = cli.command.as_ref().unwrap().intent_string().unwrap();
        assert_eq!(intent, "check disk usage");
    }

    #[test]
    fn yes_flag_parsed() {
        let cli = Cli::try_parse_from(["sysknife", "--yes", "intent"]).unwrap();
        assert!(cli.yes);
    }

    #[test]
    fn max_risk_low_medium_high_parsed() {
        for (input, expected) in [
            ("low", MaxRiskArg::Low),
            ("medium", MaxRiskArg::Medium),
            ("high", MaxRiskArg::High),
        ] {
            let cli = Cli::try_parse_from(["sysknife", "--max-risk", input]).unwrap();
            assert_eq!(cli.max_risk.unwrap(), expected);
        }
    }

    #[test]
    fn max_risk_arg_converts_to_max_risk() {
        assert_eq!(MaxRisk::from(MaxRiskArg::Low), MaxRisk::Low);
        assert_eq!(MaxRisk::from(MaxRiskArg::Medium), MaxRisk::Medium);
        assert_eq!(MaxRisk::from(MaxRiskArg::High), MaxRisk::High);
    }

    #[test]
    fn dry_run_and_non_interactive_parsed() {
        let cli =
            Cli::try_parse_from(["sysknife", "--dry-run", "--non-interactive", "intent"]).unwrap();
        assert!(cli.dry_run);
        assert!(cli.non_interactive);
    }

    #[test]
    fn json_and_timeout_and_step_by_step_parsed() {
        let cli = Cli::try_parse_from([
            "sysknife",
            "--json",
            "--timeout",
            "30",
            "--step-by-step",
            "intent",
        ])
        .unwrap();
        assert!(cli.json);
        assert_eq!(cli.timeout, Some(30));
        assert!(cli.step_by_step);
    }

    #[test]
    fn log_to_path_parsed() {
        let cli =
            Cli::try_parse_from(["sysknife", "--log-to", "/tmp/sysknife.log", "intent"]).unwrap();
        assert_eq!(
            cli.log_to.as_deref(),
            Some(std::path::Path::new("/tmp/sysknife.log"))
        );
    }

    #[test]
    fn doctor_subcommand_parsed() {
        let cli = Cli::try_parse_from(["sysknife", "doctor"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Doctor)));
    }

    #[test]
    fn history_subcommand_default_limit() {
        let cli = Cli::try_parse_from(["sysknife", "history"]).unwrap();
        match cli.command {
            Some(Command::History(args)) => {
                assert_eq!(args.limit, 20);
                assert!(args.status.is_none());
                assert!(args.action.is_none());
                assert!(args.since.is_none());
            }
            other => panic!("expected Command::History, got {other:?}"),
        }
    }

    #[test]
    fn history_subcommand_with_all_flags() {
        let cli = Cli::try_parse_from([
            "sysknife",
            "history",
            "--limit",
            "5",
            "--status",
            "succeeded",
            "--action",
            "InstallPackages",
            "--since",
            "2026-01-01T00:00:00Z",
        ])
        .unwrap();
        match cli.command {
            Some(Command::History(args)) => {
                assert_eq!(args.limit, 5);
                assert_eq!(args.status.as_deref(), Some("succeeded"));
                assert_eq!(args.action.as_deref(), Some("InstallPackages"));
                assert_eq!(args.since.as_deref(), Some("2026-01-01T00:00:00Z"));
            }
            other => panic!("expected Command::History, got {other:?}"),
        }
    }

    #[test]
    fn global_flags_work_before_subcommand() {
        let cli = Cli::try_parse_from(["sysknife", "--yes", "--dry-run", "doctor"]).unwrap();
        assert!(cli.yes);
        assert!(cli.dry_run);
        assert!(matches!(cli.command, Some(Command::Doctor)));
    }

    #[test]
    fn intent_string_returns_none_for_non_intent_commands() {
        let cli = Cli::try_parse_from(["sysknife", "doctor"]).unwrap();
        assert!(cli.command.unwrap().intent_string().is_none());
    }

    #[test]
    fn completions_subcommand_parsed() {
        let cli = Cli::try_parse_from(["sysknife", "completions", "bash"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Completions {
                shell: clap_complete::Shell::Bash
            })
        ));
    }

    #[test]
    fn completions_unknown_shell_fails() {
        assert!(Cli::try_parse_from(["sysknife", "completions", "zsh-invalid"]).is_err());
    }

    #[test]
    fn history_with_partial_flags() {
        let cli =
            Cli::try_parse_from(["sysknife", "history", "--status", "failed", "--limit", "10"])
                .unwrap();
        match cli.command {
            Some(Command::History(args)) => {
                assert_eq!(args.status.as_deref(), Some("failed"));
                assert_eq!(args.limit, 10);
                assert!(args.action.is_none());
                assert!(args.since.is_none());
            }
            other => panic!("expected Command::History, got {other:?}"),
        }
    }
}
