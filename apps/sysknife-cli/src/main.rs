mod approval;
mod cli;
mod client;
mod distro_routing;
mod error;
mod mcp_server;
mod operator_text;
mod render;
mod runner;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::runner::{Logger, RunOpts};

/// Startup is deliberately synchronous up to the point the runtime is built.
///
/// `LacsConfig::apply_defaults_to_env` writes environment variables, which is
/// only sound while the process is still single-threaded — a tokio worker pool
/// reading the environment concurrently would be undefined behaviour. Under
/// `#[tokio::main]` the runtime already exists by the time `main`'s body runs,
/// so the config load has to happen here, before the runtime is constructed.
/// Everything after `block_on` behaves exactly as it did under the attribute.
fn main() {
    let cli = Cli::parse();

    // Apply `~/.config/sysknife/config.toml` as env-var defaults so the rest of
    // the CLI — and the MCP server, which shares this entry point — reads the
    // operator's configured socket, provider and model instead of only the
    // process environment. Values already present in the environment win, so an
    // explicit `SYSKNIFE_*` still overrides the file.
    sysknife_core::config::LacsConfig::load().apply_defaults_to_env();

    // Resolve socket target once for all subcommands. Must follow the config
    // load: the socket may come from the file.
    let socket = runner::resolve_socket_target();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sysknife: could not start the async runtime: {e}");
            std::process::exit(4);
        }
    };
    runtime.block_on(run(cli, socket));
}

async fn run(cli: Cli, socket: crate::client::SocketTarget) {
    // Set up logger (tee to file when --log-to is present).
    let log = match Logger::new(cli.log_to.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sysknife: {e}");
            std::process::exit(4);
        }
    };

    // Dispatch.
    let result: Result<(), crate::error::CliError> = async {
        // Wrap everything in an optional hard timeout.
        if let Some(secs) = cli.timeout {
            tokio::time::timeout(
                std::time::Duration::from_secs(secs),
                dispatch(&cli, socket, &log),
            )
            .await
            .unwrap_or_else(|_| {
                Err(crate::error::CliError::ExecutionFailed(format!(
                    "operation timed out after {secs}s"
                )))
            })
        } else {
            dispatch(&cli, socket, &log).await
        }
    }
    .await;

    if let Err(e) = result {
        // `Exit` means the subcommand owns its own output and has already
        // printed a report (e.g. `doctor`, `audit verify`). Printing here too
        // showed the user the same failure twice.
        match &e {
            // The subcommand owns its own output and has already printed a
            // report (e.g. `doctor`, `audit verify`).
            crate::error::CliError::Exit(_) => {}
            // A refusal is an answer, not a fault. It gets the reason on its own
            // line and the suggested correction underneath, rather than being
            // flattened into one "sysknife: ..." error line the way a genuine
            // failure is (#179).
            crate::error::CliError::Refused { reason, suggestion } => {
                eprintln!("Cannot satisfy that request.");
                eprintln!("  {}", crate::operator_text::operator_safe(reason));
                if let Some(s) = suggestion {
                    eprintln!("  Try: {}", crate::operator_text::operator_safe(s));
                }
            }
            _ => eprintln!("sysknife: {e}"),
        }
        std::process::exit(e.exit_code());
    }
}

async fn dispatch(
    cli: &Cli,
    socket: crate::client::SocketTarget,
    log: &Logger,
) -> Result<(), crate::error::CliError> {
    match &cli.command {
        // --- sysknife completions <shell> ---
        Some(Command::Completions { shell }) => {
            runner::run_completions(*shell);
            Ok(())
        }

        // --- sysknife doctor ---
        Some(Command::Doctor) => runner::run_doctor(socket, cli.json, log).await,

        // --- sysknife history [flags] ---
        Some(Command::History(args)) => runner::run_history(args.clone(), socket, log).await,

        // --- sysknife approve <transaction-id> ---
        Some(Command::Approve { transaction_id }) => {
            runner::run_approve(
                &sysknife_types::TransactionId::new(transaction_id.clone()),
                socket,
                cli.json,
                log,
            )
            .await
        }

        // --- sysknife mcp-server ---
        Some(Command::McpServer) => mcp_server::run_mcp_server().await,

        // --- sysknife audit verify ---
        Some(Command::Audit { command }) => match command {
            crate::cli::AuditCommand::Export(args) => {
                runner::run_audit_export(args.clone(), log).await
            }
            crate::cli::AuditCommand::Verify(args) => {
                runner::run_audit_verify(args.clone(), log).await
            }
            crate::cli::AuditCommand::Checkpoint(args) => {
                runner::run_audit_checkpoint(args.clone(), log).await
            }
        },

        // --- sysknife <intent words ...> ---
        Some(Command::Intent(_)) => {
            let intent = cli
                .command
                .as_ref()
                .unwrap()
                .intent_string()
                .expect("Intent variant always has a string");
            let opts = build_run_opts(cli, socket);
            runner::run_intent(intent, &opts, log).await
        }

        // --- sysknife  (no subcommand → REPL) ---
        None => {
            let opts = build_run_opts(cli, socket);
            runner::run_repl(&opts, log).await
        }
    }
}

fn build_run_opts(cli: &Cli, socket: crate::client::SocketTarget) -> RunOpts {
    RunOpts {
        socket,
        yes: cli.yes,
        max_risk: cli.max_risk.map(crate::approval::MaxRisk::from),
        non_interactive: cli.non_interactive,
        dry_run: cli.dry_run,
        json: cli.json,
        step_by_step: cli.step_by_step,
    }
}
