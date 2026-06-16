//! Top-level dispatch for all `sysknife` CLI commands.
//!
//! Each public `run_*` function corresponds to one subcommand or the
//! free-form intent path.  All printed output goes through [`Logger`] so
//! that `--log-to` tee works transparently.
//!
//! ## Approval flow
//!
//! Without `--step-by-step`: [`ApprovalPolicy::decide_plan`] is called once
//! for the whole plan.  If a single confirmation is needed the user is asked
//! once, then all steps execute in sequence.
//!
//! With `--step-by-step`: [`ApprovalPolicy::decide_step`] is called before
//! each step so the user can approve or reject them individually.
//!
//! `--dry-run` short-circuits before any execution: the plan is printed and
//! the function returns `Ok(())`.

use std::io::{self, Write as _};
use std::path::PathBuf;

use clap::CommandFactory;
use serde_json::{json, Value};
use sysknife_brain::config::BrainConfig;
use sysknife_brain::planner::{LlmPlanner, PlanRiskLevel};
use sysknife_brain::PlanEvent;
use sysknife_types::{DistroHint, DISTRO_FAMILY_DEBIAN, DISTRO_FAMILY_FEDORA, DISTRO_FAMILY_OTHER};

use sysknife_brain::state_client::StateClient as _;

use crate::approval::{ApprovalDecision, ApprovalPolicy, MaxRisk};
use crate::cli::{AuditVerifyArgs, Cli, HistoryArgs};
use crate::client::{DaemonClient, SocketTarget};
use crate::error::CliError;

// ---------------------------------------------------------------------------
// distro_id_to_hint — DistroId → DistroHint conversion
// ---------------------------------------------------------------------------

/// Convert a `sysknife_core::distro::DistroId` to a `DistroHint` for the planner.
///
/// This is the single place where the CLI bridges the detection layer
/// (`sysknife-core`) and the planning layer (`sysknife-brain`), keeping each
/// side independent of the other.
pub fn distro_id_to_hint(distro: &sysknife_core::distro::DistroId) -> DistroHint {
    use sysknife_core::distro::DistroFamily;
    let family = match distro.family() {
        DistroFamily::Fedora => DISTRO_FAMILY_FEDORA,
        DistroFamily::Debian => DISTRO_FAMILY_DEBIAN,
        DistroFamily::Other => DISTRO_FAMILY_OTHER,
    };
    DistroHint {
        family,
        version: Some(distro.to_string()),
    }
}

// ---------------------------------------------------------------------------
// resolve_socket / resolve_socket_target
// ---------------------------------------------------------------------------

/// Returns the daemon [`SocketTarget`] from `$SYSKNIFE_SOCKET`.
///
/// Falls back to the system-wide Unix socket default when the env var is absent.
/// Exits the process with an error message if the env var is set but unparseable.
pub fn resolve_socket_target() -> SocketTarget {
    match std::env::var("SYSKNIFE_SOCKET") {
        Ok(s) => SocketTarget::try_from_str(&s).unwrap_or_else(|e| {
            eprintln!("sysknife: invalid SYSKNIFE_SOCKET: {e}");
            std::process::exit(1);
        }),
        Err(_) => SocketTarget::Unix(PathBuf::from("/run/sysknife/daemon.sock")),
    }
}

// ---------------------------------------------------------------------------
// since_to_hours
// ---------------------------------------------------------------------------

/// Parse an RFC 3339 / ISO-8601 UTC datetime string and return the number of
/// whole hours that have elapsed since that moment.
///
/// Returns `None` when:
/// - the string is not a valid UTC timestamp (`Z` or `+00:00` suffix),
/// - the datetime is in the future, or
/// - the value is too large to fit in `u32`.
///
/// Sub-second precision (`.NNN`) is accepted and truncated.  Non-zero UTC
/// offsets are not supported and return `None`.
pub fn since_to_hours(s: &str) -> Option<u32> {
    let epoch = rfc3339_to_unix(s)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    if epoch > now {
        return None;
    }
    u32::try_from((now - epoch) / 3600).ok()
}

/// Parse a UTC RFC 3339 string to seconds since Unix epoch (no external dep).
///
/// Supports `YYYY-MM-DDThh:mm:ssZ` and `YYYY-MM-DDThh:mm:ss+00:00`.
/// Sub-second fractions are stripped.
///
/// Uses Howard Hinnant's civil day algorithm to convert a proleptic-Gregorian
/// date to a day count, then scales to seconds.
fn rfc3339_to_unix(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00"))?;

    // Split on the 'T' separator.
    let (date_part, time_and_frac) = s.split_once('T')?;

    // Drop sub-second fractions: keep only up to "hh:mm:ss".
    let time_part = &time_and_frac[..time_and_frac.find('.').unwrap_or(time_and_frac.len())];
    if time_part.len() < 8 {
        return None;
    }

    // Parse date components.
    let mut date_iter = date_part.splitn(4, '-');
    let y: i64 = date_iter.next()?.parse().ok()?;
    let m: i64 = date_iter.next()?.parse().ok()?;
    let d: i64 = date_iter.next()?.parse().ok()?;
    if date_iter.next().is_some() {
        return None; // extra segments → reject
    }

    // Parse time components.
    let mut time_iter = time_part.splitn(4, ':');
    let h: i64 = time_iter.next()?.parse().ok()?;
    let mn: i64 = time_iter.next()?.parse().ok()?;
    let sec: i64 = time_iter.next()?.parse().ok()?;
    if time_iter.next().is_some() {
        return None; // extra segments → reject
    }

    // Range validation.
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mn > 59 || sec > 60
    // allow leap second
    {
        return None;
    }

    // Howard Hinnant's civil_from_days: compute days since 1970-01-01.
    //
    // Reference: https://howardhinnant.github.io/date_algorithms.html
    // The civil epoch starts on 0000-03-01; shift y back by 1 for Jan/Feb so
    // Feb 29 falls at the end of its civil year.
    let z = if m > 2 { y } else { y - 1 };
    let era = (if z >= 0 { z } else { z - 399 }) / 400;
    let yoe = z - era * 400; // year-of-era [0, 399]
    let m_adj = if m > 2 { m - 3 } else { m + 9 }; // month-of-civil-year [0, 11]
    let doy = (153 * m_adj + 2) / 5 + d - 1; // day-of-year from Mar 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day-of-era
    let days = era * 146097 + doe - 719468; // days since 1970-01-01

    Some(days * 86_400 + h * 3600 + mn * 60 + sec)
}

// ---------------------------------------------------------------------------
// highest_risk
// ---------------------------------------------------------------------------

/// Return the highest risk level present in `plan`.
///
/// Returns `None` only if the plan has no steps; in practice `Plan::new`
/// enforces at least one step, so callers may safely `.expect` the result.
pub fn highest_risk(plan: &sysknife_brain::planner::Plan) -> Option<&PlanRiskLevel> {
    plan.steps()
        .iter()
        .max_by_key(|s| match s.risk_level() {
            PlanRiskLevel::Low => 0u8,
            PlanRiskLevel::Medium => 1,
            PlanRiskLevel::High => 2,
        })
        .map(|s| s.risk_level())
}

// ---------------------------------------------------------------------------
// build_history_params (private helper)
// ---------------------------------------------------------------------------

pub(crate) fn build_history_params(
    limit: u32,
    status: Option<&str>,
    action: Option<&str>,
    since_hours: Option<u32>,
) -> Value {
    let mut params = json!({ "limit": limit });
    if let Some(s) = status {
        params["status_filter"] = json!(s);
    }
    if let Some(a) = action {
        params["action_filter"] = json!(a);
    }
    if let Some(h) = since_hours {
        params["since_hours"] = json!(h);
    }
    params
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

/// Tees all output to stdout and optionally to a log file.
///
/// `Mutex` makes `Logger` `Send + Sync` so it can be shared across the async
/// executor boundary without requiring a separate Arc.
pub struct Logger {
    file: std::sync::Mutex<Option<std::fs::File>>,
}

impl Logger {
    /// Construct.  Pass `None` to disable file tee.
    pub fn new(path: Option<&std::path::Path>) -> Result<Self, CliError> {
        let file = match path {
            None => None,
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(p)
                    .map_err(|e| CliError::ConfigOrDaemon(format!("open log file: {e}")))?,
            ),
        };
        Ok(Self {
            file: std::sync::Mutex::new(file),
        })
    }

    /// Print `line` to stdout and, if a log file is configured, also append it
    /// to that file.
    ///
    /// On the first file-write failure a warning is emitted to stderr and the
    /// file tee is permanently disabled so that subsequent writes do not spin
    /// on a dead handle.  The stdout print always succeeds (or panics, which is
    /// the correct response to a broken stdout in a CLI tool).
    pub fn println(&self, line: &str) {
        println!("{line}");
        let mut guard = self.file.lock().expect("Logger mutex poisoned");
        if let Some(f) = guard.as_mut() {
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("sysknife: log write failed ({e}); --log-to tee disabled");
                *guard = None;
            }
        }
    }

    /// Print `line` to stderr only.  Not teed to the log file — errors belong
    /// on stderr and must not be mixed into a structured log meant for parsing.
    pub fn print_stderr(&self, line: &str) {
        eprintln!("{line}");
    }
}

// ---------------------------------------------------------------------------
// run_completions
// ---------------------------------------------------------------------------

/// Write a shell completion script for `shell` to stdout.
pub fn run_completions(shell: clap_complete::Shell) {
    clap_complete::generate(shell, &mut Cli::command(), "sysknife", &mut io::stdout());
}

// ---------------------------------------------------------------------------
// run_doctor
// ---------------------------------------------------------------------------

/// Check daemon connectivity and print configuration summary.
pub async fn run_doctor(
    socket: SocketTarget,
    json_out: bool,
    log: &Logger,
) -> Result<(), CliError> {
    let config = BrainConfig::from_env().map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;

    let socket_label = format!("{socket:?}");
    let client = DaemonClient::new(socket);

    // Detect the running distro once; failure is non-fatal for doctor.
    let distro_label = match sysknife_core::distro::detect() {
        Ok(d) => d.to_string(),
        Err(e) => format!("unknown ({})", e),
    };

    // `curated_state` is a blocking sync call; use spawn_blocking so the
    // multi-threaded runtime is not blocked on one thread indefinitely.
    let state_result = tokio::task::spawn_blocking(move || client.curated_state())
        .await
        .map_err(|e| CliError::ConfigOrDaemon(format!("join: {e}")))?;

    match state_result {
        Ok(state) => {
            if json_out {
                let out = json!({
                    "ok": true,
                    "socket": socket_label,
                    "host": state.host_name(),
                    "provider": config.provider_name(),
                    "model": config.model_name(),
                    "distro": distro_label,
                });
                log.println(&serde_json::to_string(&out).expect("static JSON"));
            } else {
                crate::render::print_doctor_ok(
                    &socket_label,
                    state.host_name(),
                    config.provider_name(),
                    config.model_name(),
                    &distro_label,
                    log,
                );
            }
            Ok(())
        }
        Err(e) => {
            if json_out {
                let out = json!({ "ok": false, "error": e.to_string() });
                log.println(&serde_json::to_string(&out).expect("static JSON"));
            } else {
                crate::render::print_doctor_fail(&e.to_string());
            }
            Err(CliError::ConfigOrDaemon(e.to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// run_history
// ---------------------------------------------------------------------------

/// Query past SysKnife execution history via `ListJobHistory`.
pub async fn run_history(
    args: HistoryArgs,
    socket: SocketTarget,
    log: &Logger,
) -> Result<(), CliError> {
    let since_hours = match args.since.as_deref() {
        None => None,
        Some(s) => {
            // Distinguish the two failure modes so the user knows how to fix each.
            if rfc3339_to_unix(s).is_none() {
                return Err(CliError::ConfigOrDaemon(format!(
                    "--since: {s:?} is not a valid UTC RFC 3339 timestamp \
                     (accepted formats: 2026-01-15T10:30:00Z or 2026-01-15T10:30:00+00:00)"
                )));
            }
            match since_to_hours(s) {
                Some(h) => Some(h),
                None => {
                    return Err(CliError::ConfigOrDaemon(format!(
                        "--since: {s:?} is in the future"
                    )));
                }
            }
        }
    };

    let params = build_history_params(
        args.limit,
        args.status.as_deref(),
        args.action.as_deref(),
        since_hours,
    );

    let client = DaemonClient::new(socket);
    let output =
        tokio::task::spawn_blocking(move || client.query_action("ListJobHistory", &params))
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("join: {e}")))?
            .map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;

    log.println(&output);
    Ok(())
}

// ---------------------------------------------------------------------------
// RunOpts
// ---------------------------------------------------------------------------

/// Options derived from global CLI flags; threaded into `run_intent` and
/// `run_repl` so callers do not have to pass each flag individually.
pub struct RunOpts {
    pub socket: SocketTarget,
    pub yes: bool,
    pub max_risk: Option<MaxRisk>,
    pub non_interactive: bool,
    pub dry_run: bool,
    pub json: bool,
    pub step_by_step: bool,
}

impl RunOpts {
    /// Build the `ApprovalPolicy` for this set of flags.
    pub fn approval_policy(&self) -> ApprovalPolicy {
        ApprovalPolicy::new(self.yes, self.max_risk, self.non_interactive, self.dry_run)
    }
}

// ---------------------------------------------------------------------------
// run_audit_verify
// ---------------------------------------------------------------------------

/// Walk the audit log hash chain and report integrity status.
///
/// Resolves the database path via [`sysknife_core::default_database_path`]
/// (same precedence as the daemon: `$SYSKNIFE_DATABASE_PATH` →
/// `$XDG_STATE_HOME/sysknife/daemon.sqlite` → fallbacks). Loads the audit
/// key from the path the daemon would generate it at (sibling of the DB,
/// or `$SYSKNIFE_AUDIT_KEY_PATH`).
///
/// Exit codes:
/// - 0 — chain intact across all rows
/// - 1 — chain broken; first offending row is reported
/// - 2 — verification could not be completed (missing key, unreadable DB,
///   retired key not on disk, etc.)
///
/// On exit code 2, do **not** treat the audit log as either intact or
/// tampered — the result is unknown until the operator resolves the
/// underlying access problem.
pub async fn run_audit_verify(args: AuditVerifyArgs, log: &Logger) -> Result<(), CliError> {
    use sysknife_core::config::LacsConfig;
    use sysknife_daemon::audit_chain::{self, AuditKey, VerifyOutcome};

    // Honour the same `[storage]` config the daemon uses, so `sysknife audit
    // verify` works against whichever backend is in production. Without this,
    // a Postgres-backed deployment can never verify its chain from the CLI.
    let lacs_config = LacsConfig::load();

    let label_for_diag = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => "postgres".to_string(),
        _ => sysknife_core::default_database_path().display().to_string(),
    };

    // Load the audit HMAC key. Its location is the same across SQLite and
    // Postgres (sibling of the SQLite path, or `$SYSKNIFE_AUDIT_KEY_PATH`).
    let db_path = sysknife_core::default_database_path();
    let key_path = std::env::var("SYSKNIFE_AUDIT_KEY_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            db_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("audit-key")
        });

    if !key_path.exists() {
        let reason = format!(
            "audit key not found at {}; the daemon generates this on first run, \
             or set $SYSKNIFE_AUDIT_KEY_PATH",
            key_path.display()
        );
        emit_verify_outcome(
            &args,
            log,
            &VerifyOutcome::CannotVerify { reason },
            &label_for_diag,
        );
        return Err(CliError::Exit(2));
    }

    let key = match AuditKey::load_or_generate(&key_path) {
        Ok(k) => k,
        Err(e) => {
            let reason = format!("audit key load failed: {e}");
            emit_verify_outcome(
                &args,
                log,
                &VerifyOutcome::CannotVerify { reason },
                &label_for_diag,
            );
            return Err(CliError::Exit(2));
        }
    };

    // Branch on storage backend. SQLite: open the local file read-only.
    // Postgres: connect via sqlx and verify against the remote chain.
    let outcome = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => verify_postgres(s, &key).await,
        _ => verify_sqlite(&db_path, &key).await,
    };

    let exit_code = audit_chain::outcome_to_exit_code(&outcome);
    emit_verify_outcome(&args, log, &outcome, &label_for_diag);
    if exit_code == 0 {
        Ok(())
    } else {
        Err(CliError::Exit(exit_code))
    }
}

pub(crate) async fn verify_sqlite(
    db_path: &std::path::Path,
    key: &sysknife_daemon::audit_chain::AuditKey,
) -> sysknife_daemon::audit_chain::VerifyOutcome {
    use sysknife_daemon::audit_chain::VerifyOutcome;
    use sysknife_daemon::transactions::TransactionStore;

    if !db_path.exists() {
        return VerifyOutcome::CannotVerify {
            reason: format!(
                "audit database not found at {}; set $SYSKNIFE_DATABASE_PATH \
                 or run the daemon first",
                db_path.display()
            ),
        };
    }
    let store = match TransactionStore::open_read_only(db_path) {
        Ok(s) => s,
        Err(e) => {
            return VerifyOutcome::CannotVerify {
                reason: format!("opening audit database failed: {e}"),
            };
        }
    };
    match store.verify_audit_chain(key) {
        Ok(o) => o,
        Err(e) => VerifyOutcome::CannotVerify {
            reason: format!("audit chain query failed: {e}"),
        },
    }
}

pub(crate) async fn verify_postgres(
    storage: &sysknife_core::config::StorageSection,
    key: &sysknife_daemon::audit_chain::AuditKey,
) -> sysknife_daemon::audit_chain::VerifyOutcome {
    use sysknife_core::config::StorageBackend;
    use sysknife_daemon::audit_chain::VerifyOutcome;
    use sysknife_daemon::store::postgres::{PostgresConfig, PostgresStore};
    use sysknife_daemon::store::AuditStore;

    // Project the relaxed config form into the type-state-checked enum;
    // the match below makes future backends a compile-time decision.
    let parsed = match storage.parsed() {
        Ok(p) => p,
        Err(reason) => return VerifyOutcome::CannotVerify { reason },
    };
    let (url, pool) =
        match parsed {
            StorageBackend::Sqlite => return VerifyOutcome::CannotVerify {
                reason:
                    "verify_postgres called with backend = \"sqlite\" — caller picks the wrong path"
                        .to_string(),
            },
            StorageBackend::Postgres { url, pool } => (url, pool),
        };

    let mut cfg = PostgresConfig {
        url,
        ..PostgresConfig::default()
    };
    {
        if let Some(n) = pool.max_connections {
            cfg.max_connections = n;
        }
        if let Some(s) = pool.acquire_timeout_secs {
            cfg.acquire_timeout = std::time::Duration::from_secs(s);
        }
        if let Some(c) = pool.statement_cache_capacity {
            cfg.statement_cache_capacity = c;
        }
    }

    // PostgresStore::connect takes ownership of the key inside an Arc.
    // Clone the loaded key so the SQLite verify path can still use it if
    // both backends are ever queried in sequence (today only one runs).
    let key_arc = std::sync::Arc::new(key.clone());
    let store = match PostgresStore::connect(&cfg, key_arc).await {
        Ok(s) => s,
        Err(e) => {
            return VerifyOutcome::CannotVerify {
                reason: format!("postgres connect failed: {e}"),
            };
        }
    };
    match store.verify_audit_chain(key).await {
        Ok(o) => o,
        Err(e) => VerifyOutcome::CannotVerify {
            reason: format!("postgres audit chain query failed: {e}"),
        },
    }
}

fn emit_verify_outcome(
    args: &AuditVerifyArgs,
    log: &Logger,
    outcome: &sysknife_daemon::audit_chain::VerifyOutcome,
    backend_label: &str,
) {
    use sysknife_daemon::audit_chain::VerifyOutcome;
    if args.json {
        let payload = match outcome {
            VerifyOutcome::Intact { rows_checked } => json!({
                "status": "intact",
                "rows_checked": rows_checked,
                "backend": backend_label,
            }),
            VerifyOutcome::Broken {
                rows_checked,
                first_broken_seq,
                first_broken_transaction_id,
                expected,
                actual,
            } => json!({
                "status": "broken",
                "rows_checked": rows_checked,
                "first_broken_seq": first_broken_seq,
                "first_broken_transaction_id": first_broken_transaction_id,
                "expected": expected,
                "actual": actual,
                "backend": backend_label,
            }),
            VerifyOutcome::CannotVerify { reason } => json!({
                "status": "cannot_verify",
                "reason": reason,
                "backend": backend_label,
            }),
        };
        log.println(&serde_json::to_string_pretty(&payload).unwrap_or_default());
    } else {
        match outcome {
            VerifyOutcome::Intact { rows_checked } => {
                log.println(&format!(
                    "OK: {rows_checked} row(s) verified in {backend_label}"
                ));
            }
            VerifyOutcome::Broken {
                rows_checked,
                first_broken_seq,
                first_broken_transaction_id,
                expected,
                actual,
            } => {
                log.println(&format!(
                    "BROKEN: chain intact for first {rows_checked} row(s); \
                     row seq={first_broken_seq} (transaction {first_broken_transaction_id}) \
                     does not chain.\n  expected: {expected}\n  actual:   {actual}"
                ));
            }
            VerifyOutcome::CannotVerify { reason } => {
                log.println(&format!("CANNOT VERIFY: {reason}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// run_intent
// ---------------------------------------------------------------------------

/// Plan and (optionally) execute a single natural-language intent.
pub async fn run_intent(intent: String, opts: &RunOpts, log: &Logger) -> Result<(), CliError> {
    let config = BrainConfig::from_env().map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;

    // Detect the running distro once at intent startup.
    // Failure is non-fatal: routing checks are skipped when detection fails
    // (the daemon will produce its own error at execution time).
    let distro = sysknife_core::distro::detect().ok();

    let plan_client = DaemonClient::new(opts.socket.clone());

    // Layer 3: planning event channel — planner emits PlanEvent as it works;
    // the CLI subscribes and updates the spinner message in real time.
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<PlanEvent>();

    let mut planner = LlmPlanner::from_config(config, Box::new(plan_client))
        .map_err(CliError::ConfigOrDaemon)?
        .with_prefs_path(sysknife_core::config::prefs_path())
        .with_progress(progress_tx);
    if let Some(ref d) = distro {
        planner = planner.with_distro(distro_id_to_hint(d));
    }

    // Layer 1: spinner — auto-hidden by indicatif when stderr is not a TTY.
    let spinner = if !opts.json {
        Some(crate::render::make_spinner(format!(
            "Planning \"{intent}\"…"
        )))
    } else {
        None
    };

    // Spawn event updater: receives PlanEvent and updates the spinner message.
    // The task exits naturally when the channel closes (i.e. when the planner
    // is dropped after plan_intent returns).
    let spinner_for_task = spinner.clone();
    let event_task = tokio::spawn(async move {
        while let Some(event) = progress_rx.recv().await {
            if let Some(ref pb) = spinner_for_task {
                match event {
                    PlanEvent::Thinking => pb.set_message("Thinking…"),
                    PlanEvent::QueryingTool(ref name) => {
                        pb.set_message(format!("Querying {name}…"))
                    }
                    PlanEvent::ProposingPlan => pb.set_message("Proposing plan…"),
                }
            }
        }
    });

    // `plan_intent` may call `StateClient::curated_state()` (a blocking sync
    // Unix socket call) on the current async thread.  This is tolerable on
    // the multi-threaded runtime: the call is bounded by SOCKET_TIMEOUT (10 s)
    // and ties up one worker thread for at most that duration.
    let plan_result = planner.plan_intent(&intent).await;

    // Drop the planner to close the UnboundedSender, which closes the channel
    // and allows event_task to drain and exit.
    drop(planner);
    if let Err(e) = event_task.await {
        eprintln!("sysknife: event task panicked: {e}");
    }

    if let Some(ref pb) = spinner {
        pb.finish_and_clear();
    }

    let plan = plan_result.map_err(|e| CliError::PlanningFailed(e.to_string()))?;

    // ---- print plan --------------------------------------------------------

    if opts.json {
        let steps: Vec<Value> = plan
            .steps()
            .iter()
            .map(|s| {
                json!({
                    "action": s.action_name(),
                    "summary": s.summary(),
                    "risk": s.risk_level().as_str(),
                    "params": s.params(),
                })
            })
            .collect();
        log.println(
            &serde_json::to_string(&json!({
                "plan": { "intent": plan.intent(), "summary": plan.summary(), "steps": steps }
            }))
            .expect("static JSON"),
        );
    } else {
        crate::render::print_plan(&plan, log);
    }

    if opts.dry_run {
        if opts.step_by_step {
            log.print_stderr("warning: --step-by-step has no effect with --dry-run");
        }
        return Ok(());
    }

    // ---- plan-level approval (non-step-by-step) ----------------------------

    let policy = opts.approval_policy();

    if !opts.step_by_step {
        match policy.decide_plan(&plan) {
            ApprovalDecision::AutoApproved => {}
            ApprovalDecision::RequiresPrompt => {
                let n = plan.steps().len();
                let highest = highest_risk(&plan).expect("plan has steps");
                let msg = if opts.json {
                    "Execute this plan?".to_owned()
                } else {
                    format!(
                        "  {} step{}, {} risk — execute?",
                        n,
                        if n == 1 { "" } else { "s" },
                        crate::render::risk_colored(highest),
                    )
                };
                if !prompt_confirm(&msg).await {
                    return Err(CliError::Rejected);
                }
            }
            ApprovalDecision::RequiresInteraction => return Err(CliError::NonInteractive),
            ApprovalDecision::ExceedsCeiling => {
                let highest =
                    highest_risk(&plan).expect("ExceedsCeiling implies at least one step");
                return Err(CliError::RiskCeilingExceeded {
                    highest: highest.clone(),
                    ceiling: opts
                        .max_risk
                        .expect("ExceedsCeiling implies --max-risk was set"),
                });
            }
        }
    }

    // ---- distro routing guard ---------------------------------------------
    // Validate every step's action against the detected distro before
    // executing anything.  This surfaces a clear error for obviously wrong
    // plans (e.g. AptInstall on Fedora) without touching the daemon.
    if !opts.dry_run {
        for step in plan.steps() {
            if let Err(msg) =
                crate::distro_routing::check_action_distro(step.action_name(), distro.as_ref())
            {
                return Err(CliError::ConfigOrDaemon(msg));
            }
        }
    }

    // ---- execute steps -----------------------------------------------------

    let exec_client = DaemonClient::new(opts.socket.clone());
    let start = std::time::Instant::now();

    for step in plan.steps() {
        // Step-by-step: approve each step before previewing it.
        if opts.step_by_step {
            match policy.decide_step(step.risk_level()) {
                ApprovalDecision::AutoApproved => {}
                ApprovalDecision::RequiresPrompt => {
                    let msg = if opts.json {
                        format!("Execute {} ({})?", step.action_name(), step.summary())
                    } else {
                        format!(
                            "Execute {} ({} risk)?",
                            step.action_name(),
                            crate::render::risk_colored(step.risk_level()),
                        )
                    };
                    if !prompt_confirm(&msg).await {
                        return Err(CliError::Rejected);
                    }
                }
                ApprovalDecision::RequiresInteraction => return Err(CliError::NonInteractive),
                ApprovalDecision::ExceedsCeiling => {
                    return Err(CliError::RiskCeilingExceeded {
                        highest: step.risk_level().clone(),
                        ceiling: opts
                            .max_risk
                            .expect("ExceedsCeiling implies --max-risk was set"),
                    });
                }
            }
        }

        // Preview the step.
        let preview = exec_client
            .preview(step.action_name(), step.params())
            .await?;

        if opts.json {
            log.println(&serde_json::to_string(&preview).expect("PreviewEnvelope is Serialize"));
        } else {
            crate::render::print_step_header(step.action_name(), &preview);
        }

        // Spinner clears on the first output line so execution output
        // streams naturally without a spinner in the way.
        let exec_spinner: Option<indicatif::ProgressBar> = if !opts.json {
            Some(crate::render::make_spinner(format!(
                "Executing {}…",
                step.action_name()
            )))
        } else {
            None
        };
        let exec_spinner_ref = exec_spinner.clone();
        let mut first_line = true;

        let exec_result = exec_client
            .execute(
                step.action_name(),
                step.params(),
                preview.request_hash.as_str(),
                |line| {
                    if first_line {
                        if let Some(ref pb) = exec_spinner_ref {
                            pb.finish_and_clear();
                        }
                        first_line = false;
                    }
                    if opts.json {
                        log.println(line);
                    } else {
                        crate::render::print_output_line(line, log);
                    }
                },
            )
            .await;

        // Always clear the exec spinner regardless of success or error.
        // If the callback already fired, finish_and_clear() is idempotent.
        // If execute() errored before the first output line, this prevents
        // the spinner artifact from being left on the terminal.
        if let Some(ref pb) = exec_spinner {
            pb.finish_and_clear();
        }

        exec_result.map(|result| {
            if opts.json {
                log.println(&serde_json::to_string(&result).expect("ResultEnvelope is Serialize"));
            } else {
                crate::render::print_step_done(&result, log);
            }
        })?;
    }

    if !opts.json {
        crate::render::print_success(start.elapsed().as_secs_f32(), log);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// run_repl
// ---------------------------------------------------------------------------

/// Interactive REPL — reads intents with rustyline (arrow-key history,
/// Ctrl+R reverse search, Ctrl+C to cancel input, Ctrl+D to exit).
///
/// History persists across sessions in `~/.local/share/sysknife/history`.
///
/// `tokio::task::block_in_place` parks the current worker thread during each
/// blocking `readline()` call so other tasks on the multi-thread runtime can
/// run freely.  rustyline does not need to be `Send` with this approach.
pub async fn run_repl(opts: &RunOpts, log: &Logger) -> Result<(), CliError> {
    use rustyline::{error::ReadlineError, DefaultEditor};

    let history_path =
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share/sysknife/history"));

    let mut rl = DefaultEditor::new()
        .map_err(|e| CliError::ExecutionFailed(format!("readline init: {e}")))?;

    if let Some(ref p) = history_path {
        // Ensure the parent directory exists before the first load/save.
        if let Some(parent) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "sysknife: failed to create history directory {}: {e}",
                    parent.display()
                );
            }
        }
        // Absence of the history file is not an error; any other failure is.
        match rl.load_history(p) {
            Ok(()) => {}
            Err(rustyline::error::ReadlineError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                eprintln!("sysknife: failed to load history from {}: {e}", p.display());
            }
        }
    }

    loop {
        // Block the worker thread only during the blocking readline call.
        // Other tokio threads continue executing tasks unaffected.
        let readline_result = tokio::task::block_in_place(|| rl.readline("sysknife> "));

        match readline_result {
            Ok(line) => {
                let intent = line.trim().to_string();
                // Ignore the result: duplicates are silently skipped by rustyline.
                let _ = rl.add_history_entry(line.as_str());
                if intent.is_empty() {
                    continue;
                }
                if matches!(intent.as_str(), "exit" | "quit") {
                    break;
                }
                if let Err(e) = run_intent(intent, opts, log).await {
                    log.print_stderr(&format!("error: {e}"));
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(e) => {
                log.print_stderr(&format!("readline error: {e}"));
                break;
            }
        }
    }

    if let Some(ref p) = history_path {
        if let Err(e) = rl.save_history(p) {
            eprintln!("sysknife: failed to save history to {}: {e}", p.display());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Ask the user a yes/no question on stderr; return `true` iff they answer "y"
/// or "yes" (case-insensitive).
///
/// Uses `tokio::io::stdin` to keep the async executor free while waiting for
/// input.  On EOF or an I/O error a warning is printed to stderr and the
/// function returns `false` (safe default: do not execute).
async fn prompt_confirm(msg: &str) -> bool {
    use tokio::io::AsyncBufReadExt as _;

    eprint!("{msg} [y/N] ");
    let _ = io::stderr().flush();

    let stdin = tokio::io::stdin();
    let mut reader = tokio::io::BufReader::new(stdin);
    let mut buf = String::new();

    match reader.read_line(&mut buf).await {
        Ok(0) => {
            eprintln!("\nsysknife: stdin closed (EOF) — treating as 'no'");
            false
        }
        Err(e) => {
            eprintln!("\nsysknife: stdin read error ({e}) — treating as 'no'");
            false
        }
        Ok(_) => matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sysknife_brain::action_name::ActionName;
    use sysknife_brain::planner::{Plan, PlanStep};

    /// Serialize env-var mutations so concurrent tests do not race on
    /// `SYSKNIFE_SOCKET`.  All tests that call `set_var` / `remove_var` must
    /// hold this lock for the full duration of the env read.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // -----------------------------------------------------------------------
    // rfc3339_to_unix — pure function, tests against known epoch values
    // -----------------------------------------------------------------------

    #[test]
    fn rfc3339_unix_epoch_z() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn rfc3339_unix_epoch_plus00() {
        assert_eq!(rfc3339_to_unix("1970-01-01T00:00:00+00:00"), Some(0));
    }

    #[test]
    fn rfc3339_unix_one_day() {
        assert_eq!(rfc3339_to_unix("1970-01-02T00:00:00Z"), Some(86_400));
    }

    #[test]
    fn rfc3339_unix_y2k() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(rfc3339_to_unix("2000-01-01T00:00:00Z"), Some(946_684_800));
    }

    #[test]
    fn rfc3339_unix_leap_day_2000() {
        // 2000-02-29: Jan has 31 days, then 28 more days = 59 days from 2000-01-01.
        // 946684800 + 59 * 86400 = 946684800 + 5097600 = 951782400
        assert_eq!(rfc3339_to_unix("2000-02-29T00:00:00Z"), Some(951_782_400));
    }

    #[test]
    fn rfc3339_unix_with_subseconds() {
        // Sub-second fraction should be stripped.
        assert_eq!(
            rfc3339_to_unix("2000-01-01T00:00:00.123456Z"),
            Some(946_684_800)
        );
    }

    #[test]
    fn rfc3339_unix_non_utc_returns_none() {
        assert!(rfc3339_to_unix("2000-01-01T00:00:00+05:00").is_none());
    }

    #[test]
    fn rfc3339_unix_no_suffix_returns_none() {
        assert!(rfc3339_to_unix("2000-01-01T00:00:00").is_none());
    }

    #[test]
    fn rfc3339_unix_garbage_returns_none() {
        assert!(rfc3339_to_unix("not-a-date").is_none());
        assert!(rfc3339_to_unix("").is_none());
    }

    #[test]
    fn rfc3339_unix_invalid_month_returns_none() {
        assert!(rfc3339_to_unix("2000-13-01T00:00:00Z").is_none());
    }

    #[test]
    fn rfc3339_unix_invalid_hour_returns_none() {
        assert!(rfc3339_to_unix("2000-01-01T25:00:00Z").is_none());
    }

    #[test]
    fn rfc3339_unix_day_zero_returns_none() {
        // Day 0 is out of range; the lower bound of the `!(1..=31)` check.
        assert!(rfc3339_to_unix("2000-01-00T00:00:00Z").is_none());
    }

    // -----------------------------------------------------------------------
    // since_to_hours
    // -----------------------------------------------------------------------

    #[test]
    fn since_to_hours_y2k_is_many_hours_ago() {
        // Y2K was well over 200_000 hours ago (as of 2026).
        let h = since_to_hours("2000-01-01T00:00:00Z").expect("should parse");
        assert!(h > 200_000, "expected >200000 hours, got {h}");
    }

    #[test]
    fn since_to_hours_far_future_returns_none() {
        // Year 9999 is in the future.
        assert!(since_to_hours("9999-12-31T23:59:59Z").is_none());
    }

    #[test]
    fn since_to_hours_garbage_returns_none() {
        assert!(since_to_hours("not-a-date").is_none());
    }

    #[test]
    fn since_to_hours_epoch_returns_many_hours() {
        // Unix epoch (1970-01-01) is always ≥ 486000 hours ago (as of 2026).
        let h = since_to_hours("1970-01-01T00:00:00Z").expect("should parse");
        assert!(h > 486_000, "expected >486000, got {h}");
    }

    #[test]
    fn since_to_hours_integer_division_not_modulo() {
        // Two timestamps exactly 1 hour apart must differ by 1 in since_to_hours.
        // A `% 3600` regression would produce wildly different results for these.
        let h0 = since_to_hours("1970-01-01T00:00:00Z").unwrap();
        let h1 = since_to_hours("1970-01-01T01:00:00Z").unwrap();
        assert_eq!(h0, h1 + 1, "timestamps 1 h apart must differ by exactly 1");
    }

    // -----------------------------------------------------------------------
    // highest_risk
    // -----------------------------------------------------------------------

    fn make_step(risk: PlanRiskLevel) -> PlanStep {
        PlanStep::new(
            ActionName::parse("GetDiskUsage").unwrap(),
            "test".into(),
            risk,
            serde_json::json!({}),
        )
        .unwrap()
    }

    fn make_plan(risks: &[PlanRiskLevel]) -> Plan {
        Plan::new(
            "test".into(),
            "test plan".into(),
            "explanation".into(),
            risks.iter().map(|r| make_step(r.clone())).collect(),
        )
        .unwrap()
    }

    // Note: Plan::new rejects empty step lists (PlanValidationError), so
    // `highest_risk` is never called on an empty plan in practice.  The return
    // type is `Option<_>` purely for type-safety against future API changes.

    #[test]
    fn highest_risk_single_low() {
        let plan = make_plan(&[PlanRiskLevel::Low]);
        assert_eq!(highest_risk(&plan), Some(&PlanRiskLevel::Low));
    }

    #[test]
    fn highest_risk_all_high() {
        let plan = make_plan(&[PlanRiskLevel::High, PlanRiskLevel::High]);
        assert_eq!(highest_risk(&plan), Some(&PlanRiskLevel::High));
    }

    #[test]
    fn highest_risk_mixed_picks_highest() {
        let plan = make_plan(&[
            PlanRiskLevel::Low,
            PlanRiskLevel::High,
            PlanRiskLevel::Medium,
        ]);
        assert_eq!(highest_risk(&plan), Some(&PlanRiskLevel::High));
    }

    #[test]
    fn highest_risk_low_medium_picks_medium() {
        let plan = make_plan(&[PlanRiskLevel::Low, PlanRiskLevel::Medium]);
        assert_eq!(highest_risk(&plan), Some(&PlanRiskLevel::Medium));
    }

    // -----------------------------------------------------------------------
    // build_history_params
    // -----------------------------------------------------------------------

    #[test]
    fn build_history_params_minimal() {
        let p = build_history_params(20, None, None, None);
        assert_eq!(p["limit"], json!(20));
        assert!(p.get("status_filter").is_none());
        assert!(p.get("action_filter").is_none());
        assert!(p.get("since_hours").is_none());
    }

    #[test]
    fn build_history_params_all_fields() {
        let p = build_history_params(5, Some("succeeded"), Some("InstallPackages"), Some(48));
        assert_eq!(p["limit"], json!(5));
        assert_eq!(p["status_filter"], json!("succeeded"));
        assert_eq!(p["action_filter"], json!("InstallPackages"));
        assert_eq!(p["since_hours"], json!(48));
    }

    #[test]
    fn build_history_params_status_only() {
        let p = build_history_params(10, Some("failed"), None, None);
        assert_eq!(p["limit"], json!(10));
        assert_eq!(p["status_filter"], json!("failed"));
        assert!(p.get("action_filter").is_none());
        assert!(p.get("since_hours").is_none());
    }

    // -----------------------------------------------------------------------
    // run_history --since error mapping
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn run_history_invalid_since_returns_config_error() {
        // An unparseable --since must return CliError::ConfigOrDaemon without
        // ever touching the daemon socket (the socket path here is unused).
        let args = HistoryArgs {
            status: None,
            action: None,
            since: Some("not-a-date".into()),
            limit: 20,
        };
        let log = Logger::new(None).unwrap();
        let result = run_history(
            args,
            SocketTarget::Unix(PathBuf::from("/nonexistent.sock")),
            &log,
        )
        .await;
        match result {
            Err(CliError::ConfigOrDaemon(msg)) => {
                assert!(
                    msg.contains("--since"),
                    "error message must reference --since"
                );
            }
            other => panic!("expected ConfigOrDaemon, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_history_future_since_returns_config_error() {
        let args = HistoryArgs {
            status: None,
            action: None,
            since: Some("9999-12-31T23:59:59Z".into()),
            limit: 20,
        };
        let log = Logger::new(None).unwrap();
        let result = run_history(
            args,
            SocketTarget::Unix(PathBuf::from("/nonexistent.sock")),
            &log,
        )
        .await;
        match result {
            Err(CliError::ConfigOrDaemon(msg)) => {
                assert!(msg.contains("future"), "error must say 'future'");
            }
            other => panic!("expected ConfigOrDaemon, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // resolve_socket_target uses SYSKNIFE_SOCKET env var
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_socket_target_defaults_to_unix_when_unset() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("SYSKNIFE_SOCKET") };
        let t = resolve_socket_target();
        assert_eq!(
            t,
            crate::client::SocketTarget::Unix(PathBuf::from("/run/sysknife/daemon.sock"))
        );
    }

    #[test]
    fn resolve_socket_target_parses_unix_uri() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_SOCKET", "unix:///tmp/custom.sock") };
        let t = resolve_socket_target();
        unsafe { std::env::remove_var("SYSKNIFE_SOCKET") };
        assert_eq!(
            t,
            crate::client::SocketTarget::Unix(PathBuf::from("/tmp/custom.sock"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_socket_target_parses_vsock_uri() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("SYSKNIFE_SOCKET", "vsock://3:7777") };
        let t = resolve_socket_target();
        unsafe { std::env::remove_var("SYSKNIFE_SOCKET") };
        assert_eq!(t, crate::client::SocketTarget::Vsock { cid: 3, port: 7777 });
    }
}
