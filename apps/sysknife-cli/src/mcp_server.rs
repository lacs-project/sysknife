//! MCP server entry point for `sysknife mcp-server`.
//!
//! Exposes five tools plus one discovery resource:
//!
//! - `sysknife_plan`         — turn a natural-language intent into a risk-labelled plan.
//! - `sysknife_execute`      — execute a plan returned by `sysknife_plan`.
//! - `sysknife_history`      — list past audit-log entries (read-only).
//! - `sysknife_doctor`       — daemon connectivity + config diagnostics (read-only).
//! - `sysknife_audit_verify` — verify the audit-log hash chain (read-only).
//!
//! Typical agentic loop:
//!
//! 1. Call `sysknife_plan { intent }` — show the plan to the user, explain risk.
//! 2. **STOP** — wait for explicit user approval before doing anything else.
//! 3. Call `sysknife_execute { steps, max_risk }` — daemon runs each step and
//!    streams output back as collected lines.
//!
//! The three read-only tools (`sysknife_history`, `sysknife_doctor`,
//! `sysknife_audit_verify`) are safe to call without going through the
//! plan/approve/execute loop — they only inspect state.
//!
//! The server uses stdio transport so any MCP client (Claude Desktop,
//! Cursor, …) can launch it as a local subprocess.
//!
//! Example `claude_desktop_config.json` entry:
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "sysknife": { "command": "sysknife", "args": ["mcp-server"] }
//!   }
//! }
//! ```

use std::path::PathBuf;

use rmcp::{
    handler::server::wrapper::{Json, Parameters},
    model::{
        AnnotateAble, Implementation, ListResourceTemplatesResult, ListResourcesResult,
        PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult, Resource,
        ResourceContents, ServerCapabilities, ServerInfo,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use sysknife_types::RiskLevel;

use sysknife_brain::config::BrainConfig;
use sysknife_brain::planner::LlmPlanner;
use sysknife_brain::state_client::StateClient as _;

use crate::client::{DaemonClient, DescribeInfo};
use crate::error::CliError;
use crate::runner::{build_history_params, resolve_socket_target, verify_postgres, verify_sqlite};

// ---------------------------------------------------------------------------
// sysknife_plan — input / output types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PlanInput {
    /// Natural-language intent, e.g. "show disk usage" or "add vim to my system".
    pub intent: String,
}

/// One action step in the proposed plan.
#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct PlanStepOutput {
    /// Canonical action name from the SysKnife catalogue.
    pub action_name: String,
    /// Human-readable description of what this step does.
    pub summary: String,
    /// Risk level: `"low"`, `"medium"`, or `"high"`.
    pub risk_level: String,
    /// Action-specific parameters.
    pub params: serde_json::Value,
    /// Formatted shell command that will run on the VM, e.g. `"timedatectl"`.
    /// Empty string when the daemon is unreachable.
    pub command: String,
}

/// The full plan returned by `sysknife_plan`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanOutput {
    /// The original natural-language intent.
    pub intent: String,
    /// One-line summary of the plan.
    pub summary: String,
    /// Longer explanation of why this plan was chosen.
    pub explanation: String,
    /// Ordered list of steps to execute.
    pub steps: Vec<PlanStepOutput>,
}

// ---------------------------------------------------------------------------
// sysknife_execute — input / output types
// ---------------------------------------------------------------------------

/// A single step to execute, taken verbatim from `sysknife_plan` output.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StepToExecute {
    /// Canonical action name from the SysKnife catalogue, e.g. `"GetDiskUsage"`.
    pub action_name: String,
    /// Action-specific parameters (pass through from the plan unchanged).
    pub params: serde_json::Value,
}

/// Input to `sysknife_execute`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteInput {
    /// Steps to execute — take the `steps` array from `sysknife_plan` output.
    pub steps: Vec<StepToExecute>,
    /// Highest risk level you are willing to execute without further
    /// confirmation.  One of `"low"`, `"medium"`, `"high"`.
    /// Defaults to `"medium"` if omitted.
    ///
    /// Steps whose daemon-assessed risk exceeds this ceiling cause the
    /// tool to return an error before any execution occurs.
    pub max_risk: Option<String>,
}

/// Execution result for a single step.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct StepResult {
    /// Action that was executed.
    pub action_name: String,
    /// Final status: `"succeeded"`, `"failed"`, `"needs_reboot"`, etc.
    pub status: String,
    /// Human-readable summary from the daemon.
    pub summary: String,
    /// Progress lines collected during execution (ANSI stripped).
    pub output: Vec<String>,
    /// Warnings emitted by the daemon for this step.
    pub warnings: Vec<String>,
    /// Whether this step requires a reboot to take effect.
    pub needs_reboot: bool,
    /// Daemon transaction ID for audit purposes.
    pub transaction_id: String,
}

/// Output of `sysknife_execute`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExecuteOutput {
    /// Results for each executed step, in order.
    pub steps: Vec<StepResult>,
    /// True if any step requires a reboot to take effect.
    pub needs_reboot: bool,
}

// ---------------------------------------------------------------------------
// sysknife_history — input / output types
// ---------------------------------------------------------------------------

/// Input to `sysknife_history`. All fields optional; mirrors the CLI flags
/// on `sysknife history`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HistoryInput {
    /// Filter by job status (e.g. `"succeeded"`, `"failed"`, `"canceled"`).
    pub status: Option<String>,
    /// Filter by action name (e.g. `"InstallPackages"`).
    pub action: Option<String>,
    /// Show only entries after this UTC RFC 3339 timestamp
    /// (e.g. `"2026-01-15T10:30:00Z"`).
    pub since: Option<String>,
    /// Maximum number of entries to return. Defaults to 20.
    pub limit: Option<u32>,
}

/// One row in the history listing.
///
/// `created_at` and `risk_level` are `None` until the daemon's
/// `ListJobHistory` IPC is extended to return structured rows. Today the
/// daemon serialises history as a formatted text block; the MCP wrapper
/// parses what it can — transaction ID prefix, action name, status, and
/// summary — and leaves the structured-only fields empty.
#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(default)]
pub struct HistoryEntry {
    /// Daemon transaction ID (or its short prefix when only that is available).
    pub transaction_id: String,
    /// Canonical action name from the SysKnife catalogue.
    pub action: String,
    /// Final job status (`"succeeded"`, `"failed"`, etc.).
    pub status: String,
    /// Human-readable summary from the daemon.
    pub summary: String,
    /// UTC RFC 3339 timestamp when the transaction was created.
    /// Currently always `None` — see struct-level docs.
    pub created_at: Option<String>,
    /// Risk level the daemon assigned (`"low"` | `"medium"` | `"high"`).
    /// Currently always `None` — see struct-level docs.
    pub risk_level: Option<String>,
}

/// Output wrapper for `sysknife_history`.
///
/// MCP requires the tool's output schema to have an `object` root type;
/// returning a bare `Vec<HistoryEntry>` produces an `array` root and
/// makes the rmcp `ToolRouter` panic at construction time.  Wrapping
/// the vec in a single-field struct gives the schema an object root
/// with one named property, satisfying the spec without any extra
/// runtime cost.
#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct HistoryOutput {
    pub entries: Vec<HistoryEntry>,
}

// ---------------------------------------------------------------------------
// sysknife_doctor — output types
// ---------------------------------------------------------------------------

/// Output of `sysknife_doctor`. Snapshot of daemon connectivity, brain
/// provider, and audit-chain health at the moment the tool was called.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct DoctorReport {
    /// Resolved daemon socket target, e.g. `"Unix(\"/run/sysknife/daemon.sock\")"`.
    pub daemon_socket: String,
    /// `true` iff the daemon answered `query_state` within the socket timeout.
    pub daemon_reachable: bool,
    /// Configured brain provider (`"anthropic"`, `"openai"`, `"ollama"`, …).
    pub brain_provider: String,
    /// Configured brain model identifier.
    pub brain_model: String,
    /// Detected Linux distribution, e.g. `"Ubuntu 24.04"` or `"Fedora 41"`.
    /// Set to `"unknown (<reason>)"` when `/etc/os-release` cannot be read.
    pub distro: String,
    /// Resolved audit DB path. For Postgres deployments, the literal string
    /// `"postgres"` instead of a filesystem path.
    pub audit_db_path: String,
    /// `"intact"` | `"broken"` | `"unknown"`. `"unknown"` covers all
    /// `CannotVerify` cases (missing key file, unreachable DB, etc.).
    pub audit_chain_status: String,
    /// Non-fatal warnings collected during the diagnostic run. Anything
    /// that could not be checked (state, brain config, audit chain, …)
    /// adds one entry here so the operator sees what was skipped and why.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// sysknife_audit_verify — output types
// ---------------------------------------------------------------------------

/// Output of `sysknife_audit_verify`. Mirrors the JSON shape produced by
/// the CLI's `sysknife audit verify --json` command.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct AuditVerifyReport {
    /// One of `"intact"`, `"broken"`, `"cannot_verify"`.
    pub status: String,
    /// Number of audit rows the verifier successfully checked. `0` for
    /// `cannot_verify` outcomes that fail before the first row is read.
    pub rows_checked: u64,
    /// Sequence number of the first row that broke the chain. Only set
    /// when `status == "broken"`.
    pub first_broken_seq: Option<u64>,
    /// Transaction ID of the first broken row. Only set when
    /// `status == "broken"`.
    pub first_broken_transaction_id: Option<String>,
    /// HMAC the verifier expected for the first broken row.
    pub expected: Option<String>,
    /// HMAC actually stored for the first broken row.
    pub actual: Option<String>,
    /// Human-readable explanation. Only set when `status == "cannot_verify"`.
    pub reason: Option<String>,
    /// Backend label: a filesystem path for SQLite, the literal `"postgres"`
    /// for Postgres deployments.
    pub backend: String,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SysknifeMcpServer;

const SYSKNIFE_DISCOVERY_URI: &str = "sysknife://about";
const SYSKNIFE_DISCOVERY_NAME: &str = "about";
const SYSKNIFE_DISCOVERY_TITLE: &str = "SysKnife MCP server";
const SYSKNIFE_DISCOVERY_DESCRIPTION: &str = "Discovery resource for Codex and other MCP clients.";
const SYSKNIFE_DISCOVERY_BODY: &str = "SysKnife exposes a small tool set for planning and executing Linux system administration tasks.\n\nUse `sysknife_plan` first, present the plan to the user, wait for explicit approval, and only then call `sysknife_execute`.\n\nAvailable read-only tools: `sysknife_history`, `sysknife_doctor`, and `sysknife_audit_verify`.";

fn sysknife_about_resource() -> Resource {
    rmcp::model::RawResource::new(SYSKNIFE_DISCOVERY_URI, SYSKNIFE_DISCOVERY_NAME)
        .with_title(SYSKNIFE_DISCOVERY_TITLE)
        .with_description(SYSKNIFE_DISCOVERY_DESCRIPTION)
        .with_mime_type("text/plain")
        .no_annotation()
}

#[tool_router]
impl SysknifeMcpServer {
    /// Plan a Linux system administration intent.
    ///
    /// Returns a JSON object with the proposed steps, each carrying an
    /// `action_name`, `summary`, `risk_level` ("low" | "medium" | "high"),
    /// `params`, and `command` (the resolved shell command). No action is
    /// executed — call `sysknife_execute` with the returned steps after the
    /// user approves the plan.
    #[tool(
        description = "Plan a Linux system administration intent. Returns typed steps with risk levels and the resolved shell command per step. IMPORTANT: After presenting this plan to the user, STOP immediately. Do not call any other tools. Wait for explicit user approval before proceeding."
    )]
    async fn sysknife_plan(
        &self,
        Parameters(PlanInput { intent }): Parameters<PlanInput>,
    ) -> Result<Json<PlanOutput>, ErrorData> {
        let value = plan_intent_inner(&intent)
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;
        let mut output: PlanOutput = serde_json::from_value(value).map_err(|e| {
            ErrorData::internal_error(format!("output deserialization error: {e}"), None)
        })?;
        enrich_with_commands(&mut output).await;
        Ok(Json(output))
    }

    /// Execute a plan produced by `sysknife_plan`.
    ///
    /// Pass the `steps` array from `sysknife_plan` output unchanged.  Set
    /// `max_risk` to the highest risk level you are willing to execute
    /// without further confirmation (`"low"` | `"medium"` | `"high"`;
    /// defaults to `"medium"`).
    ///
    /// Steps whose daemon-assessed risk exceeds `max_risk` cause an error
    /// before any execution occurs.  On failure mid-plan execution stops
    /// immediately and the error is returned.
    ///
    /// Returns per-step results including output lines, warnings, and
    /// whether a reboot is required.
    #[tool(
        description = "Execute a plan produced by sysknife_plan. Pass the steps array unchanged. Set max_risk to the highest risk you will execute without confirmation (low/medium/high, default medium). Returns per-step output, warnings, and reboot requirements."
    )]
    async fn sysknife_execute(
        &self,
        Parameters(ExecuteInput { steps, max_risk }): Parameters<ExecuteInput>,
    ) -> Result<Json<ExecuteOutput>, ErrorData> {
        execute_steps_inner(steps, max_risk.as_deref())
            .await
            .map(Json)
            .map_err(|e| ErrorData::internal_error(e, None))
    }

    /// List past SysKnife audit-log entries.
    ///
    /// Read-only and safe to call without first calling `sysknife_plan`;
    /// it never mutates system state. Mirrors `sysknife history`.
    #[tool(
        description = "List past SysKnife audit-log entries. Read-only and safe to call without prior sysknife_plan. Filters: status (succeeded/failed/canceled/...), action (canonical action name), since (UTC RFC 3339 timestamp), limit (default 20). Returns a list of HistoryEntry rows."
    )]
    async fn sysknife_history(
        &self,
        Parameters(input): Parameters<HistoryInput>,
    ) -> Result<Json<HistoryOutput>, ErrorData> {
        history_inner(input)
            .await
            .map(|entries| Json(HistoryOutput { entries }))
            .map_err(|e| ErrorData::internal_error(e, None))
    }

    /// Daemon connectivity + configuration diagnostics.
    ///
    /// Read-only and safe to call without first calling `sysknife_plan`;
    /// it never mutates system state. Mirrors `sysknife doctor` plus an
    /// audit-chain quick-check.
    #[tool(
        description = "Diagnose SysKnife: pings the daemon, reports the configured brain provider/model, the audit DB path, and a quick audit-chain status (intact/broken/unknown). Read-only and safe to call without prior sysknife_plan."
    )]
    async fn sysknife_doctor(&self) -> Result<Json<DoctorReport>, ErrorData> {
        Ok(Json(doctor_inner().await))
    }

    /// Verify the audit-log hash chain.
    ///
    /// Read-only and safe to call without first calling `sysknife_plan`;
    /// it never mutates system state. Mirrors `sysknife audit verify`.
    #[tool(
        description = "Verify the tamper-evident HMAC-SHA256 hash chain over the audit log. Returns status (intact/broken/cannot_verify), rows_checked, and — on broken — the first offending row. Read-only and safe to call without prior sysknife_plan."
    )]
    async fn sysknife_audit_verify(&self) -> Result<Json<AuditVerifyReport>, ErrorData> {
        Ok(Json(audit_verify_inner().await))
    }
}

#[tool_handler]
impl ServerHandler for SysknifeMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions(
            "SysKnife provides planning and execution tools for Linux system administration.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult {
            resources: vec![sysknife_about_resource()],
            next_cursor: None,
            meta: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult {
            resource_templates: Vec::new(),
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        ReadResourceRequestParams { uri, .. }: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        match uri.as_str() {
            SYSKNIFE_DISCOVERY_URI => Ok(ReadResourceResult::new(vec![ResourceContents::text(
                SYSKNIFE_DISCOVERY_BODY,
                uri,
            )])),
            _ => Err(ErrorData::resource_not_found(
                "resource_not_found",
                Some(serde_json::json!({ "uri": uri })),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// sysknife_plan helper
// ---------------------------------------------------------------------------

async fn plan_intent_inner(intent: &str) -> Result<serde_json::Value, String> {
    let config = BrainConfig::from_env().map_err(|e| format!("config error: {e}"))?;

    let state_client = DaemonClient::new(resolve_socket_target());

    // Detect the running distro and pass a hint to the planner so it picks
    // the right action family up front.  Failure is non-fatal.
    let distro = sysknife_core::distro::detect().ok();

    let mut planner = LlmPlanner::from_config(config, Box::new(state_client))
        .map_err(|e| format!("planner init error: {e}"))?;
    if let Some(ref d) = distro {
        planner = planner.with_distro(crate::runner::distro_id_to_hint(d));
    }

    // `plan_intent` may call `StateClient::curated_state()` (a blocking sync
    // Unix socket call) on the current async thread.  This is tolerable on
    // the multi-threaded runtime: the call is bounded by SOCKET_TIMEOUT (10 s)
    // and ties up one worker thread for at most that duration.  MCP sessions
    // are LLM-driven and sequential in practice, so concurrent saturation of
    // the thread pool is not a realistic concern here.
    let plan = planner
        .plan_intent(intent)
        .await
        .map_err(|e| format!("planning error: {e}"))?;

    serde_json::to_value(&plan).map_err(|e| format!("serialization error: {e}"))
}

/// For each step in the plan, call the daemon's `describe` endpoint to fill in
/// `command`.  On error the `command` field is set to `"[<error>]"` so the
/// user sees a visible signal rather than a silent empty string.  A wrong
/// action name or missing required param is a planning bug — surfacing it
/// in-band lets the user (and the model) diagnose the problem immediately.
async fn enrich_with_commands(output: &mut PlanOutput) {
    let client = DaemonClient::new(resolve_socket_target());
    for step in &mut output.steps {
        match client.describe(&step.action_name, &step.params).await {
            Ok(DescribeInfo { command, .. }) => step.command = command,
            Err(e) => step.command = format!("[{e}]"),
        }
    }
}

// ---------------------------------------------------------------------------
// sysknife_execute helper
// ---------------------------------------------------------------------------

async fn execute_steps_inner(
    steps: Vec<StepToExecute>,
    max_risk: Option<&str>,
) -> Result<ExecuteOutput, String> {
    let ceiling = parse_max_risk(max_risk)?;
    let client = DaemonClient::new(resolve_socket_target());

    let mut results: Vec<StepResult> = Vec::new();
    let mut plan_needs_reboot = false;

    for step in steps {
        // Preview: get daemon's authoritative risk assessment + request_hash.
        let preview = client
            .preview(&step.action_name, &step.params)
            .await
            .map_err(|e| format!("preview error for {}: {e}", step.action_name))?;

        // Risk gate: check daemon-assessed risk against the ceiling.
        check_risk_ceiling(&preview.risk_level, ceiling).map_err(|_| {
            format!(
                "step '{}' has risk '{:?}' which exceeds max_risk ceiling '{}'",
                step.action_name,
                preview.risk_level,
                max_risk.unwrap_or("medium"),
            )
        })?;

        // Execute and collect progress lines.
        let mut output_lines: Vec<String> = Vec::new();
        let result = client
            .execute(
                &step.action_name,
                &step.params,
                preview.request_hash.as_str(),
                |line| output_lines.push(line.to_owned()),
            )
            .await
            .map_err(|e| format!("execute error for {}: {e}", step.action_name))?;

        let needs_reboot = result.needs_reboot;
        if needs_reboot {
            plan_needs_reboot = true;
        }

        let status = serde_json::to_value(result.status)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "unknown".into());

        let succeeded = matches!(result.status, sysknife_types::JobState::Succeeded);

        results.push(StepResult {
            action_name: step.action_name,
            status,
            summary: result.summary,
            output: truncate_output(output_lines),
            warnings: result.warnings,
            needs_reboot,
            transaction_id: result.transaction_id,
        });

        // Halt on first failure — do not continue executing subsequent steps.
        if !succeeded {
            break;
        }
    }

    Ok(ExecuteOutput {
        steps: results,
        needs_reboot: plan_needs_reboot,
    })
}

// ---------------------------------------------------------------------------
// Pure helpers (also tested below)
// ---------------------------------------------------------------------------

/// Maximum number of output lines returned per step in the MCP response.
///
/// Large-output actions (e.g. `GetSystemState`, `CollectDiagnostics`) can
/// produce tens of thousands of lines which exceed MCP context windows.
/// Lines beyond this limit are dropped and a single summary line is appended.
const OUTPUT_LINE_LIMIT: usize = 500;

/// Truncate `lines` to at most `OUTPUT_LINE_LIMIT` entries.
///
/// If truncation occurs, a marker line is appended so the caller knows
/// output was cut.
fn truncate_output(mut lines: Vec<String>) -> Vec<String> {
    if lines.len() > OUTPUT_LINE_LIMIT {
        let dropped = lines.len() - OUTPUT_LINE_LIMIT;
        lines.truncate(OUTPUT_LINE_LIMIT);
        lines.push(format!("[truncated: {dropped} more lines omitted]"));
    }
    lines
}

/// Parse a `max_risk` string into an ordinal `u8` (0=low, 1=medium).
///
/// `None` defaults to medium (1). High-risk actions cannot be auto-executed
/// via the MCP entrypoint — that route exists for assistant-driven flows that
/// must always have a human in the loop, so the `"high"` ceiling is rejected
/// outright. Callers that need to run high-risk plans must use the CLI/GUI
/// approval path. Comparison is case-insensitive so `"Low"`, `"MEDIUM"`, etc.
/// are all accepted.
fn parse_max_risk(s: Option<&str>) -> Result<u8, String> {
    let raw = s.unwrap_or("medium");
    match raw.to_ascii_lowercase().as_str() {
        "low" => Ok(0),
        "medium" => Ok(1),
        "high" => Err(
            "max_risk=\"high\" is not allowed via MCP — high-risk plans must \
             be approved via the CLI or GUI confirmation flow"
                .to_string(),
        ),
        _ => Err(format!(
            "invalid max_risk {raw:?}: expected \"low\" or \"medium\""
        )),
    }
}

/// Convert a daemon `RiskLevel` to an ordinal comparable against `parse_max_risk`.
fn risk_level_ord(r: &RiskLevel) -> u8 {
    match r {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
    }
}

/// Return `Err(())` if `risk` exceeds `ceiling`.
fn check_risk_ceiling(risk: &RiskLevel, ceiling: u8) -> Result<(), ()> {
    if risk_level_ord(risk) > ceiling {
        Err(())
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// sysknife_history helpers
// ---------------------------------------------------------------------------

/// Default history limit, matching the CLI's `HistoryArgs::limit` default.
const HISTORY_DEFAULT_LIMIT: u32 = 20;

async fn history_inner(input: HistoryInput) -> Result<Vec<HistoryEntry>, String> {
    let HistoryInput {
        status,
        action,
        since,
        limit,
    } = input;

    let since_hours = match since.as_deref() {
        None => None,
        Some(s) => match crate::runner::since_to_hours(s) {
            Some(h) => Some(h),
            None => {
                return Err(format!(
                    "since: {s:?} is not a valid past UTC RFC 3339 timestamp \
                     (accepted: 2026-01-15T10:30:00Z)"
                ));
            }
        },
    };

    let params = build_history_params(
        limit.unwrap_or(HISTORY_DEFAULT_LIMIT),
        status.as_deref(),
        action.as_deref(),
        since_hours,
    );

    let client = DaemonClient::new(resolve_socket_target());
    let raw = tokio::task::spawn_blocking(move || client.query_action("ListJobHistory", &params))
        .await
        .map_err(|e| format!("join: {e}"))?
        .map_err(|e| format!("daemon error: {e}"))?;

    Ok(parse_history_text(&raw))
}

/// Parse the daemon's formatted `ListJobHistory` output into structured rows.
///
/// The daemon currently returns a header line, a blank line, then one row per
/// transaction in the format `  <8-char-prefix>  <action>  <status>  <summary>`,
/// with action and status padded by `format_job_history` in the daemon. We
/// split on at-least-two-spaces because the formatter uses field padding,
/// not a delimiter character.
///
/// `created_at` and `risk_level` are not present in the formatted output and
/// stay `None`. Extending the daemon-side IPC to return structured rows
/// would let us populate them — see HistoryEntry's struct-level docs.
fn parse_history_text(raw: &str) -> Vec<HistoryEntry> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        // Skip the header line ("Transaction history (N entries):"), blank
        // lines, and the empty-result line ("No transactions found...").
        let trimmed = line.trim_start();
        if trimmed.is_empty()
            || trimmed.starts_with("Transaction history")
            || trimmed.starts_with("No transactions found")
        {
            continue;
        }

        // Split on runs of 2+ whitespace chars — robust to the daemon's
        // padding without depending on exact column widths.
        let parts: Vec<&str> = trimmed.split("  ").filter(|s| !s.is_empty()).collect();
        if parts.len() < 4 {
            // Malformed row — skip rather than panic. Better to drop one
            // unparseable row than to fail the whole tool call.
            continue;
        }

        entries.push(HistoryEntry {
            transaction_id: parts[0].trim().to_string(),
            action: parts[1].trim().to_string(),
            status: parts[2].trim().to_string(),
            summary: parts[3..].join("  ").trim().to_string(),
            created_at: None,
            risk_level: None,
        });
    }
    entries
}

// ---------------------------------------------------------------------------
// sysknife_doctor helpers
// ---------------------------------------------------------------------------

async fn doctor_inner() -> DoctorReport {
    let mut warnings: Vec<String> = Vec::new();

    let socket = resolve_socket_target();
    let socket_label = format!("{socket:?}");

    // Detect the running distro — non-fatal if /etc/os-release is absent.
    let distro = match sysknife_core::distro::detect() {
        Ok(d) => d.to_string(),
        Err(e) => {
            let label = format!("unknown ({})", e);
            warnings.push(format!("distro detection failed: {e}"));
            label
        }
    };

    // Daemon connectivity — `curated_state` is sync, so spawn_blocking.
    let client = DaemonClient::new(socket);
    let daemon_reachable = match tokio::task::spawn_blocking(move || client.curated_state()).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            warnings.push(format!("daemon unreachable: {e}"));
            false
        }
        Err(e) => {
            warnings.push(format!("daemon ping join error: {e}"));
            false
        }
    };

    // Brain provider/model — fall back to placeholders if config is missing
    // (e.g. operator hasn't run `sysknife-setup` yet).
    let (brain_provider, brain_model) = match BrainConfig::from_env() {
        Ok(cfg) => (
            cfg.provider_name().to_string(),
            cfg.model_name().to_string(),
        ),
        Err(e) => {
            warnings.push(format!("brain config unreadable: {e}"));
            ("unknown".to_string(), "unknown".to_string())
        }
    };

    // Audit DB path / chain status — same precedence rules as `run_audit_verify`.
    let lacs_config = sysknife_core::config::LacsConfig::load();
    let audit_db_path = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => "postgres".to_string(),
        _ => sysknife_core::default_database_path().display().to_string(),
    };

    let audit_chain_status = match audit_chain_quick_check(&lacs_config, &mut warnings).await {
        VerifyOutcomeKind::Intact => "intact",
        VerifyOutcomeKind::Broken => "broken",
        VerifyOutcomeKind::Unknown => "unknown",
    }
    .to_string();

    DoctorReport {
        daemon_socket: socket_label,
        daemon_reachable,
        brain_provider,
        brain_model,
        distro,
        audit_db_path,
        audit_chain_status,
        warnings,
    }
}

/// Compact summary of `VerifyOutcome` for doctor's `audit_chain_status` field.
enum VerifyOutcomeKind {
    Intact,
    Broken,
    Unknown,
}

/// Run a non-fatal audit chain check. Anything that prevents verification
/// becomes `Unknown` plus a warning entry — the doctor must never hard-fail
/// just because the audit key file is missing.
async fn audit_chain_quick_check(
    lacs_config: &sysknife_core::config::LacsConfig,
    warnings: &mut Vec<String>,
) -> VerifyOutcomeKind {
    use sysknife_daemon::audit_chain::{AuditKey, VerifyOutcome};

    let db_path = sysknife_core::default_database_path();
    let key_path = std::env::var("SYSKNIFE_AUDIT_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            db_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("audit-key")
        });

    if !key_path.exists() {
        warnings.push(format!("audit key not found at {}", key_path.display()));
        return VerifyOutcomeKind::Unknown;
    }

    let key = match AuditKey::load_or_generate(&key_path) {
        Ok(k) => k,
        Err(e) => {
            warnings.push(format!("audit key load failed: {e}"));
            return VerifyOutcomeKind::Unknown;
        }
    };

    let outcome = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => verify_postgres(s, &key).await,
        _ => verify_sqlite(&db_path, &key).await,
    };

    match outcome {
        VerifyOutcome::Intact { .. } => VerifyOutcomeKind::Intact,
        VerifyOutcome::Broken { .. } => VerifyOutcomeKind::Broken,
        VerifyOutcome::CannotVerify { reason } => {
            warnings.push(format!("audit chain cannot be verified: {reason}"));
            VerifyOutcomeKind::Unknown
        }
    }
}

// ---------------------------------------------------------------------------
// sysknife_audit_verify helpers
// ---------------------------------------------------------------------------

async fn audit_verify_inner() -> AuditVerifyReport {
    use sysknife_daemon::audit_chain::AuditKey;

    let lacs_config = sysknife_core::config::LacsConfig::load();
    let backend_label = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => "postgres".to_string(),
        _ => sysknife_core::default_database_path().display().to_string(),
    };

    let db_path = sysknife_core::default_database_path();
    let key_path = std::env::var("SYSKNIFE_AUDIT_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            db_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("audit-key")
        });

    if !key_path.exists() {
        return cannot_verify_report(
            backend_label,
            format!(
                "audit key not found at {}; the daemon generates this on first run, \
                 or set $SYSKNIFE_AUDIT_KEY_PATH",
                key_path.display()
            ),
        );
    }

    let key = match AuditKey::load_or_generate(&key_path) {
        Ok(k) => k,
        Err(e) => {
            return cannot_verify_report(backend_label, format!("audit key load failed: {e}"));
        }
    };

    let outcome = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => verify_postgres(s, &key).await,
        _ => verify_sqlite(&db_path, &key).await,
    };

    outcome_to_report(outcome, backend_label)
}

fn outcome_to_report(
    outcome: sysknife_daemon::audit_chain::VerifyOutcome,
    backend: String,
) -> AuditVerifyReport {
    use sysknife_daemon::audit_chain::VerifyOutcome;
    match outcome {
        VerifyOutcome::Intact { rows_checked } => AuditVerifyReport {
            status: "intact".to_string(),
            rows_checked,
            first_broken_seq: None,
            first_broken_transaction_id: None,
            expected: None,
            actual: None,
            reason: None,
            backend,
        },
        VerifyOutcome::Broken {
            rows_checked,
            first_broken_seq,
            first_broken_transaction_id,
            expected,
            actual,
        } => AuditVerifyReport {
            status: "broken".to_string(),
            rows_checked,
            first_broken_seq: Some(first_broken_seq),
            first_broken_transaction_id: Some(first_broken_transaction_id),
            expected: Some(expected),
            actual: Some(actual),
            reason: None,
            backend,
        },
        VerifyOutcome::CannotVerify { reason } => cannot_verify_report(backend, reason),
    }
}

fn cannot_verify_report(backend: String, reason: String) -> AuditVerifyReport {
    AuditVerifyReport {
        status: "cannot_verify".to_string(),
        rows_checked: 0,
        first_broken_seq: None,
        first_broken_transaction_id: None,
        expected: None,
        actual: None,
        reason: Some(reason),
        backend,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run_mcp_server() -> Result<(), CliError> {
    let service = SysknifeMcpServer
        .serve(stdio())
        .await
        .map_err(|e| CliError::ExecutionFailed(format!("MCP server error: {e}")))?;

    service
        .waiting()
        .await
        .map_err(|e| CliError::ExecutionFailed(format!("MCP server wait error: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // T11 — tool registration round-trip via the rmcp ToolRouter
    //
    // The `#[tool_router(server_handler)]` macro generates a
    // `tool_router()` method on `SysknifeMcpServer`.  Asking it for
    // `list_all()` returns the exact tool list MCP clients see during
    // `tools/list`, so this is the boundary contract: every tool name
    // and description that ships in production goes through this list.
    // Prior coverage tested only inner helpers; a regression that
    // forgot to register a tool, swapped its name, or broke its
    // description string would have shipped silently.
    // -----------------------------------------------------------------------

    #[test]
    fn rmcp_tool_router_registers_every_sysknife_tool() {
        let router = SysknifeMcpServer::tool_router();
        let tools = router.list_all();

        let names: std::collections::HashSet<String> =
            tools.iter().map(|t| t.name.to_string()).collect();
        for expected in [
            "sysknife_plan",
            "sysknife_execute",
            "sysknife_history",
            "sysknife_doctor",
            "sysknife_audit_verify",
        ] {
            assert!(
                names.contains(expected),
                "MCP tool registry missing {expected}: registered = {names:?}"
            );
        }

        // Every registered tool must carry a non-empty description so
        // clients (and the model) can pick the right one. Empty
        // descriptions silently degrade tool selection.
        for t in &tools {
            assert!(
                t.description.as_ref().is_some_and(|d| !d.is_empty()),
                "tool {} has empty description",
                t.name
            );
        }
    }

    #[test]
    fn rmcp_sysknife_plan_description_warns_to_stop_after_planning() {
        // The plan tool's description carries a load-bearing instruction
        // — "after presenting this plan, STOP" — that gates every
        // hookify rule and the MCP-side approval flow.  A regression
        // that drops this clause would let agents bypass the
        // human-in-the-loop interlock.
        let router = SysknifeMcpServer::tool_router();
        let tools = router.list_all();
        let plan = tools
            .iter()
            .find(|t| t.name == "sysknife_plan")
            .expect("sysknife_plan must be registered");
        let desc = plan
            .description
            .as_ref()
            .expect("plan tool has a description");
        assert!(
            desc.to_lowercase().contains("stop"),
            "sysknife_plan description must tell the agent to STOP after planning; got: {desc}"
        );
    }

    #[test]
    fn discovery_resource_is_present_and_readable() {
        let resource = sysknife_about_resource();
        assert_eq!(resource.uri, SYSKNIFE_DISCOVERY_URI);
        assert_eq!(resource.name, SYSKNIFE_DISCOVERY_NAME);
        assert_eq!(resource.title.as_deref(), Some(SYSKNIFE_DISCOVERY_TITLE));
        assert_eq!(
            resource.description.as_deref(),
            Some(SYSKNIFE_DISCOVERY_DESCRIPTION)
        );
        assert_eq!(resource.mime_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn get_info_exposes_resources_capability_for_codex() {
        let info = SysknifeMcpServer.get_info();
        assert!(
            info.capabilities.resources.is_some(),
            "Codex-compatible MCP servers should advertise resources"
        );
        assert!(
            info.capabilities.tools.is_some(),
            "SysKnife must continue advertising tools"
        );
    }

    // -----------------------------------------------------------------------
    // parse_max_risk
    // -----------------------------------------------------------------------

    #[test]
    fn parse_max_risk_none_defaults_to_medium() {
        assert_eq!(parse_max_risk(None), Ok(1));
    }

    #[test]
    fn parse_max_risk_low() {
        assert_eq!(parse_max_risk(Some("low")), Ok(0));
    }

    #[test]
    fn parse_max_risk_medium() {
        assert_eq!(parse_max_risk(Some("medium")), Ok(1));
    }

    #[test]
    fn parse_max_risk_high_is_rejected() {
        let err = parse_max_risk(Some("high")).unwrap_err();
        assert!(err.contains("not allowed via MCP"), "got: {err}");
    }

    #[test]
    fn parse_max_risk_is_case_insensitive() {
        assert_eq!(parse_max_risk(Some("LOW")), Ok(0));
        assert_eq!(parse_max_risk(Some("Low")), Ok(0));
        assert_eq!(parse_max_risk(Some("Medium")), Ok(1));
        assert_eq!(parse_max_risk(Some("MEDIUM")), Ok(1));
        // "high" is rejected regardless of case
        assert!(parse_max_risk(Some("HIGH")).is_err());
        assert!(parse_max_risk(Some("High")).is_err());
    }

    #[test]
    fn parse_max_risk_unknown_returns_err() {
        assert!(parse_max_risk(Some("extreme")).is_err());
        assert!(parse_max_risk(Some("")).is_err());
    }

    // -----------------------------------------------------------------------
    // risk_level_ord
    // -----------------------------------------------------------------------

    #[test]
    fn risk_level_ord_ordering() {
        assert!(risk_level_ord(&RiskLevel::Low) < risk_level_ord(&RiskLevel::Medium));
        assert!(risk_level_ord(&RiskLevel::Medium) < risk_level_ord(&RiskLevel::High));
    }

    // -----------------------------------------------------------------------
    // check_risk_ceiling
    // -----------------------------------------------------------------------

    #[test]
    fn check_risk_ceiling_within_ceiling_is_ok() {
        // low step, ceiling=medium
        assert!(check_risk_ceiling(&RiskLevel::Low, 1).is_ok());
        // medium step, ceiling=medium
        assert!(check_risk_ceiling(&RiskLevel::Medium, 1).is_ok());
        // high step, ceiling=high
        assert!(check_risk_ceiling(&RiskLevel::High, 2).is_ok());
        // exact match at every level
        assert!(check_risk_ceiling(&RiskLevel::Low, 0).is_ok());
    }

    #[test]
    fn check_risk_ceiling_exceeds_ceiling_is_err() {
        // medium step, ceiling=low
        assert!(check_risk_ceiling(&RiskLevel::Medium, 0).is_err());
        // high step, ceiling=low
        assert!(check_risk_ceiling(&RiskLevel::High, 0).is_err());
        // high step, ceiling=medium
        assert!(check_risk_ceiling(&RiskLevel::High, 1).is_err());
    }

    // -----------------------------------------------------------------------
    // truncate_output
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_output_short_output_unchanged() {
        let lines: Vec<String> = (0..10).map(|i| format!("line {i}")).collect();
        let result = truncate_output(lines.clone());
        assert_eq!(result, lines);
    }

    #[test]
    fn truncate_output_at_limit_unchanged() {
        let lines: Vec<String> = (0..OUTPUT_LINE_LIMIT)
            .map(|i| format!("line {i}"))
            .collect();
        let result = truncate_output(lines.clone());
        assert_eq!(result, lines);
    }

    #[test]
    fn truncate_output_over_limit_adds_marker() {
        let lines: Vec<String> = (0..OUTPUT_LINE_LIMIT + 50)
            .map(|i| format!("line {i}"))
            .collect();
        let result = truncate_output(lines);
        assert_eq!(result.len(), OUTPUT_LINE_LIMIT + 1);
        assert!(result.last().unwrap().contains("truncated"));
        assert!(result.last().unwrap().contains("50"));
    }
}
