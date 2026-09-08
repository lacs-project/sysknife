//! MCP server entry point for `sysknife mcp-server`.
//!
//! Exposes five workflow/audit tools, direct read-only action tools compatible
//! with the detected distro, and one discovery resource:
//!
//! - `sysknife_plan`         — turn a natural-language intent into a risk-labelled plan.
//! - `sysknife_execute`      — execute a plan returned by `sysknife_plan`.
//! - `sysknife_history`      — list past audit-log entries (read-only).
//! - `sysknife_doctor`       — daemon connectivity + config diagnostics (read-only).
//! - `sysknife_audit_verify` — verify the audit-log hash chain (read-only).
//! - `sysknife_<action>`     — run one catalogue-backed read-only query directly.
//!
//! Typical agentic loop:
//!
//! 1. Call `sysknife_plan { intent }` — show the plan to the user, explain risk.
//! 2. **STOP** — wait for explicit user approval before doing anything else.
//! 3. The user runs `sysknife approve <transaction-id>` for each accepted step.
//! 4. Call `sysknife_execute` with the exact steps and one-time receipts.
//!
//! The three fixed read-only tools and generated direct-query tools are safe to
//! call without going through the plan/approve/execute loop — they only inspect
//! state. Observer-callable mutations such as `AptUpdate` are never generated.
//! Direct-query schemas remain open at the MCP layer deliberately: the daemon is
//! authoritative for typed parameter validation, avoiding a second schema copy
//! that could drift.
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

use std::{path::PathBuf, sync::Arc};

use rmcp::{
    handler::server::{
        router::tool::{ToolRoute, ToolRouter},
        wrapper::{Json, Parameters},
    },
    model::{
        CallToolResult, ContentBlock, Implementation, ListResourceTemplatesResult,
        ListResourcesResult, PaginatedRequestParams, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ServerCapabilities,
        ServerInfo, Tool, ToolAnnotations,
    },
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use sysknife_types::{ApprovalReceipt, RiskLevel, TransactionId};

use sysknife_brain::config::BrainConfig;
use sysknife_brain::planner::LlmPlanner;
use sysknife_brain::planning_tools::propose_plan::KNOWN_ACTIONS;
use sysknife_brain::state_client::StateClient as _;
use sysknife_core::action_family::{DEBIAN_ONLY_ACTIONS, FEDORA_ONLY_ACTIONS};
use sysknife_core::distro::DistroId;
use sysknife_daemon::actions::OBSERVER_MUTATING_ACTIONS;

use crate::client::{DaemonClient, DescribeInfo};
use crate::error::CliError;
use crate::runner::{resolve_socket_target, verify_postgres, verify_sqlite, Verifier};

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
    pub command: String,
    /// Daemon-issued identity of the immutable persisted preview.
    pub transaction_id: String,
    /// Preview-time warnings for this step (e.g. reboot-required, platform
    /// caveats). Surfaced so the calling agent can relay them to the operator
    /// before approval; empty when the preview produced none.
    pub warnings: Vec<String>,
    /// Relevant system state as the daemon found it, before the change.
    pub current_state: serde_json::Value,
    /// What the daemon will change, as it resolved it — not as the planner
    /// described it. This is the substance of what the operator approves.
    pub proposed_change: serde_json::Value,
    /// Side effects the daemon expects beyond the change itself.
    pub expected_side_effects: Vec<String>,
    /// Whether applying this step requires a reboot to take effect.
    pub reboot_required: bool,
    /// Whether this step can be rolled back automatically if it fails.
    pub rollback_available: bool,
}

/// Copy the daemon's authoritative preview onto a plan step.
///
/// The planner's own summary and risk are a proposal; the preview is what the
/// daemon will actually do. Everything an operator needs in order to consent
/// lives in the preview, so an MCP client that only sees the plan cannot relay
/// the decision unless these fields travel with it.
///
/// Pure so the mapping is testable without a daemon.
fn merge_preview_into_step(step: &mut PlanStepOutput, preview: &sysknife_types::PreviewEnvelope) {
    step.risk_level = match preview.risk_level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
    }
    .to_string();
    step.warnings = preview.warnings.clone();
    step.current_state = preview.current_state.clone();
    step.proposed_change = preview.proposed_change.clone();
    step.expected_side_effects = preview.expected_side_effects.clone();
    step.reboot_required = preview.reboot_required;
    step.rollback_available = preview.rollback_available;
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
    /// Transaction ID returned by `sysknife_plan` for this exact step.
    pub transaction_id: String,
    /// Canonical action name from the SysKnife catalogue, e.g. `"GetDiskUsage"`.
    pub action_name: String,
    /// Action-specific parameters (pass through from the plan unchanged).
    pub params: serde_json::Value,
    /// One-time receipt from an explicit `sysknife approve <transaction-id>`.
    pub approval_receipt: String,
}

/// Input to `sysknife_execute`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteInput {
    /// Steps to execute — take the `steps` array from `sysknife_plan` output.
    pub steps: Vec<StepToExecute>,
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
    /// Identifier of the rollback the daemon performed after a failure, when
    /// one happened — e.g. the restored file or the previous deployment.
    /// `null` when the step succeeded or when nothing was rolled back.
    pub rollback_ref: Option<String>,
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
/// Populated from the daemon's structured `query_history` IPC, so
/// `created_at` and `risk_level` carry real values. They stay `Option` only
/// for wire tolerance (a future or partial row may omit them).
#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(default)]
pub struct HistoryEntry {
    /// Daemon transaction ID.
    pub transaction_id: String,
    /// Canonical action name from the SysKnife catalogue.
    pub action: String,
    /// Final job status (`"succeeded"`, `"failed"`, etc.).
    pub status: String,
    /// Human-readable summary from the daemon.
    pub summary: String,
    /// ISO-8601 timestamp when the transaction was created.
    pub created_at: Option<String>,
    /// Risk level the daemon assigned (`"low"` | `"medium"` | `"high"`).
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
    /// Resolved daemon socket target as a URI, e.g. `"unix:///run/sysknife/daemon.sock"`
    /// or `"vsock://3:7777"`. Accepted verbatim by `SYSKNIFE_SOCKET`.
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
    /// What verification expected for the first broken row (the literal
    /// `"valid ed25519 signature"`).
    pub expected: Option<String>,
    /// The hex Ed25519 signature actually stored for the first broken row.
    pub actual: Option<String>,
    /// Human-readable explanation. Only set when `status == "cannot_verify"`.
    pub reason: Option<String>,
    /// Number of approval events (grant / consume / revoke) checked in the
    /// second chain.
    pub events_checked: u64,
    /// Result of the approval-event chain walk: `"intact"`, `"broken"`, or
    /// `"cannot_verify"`. Reported separately from `status` so a clean
    /// authorisation trail can never paper over a tampered approval trail.
    pub approval_events_status: String,
    /// `"consistent"`, `"not_checked"`, or `"missing_event"`: whether every
    /// event tip committed by a transaction row is still present in the event
    /// chain.
    pub binding_status: String,
    /// Backend label: a filesystem path for SQLite, the literal `"postgres"`
    /// for Postgres deployments.
    pub backend: String,
    /// The transaction chain's own verdict: `"intact"`, `"broken"` or
    /// `"cannot_verify"`.
    ///
    /// Reported separately because `status` is the worst of three checks, so a
    /// broken *approval-event* chain sets `status` to `"broken"` while this stays
    /// `"intact"`. Read this one, not `status`, to decide whether the attribution
    /// counts below are findings or claims: without it an agent had no way to
    /// recover the chain verdict and would discard sound attribution.
    pub chain_status: String,
    /// How many rows were censused for attribution: every row read, whether or
    /// not it verified.
    ///
    /// `null` when the store could not be read at all, along with every count
    /// below, so a database nobody could open never reads as one where nothing was
    /// found. A readable but empty store reports `0`.
    ///
    /// When `chain_status` is not `"intact"` this can exceed `rows_checked`, and
    /// the difference is the part of the trail that was counted but not proven.
    pub rows_censused: Option<u64>,
    /// How many rows have a signed principal naming an account: a non-empty value
    /// under the `uid` or `token` scheme, which this build could read back as
    /// something the daemon itself could have written.
    ///
    /// Only a finding when `chain_status` is `"intact"`. Past a detected break the
    /// walk stopped checking, so those rows' principals are claims: some may be
    /// authentic, since deleting or reordering a row breaks the link while leaving
    /// later signatures valid, and this tool cannot say which.
    pub attributed_rows: Option<u64>,
    /// How many rows record that the daemon could not name the caller.
    ///
    /// `chain_status: "intact"` with a non-zero count here means the chain is sound
    /// and the attribution is not: report both, never the first alone.
    ///
    /// Since 0.4.0 this counts only rows whose `chain_version = 3` principal is
    /// signed as `none:unattributed`. 0.3.0 matched the column on any encoding,
    /// which meant an unsigned column could land here; such rows are now
    /// `rows_unattested`.
    pub unattributed_rows: Option<u64>,
    /// How many rows carry no principal the signature covers, normally because
    /// they were signed before the column existed.
    ///
    /// Reported next to `unattributed_rows` because zero attribution failures
    /// over a pre-v3 database would otherwise read as full attribution. The two
    /// have different remedies: this one cannot be fixed, since backfilling a
    /// principal would rewrite the bytes the signature covers.
    pub rows_without_principal: Option<u64>,
    /// How many rows have no principal any signature vouches for: the column is
    /// populated on an encoding that does not sign it, or holds a value this build
    /// cannot read back as one the daemon could have written, or the row declares
    /// an encoding this build does not know.
    ///
    /// This build writes none of those. The first two are out-of-band writes to
    /// investigate; the third means a newer SysKnife wrote the rows and the fix is
    /// to verify with a build at least that new.
    pub rows_unattested: Option<u64>,
    /// How many rows name no account, for any reason. The complement of
    /// `attributed_rows` over `rows_censused`, provided so a reader does not have
    /// to add the three reasons and risk missing one.
    pub rows_naming_no_account: Option<u64>,
    /// Set when `SYSKNIFE_SOCKET` names a daemon that may not live on this
    /// machine, because verification reads a local store while every other tool
    /// travels over that socket. `None` for the local-daemon case.
    pub daemon_socket_caveat: Option<String>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SysknifeMcpServer {
    tool_router: ToolRouter<Self>,
}

/// Observer-callable actions that are proven read-only and may therefore be
/// exposed without the plan/approve/execute interlock.
///
/// This list is intentionally explicit. The `observer_actions_are_fully_classified`
/// test compares it with the live catalogue plus [`OBSERVER_MUTATING_ACTIONS`], so a
/// newly added low-risk action fails the test suite until somebody decides which
/// side of the approval boundary it belongs on.
const MCP_READ_ONLY_ACTIONS: &[&str] = &[
    "GetSystemState",
    "CollectDiagnostics",
    "GetDeploymentHistory",
    "ListDeployments",
    "GetKernelArguments",
    "GetLayeredPackages",
    "GetPendingUpdates",
    "GetDiskUsage",
    "SearchFlatpakApps",
    "ListFlatpakRemotes",
    "ListInstalledFlatpaks",
    "GetFlatpakAppInfo",
    "UbuntuListFlatpaks",
    "ListToolboxes",
    "ListServices",
    "GetServiceLogs",
    "GetServiceStatus",
    "ListTimers",
    "GetServiceResourceLimits",
    "ListProcesses",
    "GetJournalLog",
    "GetLvmReport",
    "GetSysctl",
    "GetMounts",
    "GetLogrotateStatus",
    "GetPasswordAging",
    "GetAuditRules",
    "GetCertificates",
    "GetSudoGrants",
    "GetFirewallState",
    "GetNetworkStatus",
    "GetListeningPorts",
    "ResolvectlStatus",
    "GetDateTime",
    "ListUsers",
    "ListGroups",
    "GetAuthorizedKeys",
    "ListPackageRepositories",
    "GetMemoryInfo",
    "GetHostState",
    "ListContainers",
    "GetContainerInfo",
    "CheckPendingReboot",
    "AppArmorStatus",
    "CloudInitStatus",
    "Fail2banStatus",
    "AptSearch",
    "AptListInstalled",
    "AptShow",
    "AptListUpgradable",
    "AptHistoryList",
    "GetAptPins",
    "SnapList",
    "SnapInfo",
    "UfwStatus",
    "NetplanGetConfig",
    "DistroboxList",
    "GrubGetKargs",
    "ProStatus",
    "LivepatchStatus",
    "MultipassList",
    // Dispatcher-internal, with no ActionSpec of its own.
    "ListJobHistory",
];

impl SysknifeMcpServer {
    fn new() -> Self {
        let distro = sysknife_core::distro::detect().ok();
        Self::for_distro(distro.as_ref())
    }

    fn for_distro(distro: Option<&DistroId>) -> Self {
        Self {
            tool_router: Self::tool_router() + direct_read_only_tool_router(distro),
        }
    }
}

fn direct_action_tool_name(action_name: &str) -> String {
    let mut name = String::from("sysknife_");
    for (index, ch) in action_name.chars().enumerate() {
        if index > 0 && ch.is_ascii_uppercase() {
            name.push('_');
        }
        name.push(ch.to_ascii_lowercase());
    }
    name
}

fn action_is_available_on_distro(action_name: &str, distro: Option<&DistroId>) -> bool {
    match distro {
        Some(distro) => {
            crate::distro_routing::check_action_distro(action_name, Some(distro)).is_ok()
        }
        None => {
            !DEBIAN_ONLY_ACTIONS.contains(&action_name)
                && !FEDORA_ONLY_ACTIONS.contains(&action_name)
        }
    }
}

fn direct_query_input_schema() -> Arc<rmcp::model::JsonObject> {
    Arc::new(serde_json::Map::from_iter([
        ("type".to_string(), serde_json::json!("object")),
        ("additionalProperties".to_string(), serde_json::json!(true)),
    ]))
}

fn direct_read_only_tool_router(distro: Option<&DistroId>) -> ToolRouter<SysknifeMcpServer> {
    let mut router = ToolRouter::new();

    for spec in sysknife_daemon::actions::all_specs() {
        let action_name = spec.action_name;
        if spec.risk_level != RiskLevel::Low || !MCP_READ_ONLY_ACTIONS.contains(&action_name) {
            continue;
        }
        // Fail closed even before the drift test runs: a name accidentally
        // copied onto both lists never reaches the approval-free router.
        if OBSERVER_MUTATING_ACTIONS.contains(&action_name) {
            continue;
        }
        if !action_is_available_on_distro(action_name, distro) {
            continue;
        }

        let tool_name = direct_action_tool_name(action_name);
        let action_description = KNOWN_ACTIONS
            .iter()
            .find_map(|(name, description)| (*name == action_name).then_some(*description))
            .unwrap_or("Read live system state through the SysKnife daemon.");
        let tool = Tool::new(
            tool_name,
            format!("Read-only SysKnife action `{action_name}`. {action_description}"),
            direct_query_input_schema(),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        );
        let routed_action = action_name.to_string();

        router.add_route(ToolRoute::new_dyn(tool, move |context| {
            let action_name = routed_action.clone();
            let params = serde_json::Value::Object(context.arguments.unwrap_or_default());
            Box::pin(async move {
                let output = direct_query_inner(action_name, params)
                    .await
                    .map_err(|e| ErrorData::internal_error(e, None))?;

                Ok(CallToolResult::success(vec![ContentBlock::text(output)]).into())
            })
        }));
    }

    router
}

async fn direct_query_inner(
    action_name: String,
    params: serde_json::Value,
) -> Result<String, String> {
    let client = DaemonClient::new(resolve_socket_target());
    tokio::task::spawn_blocking(move || client.query_action(&action_name, &params))
        .await
        .map_err(|e| format!("query join error: {e}"))?
        .map_err(|e| format!("query failed: {e}"))
}

const SYSKNIFE_DISCOVERY_URI: &str = "sysknife://about";
const SYSKNIFE_DISCOVERY_NAME: &str = "about";
const SYSKNIFE_DISCOVERY_TITLE: &str = "SysKnife MCP server";
const SYSKNIFE_DISCOVERY_DESCRIPTION: &str = "Discovery resource for Codex and other MCP clients.";
const SYSKNIFE_DISCOVERY_BODY: &str = "SysKnife exposes tools for planning and executing Linux system administration tasks, plus direct read-only queries selected for the detected distro.\n\nUse `sysknife_plan` first for any mutation and present the plan to the user. The user must run `sysknife approve <transaction-id>` in a terminal for every accepted step. Call `sysknife_execute` only with the one-time receipts printed by those commands. MCP cannot issue approval receipts.\n\nAvailable fixed read-only tools: `sysknife_history`, `sysknife_doctor`, and `sysknife_audit_verify`. Catalogue-backed query tools use `sysknife_<snake_case_action>` names, for example `sysknife_get_disk_usage`. `AptUpdate` remains plan-only even though its risk level is Low.";

fn sysknife_about_resource() -> Resource {
    rmcp::model::Resource::new(SYSKNIFE_DISCOVERY_URI, SYSKNIFE_DISCOVERY_NAME)
        .with_title(SYSKNIFE_DISCOVERY_TITLE)
        .with_description(SYSKNIFE_DISCOVERY_DESCRIPTION)
        .with_mime_type("text/plain")
}

#[tool_router]
impl SysknifeMcpServer {
    /// Plan a Linux system administration intent.
    ///
    /// Returns a JSON object with the proposed steps, each carrying an
    /// `action_name`, `summary`, `risk_level` ("low" | "medium" | "high"),
    /// `params`, `command` (the resolved shell command), and a daemon-issued
    /// `transaction_id`. No action is executed. The user must approve each
    /// transaction from a separate terminal before execution.
    #[tool(
        description = "Plan a Linux system administration intent. Returns typed steps with risk levels, resolved commands, and daemon transaction IDs. IMPORTANT: Present the plan, then STOP. The user must run `sysknife approve <transaction-id>` in a real terminal for each accepted step. Do not execute from chat approval alone."
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
        let client = DaemonClient::new(resolve_socket_target());
        enrich_with_commands(&mut output, &client)
            .await
            .map_err(|e| ErrorData::internal_error(e, None))?;
        Ok(Json(output))
    }

    /// Execute a plan produced by `sysknife_plan`.
    ///
    /// Pass each exact step from `sysknife_plan` with the one-time receipt
    /// printed by `sysknife approve <transaction-id>`. MCP cannot issue these
    /// receipts itself. On failure mid-plan execution stops immediately.
    ///
    /// Returns per-step results including output lines, warnings, and
    /// whether a reboot is required.
    #[tool(
        description = "Execute exact steps produced by sysknife_plan. Every step requires a one-time receipt from an explicit `sysknife approve <transaction-id>` CLI confirmation; MCP cannot approve its own mutations."
    )]
    async fn sysknife_execute(
        &self,
        Parameters(ExecuteInput { steps }): Parameters<ExecuteInput>,
    ) -> Result<Json<ExecuteOutput>, ErrorData> {
        execute_steps_inner(steps)
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
        description = "Verify the tamper-evident Ed25519-signed hash chain over the audit log. Returns status (intact/broken/cannot_verify), rows_checked, and, on broken, the first offending row. Read-only and safe to call without prior sysknife_plan."
    )]
    async fn sysknife_audit_verify(&self) -> Result<Json<AuditVerifyReport>, ErrorData> {
        Ok(Json(audit_verify_inner().await))
    }
}

/// Identity this server reports in `initialize`.
///
/// `Implementation::from_build_env()` resolves `CARGO_PKG_*` at the crate where
/// the macro expands — which is `rmcp` — so the server introduced itself to
/// every client, and to directory listings, as "rmcp" at rmcp's version. The
/// struct is `#[non_exhaustive]`, so the fields are overwritten rather than
/// rebuilt, which also keeps any future field at its upstream default.
fn sysknife_implementation() -> Implementation {
    let mut implementation = Implementation::from_build_env();
    implementation.name = "sysknife".to_string();
    implementation.version = env!("CARGO_PKG_VERSION").to_string();
    implementation
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SysknifeMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        // Not `Implementation::from_build_env()`: that macro resolves
        // `CARGO_PKG_*` at the crate where it is expanded, which is `rmcp`, so
        // the server introduced itself to every client as "rmcp" at rmcp's
        // version. Directory listings and client UIs show this string.
        .with_server_info(sysknife_implementation())
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
            result_type: None,
            ttl_ms: None,
            cache_scope: None,
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        // `result_type`, `ttl_ms` and `cache_scope` arrived with the 2026-07-28
        // protocol revision. All three stay `None`: absent `result_type` means
        // "complete", and declining to advertise a cache scope or a TTL keeps
        // every client asking the daemon rather than replaying a stored answer.
        Ok(ListResourceTemplatesResult {
            resource_templates: Vec::new(),
            next_cursor: None,
            meta: None,
            result_type: None,
            ttl_ms: None,
            cache_scope: None,
        })
    }

    async fn read_resource(
        &self,
        ReadResourceRequestParams { uri, .. }: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        // rmcp 3 lets a server answer `resources/read` with `InputRequired`
        // (SEP-2322), which asks the *client* for more input before the read
        // finishes. SysKnife never uses it. Approval is a terminal action
        // against the daemon, and an MCP-level input round would be a second
        // channel that reaches the operator without one.
        match uri.as_str() {
            SYSKNIFE_DISCOVERY_URI => Ok(ReadResourceResponse::Complete(ReadResourceResult::new(
                vec![ResourceContents::text(SYSKNIFE_DISCOVERY_BODY, uri)],
            ))),
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

    // Mirror the CLI's distro-routing guard (`runner::run_intent`) so MCP
    // clients get a clear distro-mismatch message (e.g. "AptInstall is only
    // valid on Debian-family distros") instead of a raw daemon error
    // surfacing later out of `enrich_with_commands`/`preview`. The daemon
    // remains the enforcement backstop regardless of this check.
    check_plan_steps_distro(
        plan.steps().iter().map(|s| s.action_name()),
        distro.as_ref(),
    )?;

    serde_json::to_value(&plan).map_err(|e| format!("serialization error: {e}"))
}

/// Validate every plan step's action name against the detected distro,
/// reusing [`crate::distro_routing::check_action_distro`]. Extracted as a
/// small pure function (taking action-name strings rather than a full
/// `Plan`) so it can be unit-tested without constructing planner internals.
fn check_plan_steps_distro<'a>(
    action_names: impl Iterator<Item = &'a str>,
    distro: Option<&sysknife_core::distro::DistroId>,
) -> Result<(), String> {
    for action_name in action_names {
        crate::distro_routing::check_action_distro(action_name, distro)?;
    }
    Ok(())
}

/// Resolve and persist every step against the daemon. Planning fails closed if
/// any step cannot be described or previewed; a synthetic transaction ID must
/// never be presented as executable.
async fn enrich_with_commands(
    output: &mut PlanOutput,
    client: &DaemonClient,
) -> Result<(), String> {
    for step in &mut output.steps {
        let DescribeInfo { command, .. } =
            client
                .describe(&step.action_name, &step.params)
                .await
                .map_err(|e| format!("describe failed for {}: {e}", step.action_name))?;
        step.command = command;

        let prepared = client
            .preview(&step.action_name, &step.params)
            .await
            .map_err(|e| format!("preview failed for {}: {e}", step.action_name))?;
        // The MCP wire structs keep plain strings: their JSON Schema is what
        // the agent sees, and a bare string is the honest description of an
        // opaque identifier. The newtypes guard the internal call sites, so the
        // conversion happens once, here at the boundary.
        step.transaction_id = prepared.transaction_id.into_inner();
        // Carry the whole authoritative preview through to the plan output
        // rather than a slice of it — the agent needs it to inform the operator.
        merge_preview_into_step(step, &prepared.preview);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sysknife_execute helper
// ---------------------------------------------------------------------------

async fn execute_steps_inner(steps: Vec<StepToExecute>) -> Result<ExecuteOutput, String> {
    let client = DaemonClient::new(resolve_socket_target());

    let mut results: Vec<StepResult> = Vec::new();
    let mut plan_needs_reboot = false;

    for step in steps {
        // Execute and collect progress lines.
        let mut output_lines: Vec<String> = Vec::new();
        let result = client
            .execute(
                &TransactionId::new(step.transaction_id.clone()),
                &step.action_name,
                &step.params,
                &ApprovalReceipt::new(step.approval_receipt.clone()),
                |line| output_lines.push(line.to_owned()),
            )
            .await
            .map_err(|e| format!("execute error for {}: {e}", step.action_name))?;

        let needs_reboot = result.needs_reboot;
        if needs_reboot {
            plan_needs_reboot = true;
        }

        // `JobState` is a plain snake_case string enum, so this cannot fail
        // today. Fail loudly rather than degrading to "unknown": silently
        // replacing a real status with a placeholder would leave the calling
        // agent unable to distinguish "the daemon said unknown" from "we lost
        // the status", which is exactly the kind of quiet drift a future
        // non-string `JobState` representation would introduce.
        let status = serde_json::to_value(result.status)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .expect("JobState always serializes to a JSON string");

        let succeeded = matches!(result.status, sysknife_types::JobState::Succeeded);

        results.push(StepResult {
            action_name: step.action_name,
            status,
            summary: result.summary,
            output: truncate_output(output_lines),
            warnings: result.warnings,
            needs_reboot,
            transaction_id: result.transaction_id,
            // `docs/automatic-rollback.md` promises this reaches MCP callers;
            // the daemon has always sent it, the wire struct simply dropped it.
            rollback_ref: result.rollback_ref,
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

    let limit = limit.unwrap_or(HISTORY_DEFAULT_LIMIT);
    let client = DaemonClient::new(resolve_socket_target());
    let rows = tokio::task::spawn_blocking(move || {
        client.query_history(
            Some(limit),
            status.as_deref(),
            action.as_deref(),
            since_hours,
        )
    })
    .await
    .map_err(|e| format!("join: {e}"))?
    .map_err(|e| format!("daemon error: {e}"))?;

    Ok(rows.into_iter().map(history_entry_from_row).collect())
}

/// Map a daemon `JobHistoryEntry` to the MCP `HistoryEntry`, populating the
/// `created_at` and typed `risk_level` fields the old text-parsing path always
/// left `None`. Status is rendered lowercase to match the daemon's display.
fn history_entry_from_row(row: sysknife_daemon::transactions::JobHistoryEntry) -> HistoryEntry {
    let risk_level = match row.risk_level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
    };
    HistoryEntry {
        transaction_id: row.transaction_id,
        action: row.action_name,
        status: format!("{:?}", row.status).to_lowercase(),
        summary: row.summary,
        created_at: Some(row.created_at),
        risk_level: Some(risk_level.to_string()),
    }
}

// ---------------------------------------------------------------------------
// sysknife_doctor helpers
// ---------------------------------------------------------------------------

async fn doctor_inner() -> DoctorReport {
    let mut warnings: Vec<String> = Vec::new();

    let socket = resolve_socket_target();
    // `label()`, not `{:?}`: this string is published to MCP clients, and
    // `Unix("/run/…")` is Rust internals rather than something a caller can put
    // back into SYSKNIFE_SOCKET. Must match what `sysknife doctor` prints.
    let socket_label = socket.label();

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
    use sysknife_daemon::audit_chain::{AuditKey, BindingOutcome, VerifyOutcome};

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

    let verifier = Verifier::Private(Box::new(key));
    let outcome = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => {
            verify_postgres(s, &verifier).await
        }
        _ => verify_sqlite(&db_path, &verifier).await,
    };

    // The doctor summary reports the worst of the three checks. Reporting only
    // the transaction chain would call a deployment healthy while its approval
    // trail was broken.
    for (label, sub) in [
        ("audit chain", &outcome.chain),
        ("approval-event chain", &outcome.events),
    ] {
        if let VerifyOutcome::CannotVerify { reason } = sub {
            warnings.push(format!("{label} cannot be verified: {reason}"));
        }
    }
    if let BindingOutcome::MissingEvent {
        transaction_seq, ..
    } = &outcome.binding
    {
        warnings.push(format!(
            "transaction seq={transaction_seq} commits to an approval event that no longer exists"
        ));
    }
    match outcome.exit_code() {
        0 => VerifyOutcomeKind::Intact,
        1 => VerifyOutcomeKind::Broken,
        _ => VerifyOutcomeKind::Unknown,
    }
}

// ---------------------------------------------------------------------------
// sysknife_audit_verify helpers
// ---------------------------------------------------------------------------

async fn audit_verify_inner() -> AuditVerifyReport {
    // Every path through the verifier, including the early cannot_verify
    // returns, has to carry the caveat, so it is attached once here rather than
    // at each return site.
    with_socket_caveat(
        audit_verify_local_store().await,
        crate::runner::remote_daemon_caveat_from_env(),
    )
}

/// Verify the chain in the store on **this** machine.
///
/// Named for what it actually does: this is a filesystem operation, not a daemon
/// request, so it says nothing about the host `SYSKNIFE_SOCKET` points at.
async fn audit_verify_local_store() -> AuditVerifyReport {
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

    let verifier = Verifier::Private(Box::new(key));
    let outcome = match lacs_config.storage.as_ref() {
        Some(s) if s.backend.eq_ignore_ascii_case("postgres") => {
            verify_postgres(s, &verifier).await
        }
        _ => verify_sqlite(&db_path, &verifier).await,
    };

    outcome_to_report(outcome, backend_label)
}

/// Short label for one chain walk.
fn outcome_label(outcome: &sysknife_daemon::audit_chain::VerifyOutcome) -> &'static str {
    use sysknife_daemon::audit_chain::VerifyOutcome;
    match outcome {
        VerifyOutcome::Intact { .. } => "intact",
        VerifyOutcome::Broken { .. } => "broken",
        VerifyOutcome::CannotVerify { .. } => "cannot_verify",
    }
}

fn binding_outcome_label(outcome: &sysknife_daemon::audit_chain::BindingOutcome) -> &'static str {
    use sysknife_daemon::audit_chain::BindingOutcome;
    match outcome {
        BindingOutcome::Consistent { .. } => "consistent",
        BindingOutcome::NotChecked => "not_checked",
        BindingOutcome::MissingEvent { .. } => "missing_event",
    }
}

fn outcome_to_report(
    verification: sysknife_daemon::audit_chain::AuditVerification,
    backend: String,
) -> AuditVerifyReport {
    use sysknife_daemon::audit_chain::VerifyOutcome;

    // One helper for both report arms and for the `CannotVerify` arm below, so
    // the census can only reach the report one way. The first version of this
    // change let `cannot_verify_report` invent its own zeros while a real census
    // sat in `verification`, and the MCP tool then published different numbers
    // than `sysknife audit verify --json` did for the same database.
    let attribution = verification.attribution;
    let chain_status = outcome_label(&verification.chain).to_string();
    let events_checked = match &verification.events {
        VerifyOutcome::Intact { rows_checked } | VerifyOutcome::Broken { rows_checked, .. } => {
            *rows_checked
        }
        VerifyOutcome::CannotVerify { .. } => 0,
    };
    let approval_events_status = outcome_label(&verification.events).to_string();
    let binding_status = binding_outcome_label(&verification.binding).to_string();

    // The detail fields describe the first *break*, wherever it was found. A
    // broken transaction chain is reported ahead of a broken event chain
    // because it is the one checkpoints anchor.
    let overall = verification.exit_code();
    let mut report = match verification.chain {
        VerifyOutcome::Intact { rows_checked } => AuditVerifyReport {
            status: "intact".to_string(),
            rows_checked,
            first_broken_seq: None,
            first_broken_transaction_id: None,
            expected: None,
            actual: None,
            reason: None,
            backend,
            events_checked,
            approval_events_status,
            binding_status,
            chain_status: chain_status.clone(),
            rows_censused: attribution.map(|c| c.rows()),
            attributed_rows: attribution.map(|c| c.named()),
            unattributed_rows: attribution.map(|c| c.attribution_failed()),
            rows_without_principal: attribution.map(|c| c.not_recorded()),
            rows_unattested: attribution.map(|c| c.unattested()),
            rows_naming_no_account: attribution.map(|c| c.unnamed()),
            daemon_socket_caveat: None,
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
            events_checked,
            approval_events_status,
            binding_status,
            chain_status: chain_status.clone(),
            rows_censused: attribution.map(|c| c.rows()),
            attributed_rows: attribution.map(|c| c.named()),
            unattributed_rows: attribution.map(|c| c.attribution_failed()),
            rows_without_principal: attribution.map(|c| c.not_recorded()),
            rows_unattested: attribution.map(|c| c.unattested()),
            rows_naming_no_account: attribution.map(|c| c.unnamed()),
            daemon_socket_caveat: None,
        },
        VerifyOutcome::CannotVerify { reason } => {
            let mut r = cannot_verify_report(backend, reason);
            r.events_checked = events_checked;
            r.approval_events_status = approval_events_status;
            r.binding_status = binding_status;
            // Rows can be read and censused and still fail to verify: one row
            // from a newer encoding, or a key_id mismatch after key rotation, is
            // enough. Dropping the census here republished the very defect this
            // release fixes, on the surface an agent reads without a human.
            r.chain_status = chain_status;
            r.rows_censused = attribution.map(|c| c.rows());
            r.attributed_rows = attribution.map(|c| c.named());
            r.unattributed_rows = attribution.map(|c| c.attribution_failed());
            r.rows_without_principal = attribution.map(|c| c.not_recorded());
            r.rows_unattested = attribution.map(|c| c.unattested());
            r.rows_naming_no_account = attribution.map(|c| c.unnamed());
            r
        }
    };

    // `status` is the headline an MCP client is most likely to read alone, so
    // it must reflect the worst of the three checks, not just the first.
    if report.status == "intact" {
        report.status = match overall {
            0 => "intact",
            1 => "broken",
            _ => "cannot_verify",
        }
        .to_string();
    }
    report
}

/// Attach the "which machine did this verify" caveat to a finished report.
///
/// Kept separate from report construction so the three construction sites stay
/// free of environment reads and the composition is unit-testable without
/// mutating process env, which parallel tests share.
fn with_socket_caveat(mut report: AuditVerifyReport, caveat: Option<String>) -> AuditVerifyReport {
    report.daemon_socket_caveat = caveat;
    report
}

fn cannot_verify_report(backend: String, reason: String) -> AuditVerifyReport {
    use sysknife_daemon::audit_chain::BindingOutcome;

    AuditVerifyReport {
        status: "cannot_verify".to_string(),
        rows_checked: 0,
        first_broken_seq: None,
        first_broken_transaction_id: None,
        expected: None,
        actual: None,
        reason: Some(reason),
        backend,
        events_checked: 0,
        approval_events_status: "cannot_verify".to_string(),
        binding_status: binding_outcome_label(&BindingOutcome::NotChecked).to_string(),
        // The chain verdict for a report built before any row was read. Callers
        // that reach this constructor overwrite it when they know better.
        chain_status: "cannot_verify".to_string(),
        // Null, not zero. This constructor also serves the paths where the store
        // or the key could not be opened, and there "no row named an account" is
        // not a fact anyone established.
        rows_censused: None,
        attributed_rows: None,
        unattributed_rows: None,
        rows_without_principal: None,
        rows_unattested: None,
        rows_naming_no_account: None,
        daemon_socket_caveat: None,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run_mcp_server() -> Result<(), CliError> {
    let service = SysknifeMcpServer::new()
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
    // An agent must be told when the verdict is about a different machine
    // -----------------------------------------------------------------------

    /// The agent calling `sysknife_audit_verify` has less context than a human
    /// at a terminal: it cannot see that `SYSKNIFE_SOCKET` points into a VM or
    /// down an SSH tunnel. If the report says `intact` and carries nothing else,
    /// the agent will tell the operator their audit trail is fine, having read a
    /// chain on the wrong host. The caveat has to travel in the structured
    /// output, not only in the CLI's human text.
    #[test]
    fn the_report_carries_the_which_machine_caveat() {
        let report = with_socket_caveat(
            cannot_verify_report("/tmp/store.sqlite".into(), "no key".into()),
            Some("NOTE: SYSKNIFE_SOCKET is /tmp/sysknife-web01.sock".into()),
        );

        let caveat = report
            .daemon_socket_caveat
            .as_deref()
            .expect("the caveat must survive onto the report");
        assert!(caveat.contains("/tmp/sysknife-web01.sock"));

        let json = serde_json::to_value(&report).expect("report serializes");
        assert!(
            json.get("daemon_socket_caveat").is_some(),
            "and must be visible in the tool's JSON output, got: {json}"
        );
    }

    /// The local case stays clean: no socket override, no field content, so the
    /// common path does not train agents to skip the note.
    #[test]
    fn a_local_daemon_leaves_the_caveat_empty() {
        let report = with_socket_caveat(
            cannot_verify_report("/tmp/store.sqlite".into(), "no key".into()),
            None,
        );
        assert!(report.daemon_socket_caveat.is_none());
    }

    // -----------------------------------------------------------------------
    // What the agent-facing report says about attribution
    // -----------------------------------------------------------------------

    fn verification_with(
        chain: sysknife_daemon::audit_chain::VerifyOutcome,
        attribution: Option<sysknife_daemon::audit_chain::AttributionCensus>,
    ) -> sysknife_daemon::audit_chain::AuditVerification {
        use sysknife_daemon::audit_chain::{AuditVerification, BindingOutcome, VerifyOutcome};
        AuditVerification {
            chain,
            events: VerifyOutcome::Intact { rows_checked: 0 },
            binding: BindingOutcome::Consistent {
                bindings_checked: 0,
            },
            attribution,
        }
    }

    /// Every count has to reach the agent-facing report, with distinct values so
    /// no permutation of the six fields can satisfy this. Both the `Intact` and
    /// `Broken` arms are separate struct literals repeating the field list, so a
    /// fix applied to one arm only is otherwise invisible.
    #[test]
    fn the_report_carries_every_attribution_count_on_both_verdicts() {
        use sysknife_daemon::audit_chain::{AttributionCensus, VerifyOutcome};
        let census = AttributionCensus::from_counts_for_tests(6, 1, 2, 3);

        for chain in [
            VerifyOutcome::Intact { rows_checked: 12 },
            VerifyOutcome::Broken {
                rows_checked: 4,
                first_broken_seq: 5,
                first_broken_transaction_id: "tx5".to_string(),
                expected: "x".to_string(),
                actual: "y".to_string(),
            },
        ] {
            let report = outcome_to_report(
                verification_with(chain.clone(), Some(census)),
                "/tmp/store.sqlite".to_string(),
            );
            assert_eq!(report.attributed_rows, Some(6), "chain: {chain:?}");
            assert_eq!(report.unattributed_rows, Some(1), "chain: {chain:?}");
            assert_eq!(report.rows_without_principal, Some(2), "chain: {chain:?}");
            assert_eq!(report.rows_unattested, Some(3), "chain: {chain:?}");
            assert_eq!(report.rows_naming_no_account, Some(6), "chain: {chain:?}");
            assert_eq!(report.rows_censused, Some(12), "chain: {chain:?}");
        }
    }

    /// Rows can be read and censused and still fail to verify: one row from a
    /// newer encoding is enough, as is a `key_id` mismatch after key rotation.
    /// This arm used to drop the census and publish zeros, so the MCP tool told an
    /// agent `attributed_rows: 0` over a fully attributed database while
    /// `sysknife audit verify --json` told a human the truth for the same store.
    #[test]
    fn a_cannot_verify_report_keeps_the_census_it_was_given() {
        use sysknife_daemon::audit_chain::{AttributionCensus, VerifyOutcome};
        let report = outcome_to_report(
            verification_with(
                VerifyOutcome::CannotVerify {
                    reason: "row seq=9 declares chain_version=4".to_string(),
                },
                Some(AttributionCensus::from_counts_for_tests(5, 2, 9, 0)),
            ),
            "/tmp/store.sqlite".to_string(),
        );

        assert_eq!(report.status, "cannot_verify");
        assert_eq!(
            report.chain_status, "cannot_verify",
            "the chain's own verdict must be recoverable, not only the aggregate"
        );
        assert_eq!(
            report.attributed_rows,
            Some(5),
            "the census survived the read, so the report must not invent zeros"
        );
        assert_eq!(report.unattributed_rows, Some(2));
        assert_eq!(report.rows_without_principal, Some(9));
        assert_eq!(report.rows_censused, Some(16));
    }

    /// `status` is the worst of three checks, so a broken approval-event chain
    /// makes it `"broken"` while the transaction chain is intact. An agent reading
    /// only `status` would treat sound attribution as unproven, so the chain's own
    /// verdict has to be recoverable from the report.
    #[test]
    fn a_broken_event_chain_does_not_make_the_transaction_chain_look_broken() {
        use sysknife_daemon::audit_chain::{
            AttributionCensus, AuditVerification, BindingOutcome, VerifyOutcome,
        };
        let report = outcome_to_report(
            AuditVerification {
                chain: VerifyOutcome::Intact { rows_checked: 3 },
                events: VerifyOutcome::Broken {
                    rows_checked: 0,
                    first_broken_seq: 1,
                    first_broken_transaction_id: "ev1".to_string(),
                    expected: "x".to_string(),
                    actual: "y".to_string(),
                },
                binding: BindingOutcome::Consistent {
                    bindings_checked: 0,
                },
                attribution: Some(AttributionCensus::from_counts_for_tests(3, 0, 0, 0)),
            },
            "/tmp/store.sqlite".to_string(),
        );

        assert_eq!(
            report.status, "broken",
            "the headline must still reflect the worst of the three checks"
        );
        assert_eq!(
            report.chain_status, "intact",
            "while the transaction chain's own verdict stays recoverable"
        );
        assert_eq!(report.attributed_rows, Some(3));
        assert_eq!(
            report.rows_censused, report.attributed_rows,
            "nothing was counted that was not also checked here"
        );
    }

    /// The other `cannot_verify` shape: nothing was read at all, so every count is
    /// `null`. An agent alerting on attribution must be able to tell "no data" from
    /// "no account named", which a `0` here would hide.
    #[test]
    fn an_unreadable_store_marks_binding_not_checked_and_nulls_every_count() {
        use sysknife_daemon::audit_chain::BindingOutcome;

        let report = cannot_verify_report("/tmp/store.sqlite".into(), "no key".into());

        assert_eq!(
            binding_outcome_label(&BindingOutcome::NotChecked),
            "not_checked"
        );
        assert_eq!(report.binding_status, "not_checked");
        assert!(report.attributed_rows.is_none());
        assert!(report.unattributed_rows.is_none());
        assert!(report.rows_without_principal.is_none());
        assert!(report.rows_unattested.is_none());
        assert!(report.rows_naming_no_account.is_none());
        assert!(report.rows_censused.is_none());
    }

    // -----------------------------------------------------------------------
    // The plan an agent sees carries the daemon's authoritative preview
    // -----------------------------------------------------------------------

    fn sample_preview() -> sysknife_types::PreviewEnvelope {
        sysknife_types::PreviewEnvelope {
            summary: "install vim 2:9.1".into(),
            risk_level: RiskLevel::Medium,
            current_state: serde_json::json!({"installed": false}),
            proposed_change: serde_json::json!({"action": "AptInstall", "package": "vim"}),
            expected_side_effects: vec!["apt lists updated".into()],
            reboot_required: true,
            rollback_available: true,
            warnings: vec!["a reboot is required".into()],
            request_hash: sysknife_types::RequestHash::new("deadbeef".to_string()),
        }
    }

    /// An agent that can only read `sysknife_plan` output must be able to tell
    /// the operator what changes, what else happens, whether a reboot follows
    /// and whether failure is recoverable. Dropping those fields left the
    /// approval request unanswerable from the MCP surface alone.
    #[test]
    fn a_plan_step_carries_the_whole_preview_not_a_slice_of_it() {
        let mut step = PlanStepOutput::default();
        merge_preview_into_step(&mut step, &sample_preview());

        assert_eq!(step.risk_level, "medium");
        assert_eq!(step.proposed_change["package"], "vim");
        assert_eq!(step.current_state["installed"], false);
        assert_eq!(step.expected_side_effects, vec!["apt lists updated"]);
        assert!(step.reboot_required, "reboot requirement must survive");
        assert!(
            step.rollback_available,
            "rollback availability must survive"
        );
        assert_eq!(step.warnings, vec!["a reboot is required"]);
    }

    /// The risk the agent reports must be the daemon's, never the planner's.
    #[test]
    fn merging_a_preview_overwrites_a_planner_supplied_risk() {
        let mut step = PlanStepOutput {
            risk_level: "low".into(),
            ..PlanStepOutput::default()
        };
        let mut preview = sample_preview();
        preview.risk_level = RiskLevel::High;
        merge_preview_into_step(&mut step, &preview);
        assert_eq!(step.risk_level, "high");
    }

    /// Schema guard: these fields are the contract an MCP client codes against,
    /// so their names are pinned here rather than only in prose.
    #[test]
    fn the_plan_step_schema_exposes_the_preview_fields() {
        let schema =
            serde_json::to_value(schemars::schema_for!(PlanStepOutput)).expect("schema serializes");
        let props = schema["properties"]
            .as_object()
            .expect("PlanStepOutput schema has properties");
        for field in [
            "current_state",
            "proposed_change",
            "expected_side_effects",
            "reboot_required",
            "rollback_available",
            "warnings",
        ] {
            assert!(
                props.contains_key(field),
                "PlanStep schema must expose {field}; an agent cannot relay what it \
                 cannot see. Present: {:?}",
                props.keys().collect::<Vec<_>>()
            );
        }
    }

    /// `docs/automatic-rollback.md` tells operators that `rollback_ref` comes
    /// back over MCP. The result struct silently omitted it.
    #[test]
    fn the_step_result_schema_exposes_rollback_ref() {
        let schema =
            serde_json::to_value(schemars::schema_for!(StepResult)).expect("schema serializes");
        let props = schema["properties"]
            .as_object()
            .expect("StepResult schema has properties");
        assert!(
            props.contains_key("rollback_ref"),
            "StepResult must report what was rolled back; present: {:?}",
            props.keys().collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // check_plan_steps_distro — MCP planning-path distro guard
    // -----------------------------------------------------------------------

    #[test]
    fn check_plan_steps_distro_rejects_mismatched_action() {
        let distro = sysknife_core::distro::DistroId::Fedora { version: 41 };
        let result = check_plan_steps_distro(["AptInstall"].into_iter(), Some(&distro));
        assert!(
            result.is_err(),
            "AptInstall on Fedora must be rejected by the MCP planning path too"
        );
        assert!(result.unwrap_err().contains("Debian-family"));
    }

    /// `GetSystemState` used to stand in for "a generic action" here. It is not
    /// one — it runs rpm-ostree and is now Fedora-fenced (#181) — so this test
    /// needs an action that genuinely belongs to neither family, or it stops
    /// testing what its name says.
    #[test]
    fn check_plan_steps_distro_allows_generic_action() {
        let distro = sysknife_core::distro::DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        let result = check_plan_steps_distro(["GetMemoryInfo"].into_iter(), Some(&distro));
        assert!(result.is_ok());

        let atomic = sysknife_core::distro::DistroId::FedoraSilverblue { version: 41 };
        let result = check_plan_steps_distro(["GetMemoryInfo"].into_iter(), Some(&atomic));
        assert!(
            result.is_ok(),
            "a generic action is generic on both families"
        );
    }

    #[test]
    fn check_plan_steps_distro_allows_all_when_distro_unknown() {
        // Detection failure (None) must never block planning -- the daemon
        // is the enforcement backstop in that case.
        let result = check_plan_steps_distro(["AptInstall", "RebaseSystem"].into_iter(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn check_plan_steps_distro_stops_at_first_mismatched_step() {
        let distro = sysknife_core::distro::DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        let result = check_plan_steps_distro(
            ["GetSystemState", "RebaseSystem", "AptInstall"].into_iter(),
            Some(&distro),
        );
        assert!(result.is_err(), "RebaseSystem on Ubuntu must be rejected");
        assert!(result.unwrap_err().contains("Fedora-family"));
    }

    #[tokio::test]
    async fn enrich_with_commands_fails_closed_when_daemon_unreachable() {
        // Fail-closed contract: if the daemon cannot describe/preview a step,
        // planning must error out — it must never hand back a step carrying a
        // synthetic or empty transaction_id that a client could then try to
        // execute. This guards the MCP approval interlock.
        let mut output = PlanOutput {
            intent: "set the timezone".to_string(),
            summary: "plan".to_string(),
            explanation: String::new(),
            steps: vec![PlanStepOutput {
                action_name: "SetTimezone".to_string(),
                params: serde_json::json!({ "timezone": "UTC" }),
                ..Default::default()
            }],
        };
        // A socket path that cannot exist → describe()/preview() fail fast.
        let client = DaemonClient::new(std::path::PathBuf::from(
            "/nonexistent/sysknife-unreachable.sock",
        ));

        let result = enrich_with_commands(&mut output, &client).await;
        assert!(
            result.is_err(),
            "enrich must fail closed when the daemon is unreachable"
        );
        assert!(
            output.steps[0].transaction_id.is_empty(),
            "no synthetic transaction_id may be presented for an un-previewed step"
        );
    }

    // -----------------------------------------------------------------------
    // Direct read-only action classification and routing
    // -----------------------------------------------------------------------

    #[test]
    fn observer_actions_are_fully_classified() {
        use std::collections::BTreeSet;

        let mut observer_actions: BTreeSet<&str> = sysknife_daemon::actions::all_specs()
            .into_iter()
            .filter(|spec| spec.risk_level == RiskLevel::Low)
            .map(|spec| spec.action_name)
            .collect();
        observer_actions.insert("ListJobHistory");

        let read_only: BTreeSet<&str> = MCP_READ_ONLY_ACTIONS.iter().copied().collect();
        let mutating: BTreeSet<&str> = OBSERVER_MUTATING_ACTIONS.iter().copied().collect();
        assert!(
            read_only.is_disjoint(&mutating),
            "an Observer action cannot be both approval-free and mutating"
        );

        let classified: BTreeSet<&str> = read_only.union(&mutating).copied().collect();
        assert_eq!(
            classified, observer_actions,
            "every Observer-callable action must be explicitly classified as read-only or mutating"
        );
        assert_eq!(observer_actions.len(), 63);
        assert_eq!(read_only.len(), 62);
        assert_eq!(mutating, BTreeSet::from(["AptUpdate"]));
    }

    #[test]
    fn direct_tool_names_are_unique_and_described() {
        use std::collections::BTreeSet;

        let names: BTreeSet<String> = MCP_READ_ONLY_ACTIONS
            .iter()
            .map(|action| direct_action_tool_name(action))
            .collect();
        assert_eq!(names.len(), MCP_READ_ONLY_ACTIONS.len());
        assert_eq!(
            direct_action_tool_name("GetDiskUsage"),
            "sysknife_get_disk_usage"
        );
        assert_eq!(
            direct_action_tool_name("AppArmorStatus"),
            "sysknife_app_armor_status"
        );

        for action in MCP_READ_ONLY_ACTIONS {
            assert!(
                KNOWN_ACTIONS.iter().any(|(known, _)| known == action),
                "{action} needs an agent-facing catalogue description"
            );
        }
    }

    #[test]
    fn direct_router_filters_by_distro_and_never_exposes_mutations() {
        let ubuntu = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        let ubuntu_names: std::collections::HashSet<String> =
            direct_read_only_tool_router(Some(&ubuntu))
                .list_all()
                .into_iter()
                .map(|tool| tool.name.to_string())
                .collect();
        assert!(ubuntu_names.contains("sysknife_get_disk_usage"));
        assert!(ubuntu_names.contains("sysknife_apt_search"));
        assert!(!ubuntu_names.contains("sysknife_get_system_state"));
        assert!(!ubuntu_names.contains("sysknife_apt_update"));

        let fedora = DistroId::FedoraSilverblue { version: 41 };
        let fedora_names: std::collections::HashSet<String> =
            direct_read_only_tool_router(Some(&fedora))
                .list_all()
                .into_iter()
                .map(|tool| tool.name.to_string())
                .collect();
        assert!(fedora_names.contains("sysknife_get_system_state"));
        assert!(!fedora_names.contains("sysknife_apt_search"));
        assert!(!fedora_names.contains("sysknife_apt_update"));

        let unknown_names: std::collections::HashSet<String> = direct_read_only_tool_router(None)
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(unknown_names.contains("sysknife_get_disk_usage"));
        assert!(!unknown_names.contains("sysknife_apt_search"));
        assert!(!unknown_names.contains("sysknife_get_system_state"));

        let read_only_names: std::collections::HashSet<String> = MCP_READ_ONLY_ACTIONS
            .iter()
            .map(|action| direct_action_tool_name(action))
            .collect();
        for routed_names in [&ubuntu_names, &fedora_names, &unknown_names] {
            let unexpected: Vec<_> = routed_names.difference(&read_only_names).collect();
            assert!(
                unexpected.is_empty(),
                "approval-free router exposed tools outside MCP_READ_ONLY_ACTIONS: {unexpected:?}"
            );
        }
    }

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
        let server = SysknifeMcpServer::for_distro(None);
        let tools = server.tool_router.list_all();

        let names: std::collections::HashSet<String> =
            tools.iter().map(|t| t.name.to_string()).collect();
        for expected in [
            "sysknife_plan",
            "sysknife_execute",
            "sysknife_history",
            "sysknife_doctor",
            "sysknife_audit_verify",
            "sysknife_get_disk_usage",
            "sysknife_get_memory_info",
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
        // The plan tool's description carries an advisory instruction telling
        // the calling agent to STOP after planning. This is prompt
        // engineering, not enforcement, and this test guards the wording of
        // an operator-facing hint — NOT the security boundary.
        //
        // The actual interlock is structural and lives elsewhere:
        // `PlanOutput`/`PlanStepOutput` carry no `approval_receipt` field, so
        // no code path lets `sysknife_plan` hand back something
        // `sysknife_execute` can consume; receipts come only from a separate
        // `sysknife approve <transaction-id>` run, and the daemon
        // independently rejects forged or stale ones (see
        // `mcp_tools_integrate_with_a_daemon_over_the_socket`). Deleting this
        // clause would degrade the hint, not open a bypass — do not treat it
        // as the thing keeping a human in the loop.
        let server = SysknifeMcpServer::for_distro(None);
        let tools = server.tool_router.list_all();
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
    fn the_server_introduces_itself_as_sysknife() {
        // `Implementation::from_build_env()` expands inside the rmcp crate, so
        // it reported name "rmcp" and rmcp's version — the string clients and
        // registry listings display for this server.
        let info = SysknifeMcpServer::new().get_info();
        assert_eq!(info.server_info.name, "sysknife");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn get_info_exposes_resources_capability_for_codex() {
        let info = SysknifeMcpServer::new().get_info();
        assert!(
            info.capabilities.resources.is_some(),
            "Codex-compatible MCP servers should advertise resources"
        );
        assert!(
            info.capabilities.tools.is_some(),
            "SysKnife must continue advertising tools"
        );
    }

    #[test]
    fn execute_input_without_approval_receipt_is_rejected() {
        let input = serde_json::json!({
            "steps": [{
                "transaction_id": "tx-1",
                "action_name": "AptInstall",
                "params": {"package": "vim"}
            }]
        });
        assert!(serde_json::from_value::<ExecuteInput>(input).is_err());
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

    // -----------------------------------------------------------------------
    // P4 — MCP <-> daemon IPC integration against a fake daemon.
    //
    // Drives the real MCP tool functions (history_inner, execute_steps_inner)
    // over a real Unix socket + the production FramedStream, against a stub
    // daemon that speaks the daemon wire protocol. This exercises the actual
    // request/response shapes end to end (catching wire drift) and, crucially,
    // proves the approval interlock: when the daemon rejects a receipt, MCP
    // execute must surface an error, never report success.
    //
    // nextest runs each test in its own process, so setting SYSKNIFE_SOCKET
    // here does not leak into other tests.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mcp_tools_integrate_with_a_daemon_over_the_socket() {
        use sysknife_daemon::transport::framing::FramedStream;
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("fake-daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        // Stub daemon: one request per connection (the client opens a fresh
        // connection per call). query_history -> structured row; execute ->
        // error_response(stale_approval) to model a rejected receipt.
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut framed = FramedStream::new(stream);
                    let Ok(raw) = framed.recv().await else { return };
                    let req: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                    let resp = match req["type"].as_str() {
                        Some("query_history") => serde_json::json!({
                        "type": "history_response",
                        "request_id": req["request_id"],
                        "entries": [{
                            "transaction_id": "tx-abc123",
                            "action_name": "GetDiskUsage",
                            "risk_level": "low",
                            "status": "succeeded",
                            "summary": "check disk usage",
                            "created_at": "2026-07-19T12:00:00Z"
                            }]
                        }),
                        Some("query_action") => {
                            assert_eq!(req["action_name"], "GetSysctl");
                            assert_eq!(
                                req["params"],
                                serde_json::json!({"key": "net.ipv4.ip_forward"})
                            );
                            serde_json::json!({
                                "type": "query_action_response",
                                "request_id": req["request_id"],
                                "action_name": req["action_name"],
                                "output": "net.ipv4.ip_forward = 0"
                            })
                        }
                        Some("execute") => serde_json::json!({
                            "type": "error_response",
                            "request_id": req["request_id"],
                            "category": "stale_approval",
                            "message": "transaction is not approved for this receipt"
                        }),
                        other => serde_json::json!({
                            "type": "error_response",
                            "request_id": req["request_id"],
                            "category": "validation_failure",
                            "message": format!("unexpected request: {other:?}")
                        }),
                    };
                    let _ = framed.send(&serde_json::to_vec(&resp).unwrap()).await;
                });
            }
        });

        std::env::set_var("SYSKNIFE_SOCKET", sock.to_str().unwrap());

        // History flows through the structured IPC with typed fields populated.
        let entries = history_inner(HistoryInput {
            status: None,
            action: None,
            since: None,
            limit: Some(5),
        })
        .await
        .expect("history over socket");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "GetDiskUsage");
        assert_eq!(
            entries[0].created_at.as_deref(),
            Some("2026-07-19T12:00:00Z")
        );
        assert_eq!(entries[0].risk_level.as_deref(), Some("low"));

        // A generated route uses query_action directly and preserves the exact
        // catalogue action plus the caller's parameter object.
        let query_output = direct_query_inner(
            "GetSysctl".to_string(),
            serde_json::json!({"key": "net.ipv4.ip_forward"}),
        )
        .await
        .expect("direct read-only query over socket");
        assert_eq!(query_output, "net.ipv4.ip_forward = 0");

        // Interlock: the daemon rejects the receipt, so execute MUST error,
        // never fabricate a success result.
        let result = execute_steps_inner(vec![StepToExecute {
            transaction_id: "tx-abc123".to_string(),
            action_name: "GetDiskUsage".to_string(),
            params: serde_json::json!({}),
            approval_receipt: "receipt-the-daemon-will-reject".to_string(),
        }])
        .await;
        assert!(
            result.is_err(),
            "a daemon-rejected receipt must surface as an MCP error, got: {result:?}"
        );
        assert!(
            result.unwrap_err().contains("stale_approval"),
            "the rejection reason must reach the caller"
        );

        std::env::remove_var("SYSKNIFE_SOCKET");
        server.abort();
    }

    // -----------------------------------------------------------------------
    // The socket label an MCP client reads
    //
    // `sysknife doctor` on the CLI was fixed to render sockets as
    // `unix:///run/…` instead of Rust's `Unix("/run/…")`, but the MCP path
    // kept its own `format!("{socket:?}")` and was missed. The two then
    // disagreed about the same value, and the schema description shipped the
    // Debug form as the documented example — which is what an LLM, and
    // Glama's tool evaluator, actually read.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn doctor_reports_the_socket_as_a_uri_not_rust_debug() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("daemon.sock");
        std::env::set_var("SYSKNIFE_SOCKET", sock.to_str().unwrap());

        let report = doctor_inner().await;

        std::env::remove_var("SYSKNIFE_SOCKET");

        assert_eq!(
            report.daemon_socket,
            format!("unix://{}", sock.display()),
            "the MCP report must use the same URI form as the CLI"
        );
        assert!(
            !report.daemon_socket.contains("Unix("),
            "no Rust Debug formatting in MCP output: {}",
            report.daemon_socket
        );
        // The value must be something a caller can feed back to SYSKNIFE_SOCKET.
        assert_eq!(
            crate::client::SocketTarget::try_from_str(&report.daemon_socket).unwrap(),
            crate::client::SocketTarget::Unix(sock.clone()),
        );
    }

    #[test]
    fn the_doctor_schema_documents_the_uri_form_not_the_debug_form() {
        // This description is published to every MCP client as the field's
        // documentation, so a stale example is a wrong instruction, not a typo.
        let schema = serde_json::to_string(&schemars::schema_for!(DoctorReport)).unwrap();
        assert!(
            !schema.contains("Unix("),
            "the schema still documents Rust Debug formatting: {schema}"
        );
        assert!(
            schema.contains("unix://"),
            "the schema should show the URI form as its example"
        );
    }

    #[test]
    fn no_source_file_formats_a_socket_target_with_debug() {
        // The CLI fix landed and the MCP one was missed, so the same defect
        // existed twice in one crate. Cheaper to assert the shape is gone than
        // to rediscover it from a third party's build log.
        //
        // The needle is assembled from two halves so this file does not contain
        // the pattern it forbids, which would make the test fail on itself.
        let needle = concat!("{socket", ":?}");
        for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            for (n, line) in src.lines().enumerate() {
                // Comments do not execute, and the comments explaining this
                // very defect necessarily quote the pattern.
                if line.trim_start().starts_with("//") {
                    continue;
                }
                assert!(
                    !line.contains(needle),
                    "{}:{} formats a socket with Debug; use SocketTarget::label()",
                    path.display(),
                    n + 1
                );
            }
        }
    }
}
