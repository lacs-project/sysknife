//! Core planning types and `LlmPlanner`.
//!
//! `LlmPlanner` drives a tool-use loop with a configured `LlmProvider`,
//! calls `StateClient::curated_state()` when the LLM invokes the
//! `get_system_state` tool, and returns a validated `Plan` when the LLM
//! calls `propose_plan`.
//!
//! The loop is bounded by `max_turns`. If the LLM exhausts all turns without
//! calling `propose_plan`, the planner returns `PlanningError::PlannerStuck`.
//!
//! Note: `StateClient::curated_state()` is synchronous. The production
//! `DaemonIpcClient` in `sysknife-shell` uses a blocking `UnixStream`; Tauri
//! async commands run on a thread pool so blocking is acceptable there.
//! Other runtimes using `StateClient` on a single-threaded async executor
//! must use `spawn_blocking`.

use crate::action_name::ActionName;
use crate::audit::SafetyAuditLog;
use crate::config::{BrainConfig, ProviderConfig};
use crate::planning_tools::get_state::get_state_tool_def;
use crate::planning_tools::propose_plan::{parse_proposed_plan, propose_plan_tool_def};
use crate::planning_tools::query_tools::query_tools;
use crate::prompt::build_system_prompt;
use std::time::Duration;

use crate::provider::{
    Completion, ContentBlock, LlmProvider, Message, ProviderError, Role, StopReason,
    ToolDefinition, ToolResultBlock,
};
use crate::providers::openai_adapter::AsyncOpenAiAdapter;
use crate::providers::rig_adapter::RigCompletionAdapter;
use crate::sanitize::sanitize_tool_output;
use crate::state_client::StateClient;
use rig::client::CompletionClient;
use serde::Serialize;
use sysknife_types::DistroHint;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Ollama-provider tuning constants
// ---------------------------------------------------------------------------

/// Output token budget passed to Ollama as `options.num_predict`.
///
/// Why this is needed at all: Rig's `OllamaCompletionRequest` sends
/// `max_tokens` at the top level of the JSON body, which Ollama's
/// `/api/chat` endpoint **ignores**. Ollama reads `options.num_predict`
/// for the generation limit. The `RigCompletionAdapter::with_additional_params`
/// keys (other than `think`/`keep_alive`, which the Ollama provider
/// consumes as top-level fields) flow into `options`, so writing
/// `num_predict` there lands it in the right place.
///
/// Why this specific value: we need enough headroom for:
///   - a thinking trace (qwen3 typically emits 100–400 tokens),
///   - a complete `propose_plan` tool-call JSON (150–300 tokens),
///   - a small buffer for retries and fallbacks.
///
/// 4096 covers the worst case comfortably while staying below values
/// that would let the model wander for minutes of thinking on CPU.
/// Empirically, well-behaved SysKnife runs never approach this limit;
/// untuned models that *do* approach it are the ones we cannot use
/// anyway (CPU inference hits Ollama's internal request timeout first).
pub const OLLAMA_NUM_PREDICT: u32 = 4096;

/// Maximum output tokens for the planning loop.
///
/// Must be large enough for: a thinking trace (100–400 tokens),
/// a `propose_plan` tool-call JSON (150–300 tokens), and a
/// buffer for multi-turn retries. 4096 is generous for all
/// providers — well-behaved runs rarely exceed 1000.
pub const PLANNING_MAX_TOKENS: u32 = 4096;

/// How many times one turn's provider call may be re-attempted after a
/// retryable failure (so at most `1 + PROVIDER_RETRY_LIMIT` attempts).
///
/// Small on purpose. This covers the momentary failures — a 502, a truncated
/// payload, one 429 — and deliberately does not try to ride out a real outage:
/// an operator waiting on a plan is better served by a clear failure than by a
/// command that hangs for a minute and then fails anyway.
const PROVIDER_RETRY_LIMIT: u32 = 2;

/// First backoff before re-attempting a failed provider call; doubles per retry.
const PROVIDER_RETRY_BACKOFF: Duration = Duration::from_millis(400);

/// First backoff when the provider explicitly signalled rate limiting. Longer
/// than [`PROVIDER_RETRY_BACKOFF`]: retrying a 429 on the same schedule as a 502
/// is how a rate limit turns into a rate-limit loop.
const PROVIDER_RETRY_RATE_LIMIT_BACKOFF: Duration = Duration::from_millis(2_000);

/// The sentence to add before retrying a call the provider rejected because the
/// model named a nonexistent tool.
///
/// Returns `None` for every other error, so an ordinary 502 or timeout still
/// retries the request unchanged — resending is the correct response when the
/// request was never the problem. The classification itself lives on
/// [`ProviderError::is_invalid_tool_call`], because the cassette has to record
/// exactly the failures this corrects — see its doc for why the two sets must
/// be the same one.
fn tool_call_correction(error: &ProviderError, tools: &[ToolDefinition]) -> Option<String> {
    if !error.is_invalid_tool_call() {
        return None;
    }

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    Some(format!(
        "Your previous response was rejected: it called a tool that does not exist. \
         Call one of these tools by its exact name: {}. \
         Emit a real tool call, not a JSON object describing one, and do not wrap \
         the call in another name. If the plan you had in mind was correct, send \
         the same plan through `propose_plan`.",
        names.join(", ")
    ))
}

/// Maximum byte length accepted for a natural-language intent.
///
/// 2 KB covers any realistic user request. Values larger than this are
/// almost certainly copy-paste accidents or prompt-injection attempts.
/// Enforced before the intent string is forwarded to the LLM provider,
/// so oversized payloads are rejected without incurring API cost.
pub const INTENT_MAX_BYTES: usize = 2048;

/// Default rate limit applied by `from_config`: 20 planning requests per 60-second
/// sliding window. Override at runtime with `SYSKNIFE_MAX_RPM`.
///
/// This prevents a looping script or misconfigured automation from exhausting
/// cloud LLM quota. Interactive users rarely exceed 5 requests per minute;
/// 20 provides generous headroom while still bounding runaway usage.
pub const DEFAULT_MAX_RPM: usize = 20;

/// Maximum output tokens for the summarization endpoint.
///
/// Summarization produces short plain-language text (no tools,
/// no structured output). 512 tokens is ample for a one-paragraph
/// summary of daemon execution output.
pub const SUMMARIZATION_MAX_TOKENS: u32 = 512;

/// Model-name prefixes that signal thinking-mode capability in Ollama.
///
/// Source of truth: Ollama documents which models accept the `think`
/// field on `/api/chat`. Sending `think: true` to a non-thinking model
/// returns HTTP 400 with `"does not support thinking"`. This list
/// therefore must be kept conservative — add a prefix only after
/// verifying the model's tag + Ollama version combination accepts it.
///
/// Current entries, verified live:
///   - `qwen3`    — all Qwen3 variants (0.6b … 30b-a3b)
///   - `qwq`      — Qwen reasoning-focused variant (qwq:32b)
///   - `deepseek-r` — DeepSeek-R1 family
///
/// NOT listed (do not support thinking): `llama3.2`, `gemma3`,
/// `qwen2.5`, `mistral`, `gemma2`.
///
/// An out-of-process override lives in `SYSKNIFE_OLLAMA_THINK`; this
/// auto-detection is only the default.
pub const THINKING_MODEL_PREFIXES: &[&str] = &["qwen3", "qwq", "deepseek-r"];

/// Environment variable that overrides the auto-detected thinking mode.
///
/// Set to `"true"` or `"false"` (case-insensitive). Any other value
/// falls back to auto-detection. Populated by `LacsConfig` from
/// `config.toml`'s `[llm] ollama_think` field.
pub const SYSKNIFE_OLLAMA_THINK_ENV: &str = "SYSKNIFE_OLLAMA_THINK";

/// Decide whether to send `think: true` for a given Ollama model.
///
/// Resolution order (highest priority wins):
///   1. `SYSKNIFE_OLLAMA_THINK` env var, if set to a parseable `true`/`false`.
///   2. Auto-detection against [`THINKING_MODEL_PREFIXES`].
///
/// An unparseable env-var value (neither `"true"` nor `"false"` after
/// trimming and lowercasing) is ignored — we fall back to auto-detection
/// so a typo does not silently break tool use.
///
/// The distinction matters on CPU-only hosts: thinking models on 4 vCPUs
/// emit long reasoning traces that exceed Ollama's request timeout before
/// any tool call lands. Users on CPU should set `ollama_think = false`
/// in `config.toml` for qwen3-class models; this helper respects that.
pub fn resolve_ollama_think(model: &str) -> bool {
    if let Ok(raw) = std::env::var(SYSKNIFE_OLLAMA_THINK_ENV) {
        match raw.trim().to_lowercase().as_str() {
            "true" => return true,
            "false" => return false,
            _ => {
                // Unparseable override — fall through to auto-detection.
                // We intentionally do not log this; startup noise is not
                // worth it and the auto-detected behaviour is safe.
            }
        }
    }
    let model_lower = model.to_lowercase();
    THINKING_MODEL_PREFIXES
        .iter()
        .any(|prefix| model_lower.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// PlanEvent
// ---------------------------------------------------------------------------

/// Progress events emitted by the LLM planning loop.
///
/// Consumers (e.g. the `sysknife` CLI) subscribe via an
/// `tokio::sync::mpsc::UnboundedSender<PlanEvent>` and update a spinner
/// message in real time.  Events are fire-and-forget; a closed channel is
/// silently ignored.
#[derive(Debug, Clone)]
pub enum PlanEvent {
    /// The planner sent the first prompt to the LLM.
    Thinking,
    /// The LLM called a query or state tool by the given name.
    QueryingTool(String),
    /// The LLM called `propose_plan` with a valid proposal.
    ProposingPlan,
}

// ---------------------------------------------------------------------------
// Risk level
// ---------------------------------------------------------------------------

/// Risk classification for a single plan step.
///
/// Determines whether the step requires explicit user approval before execution.
/// Serialises to lowercase strings (`"low"`, `"medium"`, `"high"`) matching the
/// values expected by `parse_proposed_plan` and the system prompt.
/// Ordering is declaration order (`Low < Medium < High`), so risk levels compare
/// directly (`daemon <= approved`, `steps.max()`) without a separate rank table.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanRiskLevel {
    Low,
    Medium,
    High,
}

impl PlanRiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Shared by [`PlanStep::approval_required`] and [`AuthorizedStep::approval_required`]:
/// any risk above `Low` requires approval.
fn requires_approval(risk: &PlanRiskLevel) -> bool {
    !matches!(risk, PlanRiskLevel::Low)
}

// ---------------------------------------------------------------------------
// PlanStep
// ---------------------------------------------------------------------------

/// A single action within a plan.
///
/// `approval_required` is a pure function of `risk_level`: `Low` → false,
/// `Medium`/`High` → true. It is not stored separately to prevent the class of
/// bugs where the stored value disagrees with the risk level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanStep {
    action_name: ActionName,
    summary: String,
    risk_level: PlanRiskLevel,
    params: serde_json::Value,
}

impl PlanStep {
    /// Construct a step. Returns an error if `summary` is empty.
    ///
    /// `action_name` is an [`ActionName`] which guarantees membership in
    /// the approved action catalogue at construction time.
    pub fn new(
        action_name: ActionName,
        summary: String,
        risk_level: PlanRiskLevel,
        params: serde_json::Value,
    ) -> Result<Self, PlanValidationError> {
        if summary.is_empty() {
            return Err(PlanValidationError(
                "PlanStep summary must not be empty".into(),
            ));
        }
        Ok(Self {
            action_name,
            summary,
            risk_level,
            params,
        })
    }

    pub fn action_name(&self) -> &str {
        self.action_name.as_str()
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// The LLM's *proposed* risk for this step. NOT authoritative — it must never
    /// drive an approval decision. Convert the plan with [`Plan::into_authorized`]
    /// and gate on [`AuthorizedStep::risk_level`], which reflects the daemon's
    /// `ActionSpec` (the single source of truth). This accessor exists only for
    /// display of the raw proposal and for the proposed-vs-authoritative
    /// mismatch warning.
    pub fn proposed_risk_level(&self) -> &PlanRiskLevel {
        &self.risk_level
    }

    /// Derived from the *proposed* risk level: `true` for Medium and High,
    /// `false` for Low. For gating, prefer [`AuthorizedStep::approval_required`].
    pub fn approval_required(&self) -> bool {
        requires_approval(&self.risk_level)
    }

    pub fn params(&self) -> &serde_json::Value {
        &self.params
    }
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// A complete, validated plan returned by `LlmPlanner::plan_intent`.
///
/// Guaranteed to have at least one step. Constructed only through
/// `parse_proposed_plan`, which validates all fields before calling `Plan::new`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    intent: String,
    summary: String,
    explanation: String,
    steps: Vec<PlanStep>,
}

impl Plan {
    /// Construct a plan. Returns an error if `steps` is empty or any string
    /// field is empty.
    pub fn new(
        intent: String,
        summary: String,
        explanation: String,
        steps: Vec<PlanStep>,
    ) -> Result<Self, PlanValidationError> {
        if intent.is_empty() {
            return Err(PlanValidationError("Plan intent must not be empty".into()));
        }
        if summary.is_empty() {
            return Err(PlanValidationError("Plan summary must not be empty".into()));
        }
        if explanation.is_empty() {
            return Err(PlanValidationError(
                "Plan explanation must not be empty".into(),
            ));
        }
        if steps.is_empty() {
            return Err(PlanValidationError(
                "Plan must have at least one step".into(),
            ));
        }
        Ok(Self {
            intent,
            summary,
            explanation,
            steps,
        })
    }

    pub fn intent(&self) -> &str {
        &self.intent
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    /// Consume this plan and replace every step's risk with the authoritative
    /// value from `risk_for` (keyed by action name), yielding an
    /// [`AuthorizedPlan`].
    ///
    /// The CLI supplies the daemon's `ActionSpec`-derived risk (the single source
    /// of truth) so both the plan the operator sees and the auto-approval gate
    /// reflect authoritative risk rather than a model guess. Brain stays agnostic
    /// to the daemon's action catalogue: the caller supplies the mapping. This is
    /// the only substituting constructor of `AuthorizedPlan`, so the gate can
    /// never be handed un-substituted (LLM-proposed) risk.
    #[must_use]
    pub fn into_authorized(mut self, risk_for: impl Fn(&str) -> PlanRiskLevel) -> AuthorizedPlan {
        for step in &mut self.steps {
            step.risk_level = risk_for(step.action_name.as_str());
        }
        AuthorizedPlan { plan: self }
    }

    /// Wrap this plan as authoritative *without* substituting risk.
    ///
    /// **Test-only.** `AuthorizedPlan` exists to make it structurally
    /// impossible to feed the approval gate the LLM's self-reported risk, and
    /// this function is the one hole in that guarantee. It was a plain `pub fn`
    /// whose contract lived only in a doc comment, so any crate — including a
    /// future refactor of the MCP planning path reaching for something simpler
    /// than the per-step daemon preview — could construct an `AuthorizedPlan`
    /// from unvalidated risk and still compile.
    ///
    /// Gating it behind `test-support` makes that a compile error outside
    /// tests. Production paths must use [`Plan::into_authorized`], which forces
    /// the caller to supply the substitution function.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assume_authorized(self) -> AuthorizedPlan {
        AuthorizedPlan { plan: self }
    }
}

// ---------------------------------------------------------------------------
// AuthorizedPlan / AuthorizedStep
// ---------------------------------------------------------------------------

/// A plan whose per-step risk levels are the daemon's authoritative
/// `ActionSpec`-derived risk, not the LLM's proposal.
///
/// This is the only type whose steps expose [`AuthorizedStep::risk_level`] for
/// gating. A raw [`Plan`] exposes only [`PlanStep::proposed_risk_level`], so it
/// is impossible to feed the approval gate an un-substituted (proposed) risk by
/// accident. Construct via [`Plan::into_authorized`] (substitutes) or, where the
/// risks are already authoritative, `Plan::assume_authorized` — which is
/// gated behind the `test-support` feature and so is not part of the public
/// API this documentation describes (hence the plain reference, not a link).
pub struct AuthorizedPlan {
    plan: Plan,
}

impl AuthorizedPlan {
    pub fn intent(&self) -> &str {
        self.plan.intent()
    }

    pub fn summary(&self) -> &str {
        self.plan.summary()
    }

    pub fn explanation(&self) -> &str {
        self.plan.explanation()
    }

    /// The plan's steps, each exposing its authoritative risk.
    pub fn steps(&self) -> impl ExactSizeIterator<Item = AuthorizedStep<'_>> {
        self.plan.steps.iter().map(AuthorizedStep)
    }

    /// Highest authoritative risk across all steps (`None` only if empty, which
    /// [`Plan::new`] forbids). Relies on `PlanRiskLevel: Ord`.
    pub fn highest_risk(&self) -> Option<&PlanRiskLevel> {
        self.plan.steps.iter().map(|s| &s.risk_level).max()
    }
}

/// A view over a single [`PlanStep`] whose risk is known to be authoritative.
/// Obtainable only from [`AuthorizedPlan::steps`].
#[derive(Clone, Copy)]
pub struct AuthorizedStep<'a>(&'a PlanStep);

impl<'a> AuthorizedStep<'a> {
    pub fn action_name(&self) -> &'a str {
        self.0.action_name.as_str()
    }

    pub fn summary(&self) -> &'a str {
        &self.0.summary
    }

    pub fn params(&self) -> &'a serde_json::Value {
        &self.0.params
    }

    /// The authoritative (`ActionSpec`-derived) risk for this step.
    pub fn risk_level(&self) -> &'a PlanRiskLevel {
        &self.0.risk_level
    }

    /// Derived from the authoritative risk: `true` for Medium and High.
    pub fn approval_required(&self) -> bool {
        requires_approval(&self.0.risk_level)
    }
}

// ---------------------------------------------------------------------------
// PlanValidationError
// ---------------------------------------------------------------------------

/// Returned when `Plan::new` or `PlanStep::new` receives invalid arguments.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct PlanValidationError(pub String);

// ---------------------------------------------------------------------------
// PlanningError
// ---------------------------------------------------------------------------

#[non_exhaustive]
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlanningError {
    #[error("intent must not be empty")]
    EmptyIntent,

    #[error(
        "intent exceeds maximum length of {max} bytes (got {len}); \
         shorten the request or split it into multiple commands"
    )]
    IntentTooLong { len: usize, max: usize },

    #[error(
        "intent contains sensitive data (API keys, passwords, or tokens \
         must not be forwarded to LLM providers)"
    )]
    IntentContainsSensitiveData,

    #[error(
        "rate limit exceeded; too many planning requests in the last 60 seconds \
         (retry after {retry_after_secs}s)"
    )]
    RateLimitExceeded { retry_after_secs: u64 },

    #[error("state unavailable: {0}")]
    StateUnavailable(String),

    #[error("planner did not propose a plan within the allowed turns")]
    PlannerStuck,

    #[error("planner ended without proposing a plan")]
    NoPlanProposed,

    /// The model declined: no valid action can satisfy the request.
    ///
    /// Deliberately distinct from [`PlannerStuck`](Self::PlannerStuck) and
    /// [`NoPlanProposed`](Self::NoPlanProposed). Those mean the planner failed;
    /// this means it succeeded and the answer is no. Before the `refuse` tool
    /// existed the two were indistinguishable, so an impossible request either
    /// crashed as PlannerStuck or came back as an adjacent action the user never
    /// asked for (#179).
    ///
    /// It is an `Err` because the caller has no plan to execute, not because
    /// anything went wrong — callers are expected to match it and render the
    /// reason, never to print it as an internal failure.
    #[error("{reason}")]
    Refused {
        reason: String,
        suggestion: Option<String>,
    },

    /// Carries the provider failure structurally.
    ///
    /// This used to be a `String` built from `ProviderError::to_string()`,
    /// which threw away a classification the provider layer had already made.
    /// Callers that needed it back — the shell's error mapper — recovered it by
    /// searching the rendered message for `"429"` and `"http"`, so an edit to a
    /// `#[error(...)]` format string in `provider.rs` could silently reclassify
    /// a rate limit as a parse error.
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),

    #[error("invalid plan output: {0}")]
    InvalidPlanOutput(String),
}

impl From<PlanValidationError> for PlanningError {
    fn from(e: PlanValidationError) -> Self {
        Self::InvalidPlanOutput(e.0)
    }
}

// ---------------------------------------------------------------------------
// LlmPlanner
// ---------------------------------------------------------------------------

/// Drives the LLM planning loop.
///
/// Tool definitions and the system prompt are both rebuilt per `plan_intent()`
/// call, from the same state: current user preferences and, when set, a
/// distro-specific action family hint.
///
/// The tools used to be snapshotted in [`LlmPlanner::new`]. That was safe only
/// while the schema was distro-agnostic — [`with_distro`] runs *after* `new`, so
/// a construction-time snapshot could not reflect the hint, and the Debian
/// `propose_plan` schema went out offering every Fedora action.
///
/// [`with_distro`]: LlmPlanner::with_distro
pub struct LlmPlanner {
    provider: Box<dyn LlmProvider>,
    state_client: Box<dyn StateClient>,
    max_turns: usize,
    audit_log: Option<SafetyAuditLog>,
    prefs_path: Option<std::path::PathBuf>,
    progress_tx: Option<tokio::sync::mpsc::UnboundedSender<PlanEvent>>,
    rate_limiter: Option<std::sync::Arc<crate::rate_limit::RateLimiter>>,
    distro_hint: Option<DistroHint>,
}

impl LlmPlanner {
    /// Construct a planner directly.
    ///
    /// # Panics
    /// Panics if `max_turns` is zero.
    pub fn new(
        provider: Box<dyn LlmProvider>,
        state_client: Box<dyn StateClient>,
        max_turns: usize,
    ) -> Self {
        assert!(max_turns >= 1, "max_turns must be at least 1");
        Self {
            provider,
            state_client,
            max_turns,
            audit_log: None,
            prefs_path: None,
            progress_tx: None,
            rate_limiter: None,
            distro_hint: None,
        }
    }

    /// Attach an optional [`SafetyAuditLog`] for persistent logging of
    /// safety fence activations. When set, every `propose_plan` rejection
    /// is appended to the log file in addition to being printed to stderr.
    pub fn with_audit_log(mut self, log: SafetyAuditLog) -> Self {
        self.audit_log = Some(log);
        self
    }

    /// Set the path to the user preferences file.
    ///
    /// When set, preferences are read at the start of each `plan_intent()`
    /// call and injected into the system prompt. The `remember` and `forget`
    /// tools write to this file.
    pub fn with_prefs_path(mut self, path: std::path::PathBuf) -> Self {
        self.prefs_path = Some(path);
        self
    }

    /// Attach a progress channel for real-time planning feedback.
    ///
    /// The planner emits [`PlanEvent`]s on `tx` as it progresses through the
    /// tool-use loop. The sender is owned by this `LlmPlanner` and closes
    /// when the planner itself is dropped. Drop the planner explicitly after
    /// `plan_intent` returns if you need the receiver to drain before proceeding.
    pub fn with_progress(mut self, tx: tokio::sync::mpsc::UnboundedSender<PlanEvent>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Attach a [`RateLimiter`] to cap LLM requests per 60-second window.
    ///
    /// When set, `plan_intent` and `summarize` call
    /// [`check_and_consume_async`] before forwarding the request to the LLM
    /// provider. If the window is full, they return
    /// [`PlanningError::RateLimitExceeded`] with the number of seconds until
    /// a slot opens.
    ///
    /// [`check_and_consume_async`]: crate::rate_limit::RateLimiter::check_and_consume_async
    ///
    /// [`RateLimiter`]: crate::rate_limit::RateLimiter
    pub fn with_rate_limiter(mut self, rl: crate::rate_limit::RateLimiter) -> Self {
        self.rate_limiter = Some(std::sync::Arc::new(rl));
        self
    }

    /// The tools offered for one planning call: the query tools, the preference
    /// tools, and a `propose_plan` schema scoped to the detected distro family.
    ///
    /// Built per call, not cached, because [`Self::with_distro`] can only run
    /// after [`Self::new`] — see the type-level note on `LlmPlanner`.
    fn tool_defs(&self) -> Vec<ToolDefinition> {
        let mut t = vec![get_state_tool_def()];
        t.extend(query_tools());
        t.push(crate::planning_tools::preferences::remember_tool_def());
        t.push(crate::planning_tools::preferences::forget_tool_def());
        t.push(propose_plan_tool_def(
            self.distro_hint.as_ref().map(|h| h.family),
        ));
        t.push(crate::planning_tools::refuse::refuse_tool_def());
        t
    }

    /// Attach a [`DistroHint`] to guide action-family selection in the prompt.
    ///
    /// When set, the system prompt gains a **Detected distro** section that
    /// names which action families are available on the running distro and
    /// which are not.  This tells the model to choose `AptInstall` on Ubuntu
    /// and `AddLayeredPackage` on Fedora without requiring a planning-time
    /// query tool call.
    ///
    /// When `None` (the default), the prompt falls back to the existing
    /// distro-agnostic text so all existing tests and no-distro deployments
    /// continue to work unchanged.
    pub fn with_distro(mut self, distro: DistroHint) -> Self {
        self.distro_hint = Some(distro);
        self
    }

    /// Shared prelude for the `remember`/`forget` tool-call handlers: extract
    /// the `fact` string and run the checks common to both — non-empty, then a
    /// caller-supplied extra check (`remember` rejects sensitive data; `forget`
    /// has none), then confirm preference storage is configured. Returns
    /// `Err((message, is_error))` in the same shape both callers push into a
    /// `ToolResultBlock` on failure, so only the differing async operation and
    /// its success/failure formatting stay in each match arm.
    fn prepare_pref_op<'a>(
        &self,
        input: &'a serde_json::Value,
        extra_check: impl FnOnce(&str) -> Option<String>,
    ) -> Result<(&'a str, std::path::PathBuf), (String, bool)> {
        let fact = input.get("fact").and_then(|v| v.as_str()).unwrap_or("");
        if fact.is_empty() {
            return Err((
                "Error: 'fact' parameter must not be empty.".to_string(),
                true,
            ));
        }
        if let Some(msg) = extra_check(fact) {
            return Err((msg, true));
        }
        match self.prefs_path.clone() {
            Some(p) => Ok((fact, p)),
            None => Err((
                "Error: preference storage is not configured.".to_string(),
                true,
            )),
        }
    }

    /// Send a [`PlanEvent`] to the progress channel, if one is attached.
    ///
    /// A closed or absent channel is silently ignored — progress events are
    /// advisory and must never affect planning behaviour.
    fn emit(&self, event: PlanEvent) {
        if let Some(ref tx) = self.progress_tx {
            let _ = tx.send(event);
        }
    }

    /// Construct a planner from a [`BrainConfig`].
    ///
    /// Uses Rig provider clients for all backends. Returns an error if the
    /// HTTP client cannot be initialised (rare; only fails if the TLS
    /// subsystem is unavailable).
    ///
    /// Rate limiting is **enabled by default** at [`DEFAULT_MAX_RPM`] requests
    /// per minute. Override with the `SYSKNIFE_MAX_RPM` environment variable.
    /// Call `with_rate_limiter` after this to replace the default limiter, or
    /// use `new` directly to build a planner without any rate limiting.
    pub fn from_config(
        config: BrainConfig,
        state_client: Box<dyn StateClient>,
    ) -> Result<Self, String> {
        // Read before the match below consumes `config.provider`. This names the
        // cassette surface, so a recording made against one model can never be
        // replayed as evidence about another.
        let surface = format!("{}/{}", config.provider_name(), config.model_name());
        let cassette = crate::cassette::from_env()?;

        let provider: Box<dyn LlmProvider> = match config.provider {
            ProviderConfig::Anthropic {
                api_key,
                model,
                base_url,
            } => {
                let client = rig::providers::anthropic::Client::builder()
                    .api_key(api_key)
                    .base_url(base_url)
                    .build()
                    .map_err(|e| format!("failed to initialize anthropic provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                Box::new(RigCompletionAdapter::new(completion_model))
            }
            ProviderConfig::Ollama { base_url, model } => {
                let client = rig::providers::ollama::Client::builder()
                    .api_key(rig::client::Nothing)
                    .base_url(base_url)
                    .build()
                    .map_err(|e| format!("failed to initialize ollama provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                // See `OLLAMA_NUM_PREDICT` and `THINKING_MODEL_PREFIXES`
                // at the top of this module for the rationale behind each
                // key sent through `additional_params`.
                let think = resolve_ollama_think(&model);
                let mut params = serde_json::json!({ "num_predict": OLLAMA_NUM_PREDICT });
                if think {
                    params["think"] = serde_json::Value::Bool(true);
                }
                Box::new(RigCompletionAdapter::new(completion_model).with_additional_params(params))
            }
            ProviderConfig::OpenAI { api_key, model } => {
                // Use async-openai directly with the Chat Completions API.
                // rig's OpenAI backend defaults to the Responses API, which:
                //   - emits reasoning-only items on some model variants → parse errors
                //   - places the system prompt in a user message (rig issue #1599)
                // async-openai targets /v1/chat/completions, has none of these issues.
                Box::new(AsyncOpenAiAdapter::new(api_key, model))
            }
            ProviderConfig::Gemini { api_key, model } => {
                let client = rig::providers::gemini::Client::builder()
                    .api_key(api_key)
                    .build()
                    .map_err(|e| format!("failed to initialize gemini provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                Box::new(RigCompletionAdapter::new(completion_model))
            }
            ProviderConfig::Groq { api_key, model } => {
                let client = rig::providers::groq::Client::builder()
                    .api_key(api_key)
                    .build()
                    .map_err(|e| format!("failed to initialize groq provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                Box::new(RigCompletionAdapter::new(completion_model))
            }
            ProviderConfig::DeepSeek { api_key, model } => {
                let client = rig::providers::deepseek::Client::builder()
                    .api_key(api_key)
                    .build()
                    .map_err(|e| format!("failed to initialize deepseek provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                Box::new(RigCompletionAdapter::new(completion_model))
            }
            ProviderConfig::Mistral { api_key, model } => {
                let client = rig::providers::mistral::Client::builder()
                    .api_key(api_key)
                    .build()
                    .map_err(|e| format!("failed to initialize mistral provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                Box::new(RigCompletionAdapter::new(completion_model))
            }
            ProviderConfig::XAI { api_key, model } => {
                let client = rig::providers::xai::Client::builder()
                    .api_key(api_key)
                    .build()
                    .map_err(|e| format!("failed to initialize xai provider: {e}"))?;
                let completion_model = client.completion_model(&model);
                Box::new(RigCompletionAdapter::new(completion_model))
            }
        };
        let replaying = matches!(
            cassette.as_ref().map(crate::cassette::Cassette::mode),
            Some(crate::cassette::CassetteMode::Replay)
        );
        let provider: Box<dyn LlmProvider> = match cassette {
            Some(cassette) => Box::new(crate::cassette::CassetteProvider::new(
                provider, cassette, surface,
            )),
            None => provider,
        };

        let mut planner = Self::new(provider, state_client, config.max_turns);
        planner.prefs_path = Some(sysknife_core::config::prefs_path());

        if replaying {
            // No rate limiter under replay. It exists to bound spend and load on a
            // provider, and a replay reaches neither: every answer comes off disk.
            // Leaving it installed would throttle a 50-story suite at story 20 on
            // the strength of requests that were never sent.
            return Ok(planner);
        }

        // Wire the default rate limiter. `SYSKNIFE_MAX_RPM` overrides at runtime.
        // The timestamp file lives next to the audit log in $XDG_DATA_HOME/sysknife/.
        let rate_log_path = {
            let xdg = std::env::var("XDG_DATA_HOME").unwrap_or_default();
            let base = if xdg.is_empty() {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                std::path::PathBuf::from(home).join(".local/share")
            } else {
                std::path::PathBuf::from(xdg)
            };
            base.join("sysknife").join("rate-limit.log")
        };
        planner.rate_limiter = Some(std::sync::Arc::new(crate::rate_limit::RateLimiter::new(
            rate_log_path,
            DEFAULT_MAX_RPM,
        )));
        Ok(planner)
    }

    /// Expose the current system state from the underlying `StateClient`.
    ///
    /// Used by the Tauri commands layer to populate system-context fields in
    /// `PlanResponse` without requiring a second network call.
    pub fn curated_state(&self) -> Result<crate::state_client::CuratedState, PlanningError> {
        self.state_client.curated_state()
    }

    /// Length, sensitive-data, and rate-limit checks shared by every entry point
    /// that forwards free text to the LLM provider. `plan_intent` and
    /// `summarize` used to repeat this three-step gate independently; keeping it
    /// in one place means a future change to the sequence (e.g. an added scan)
    /// can't be made at one call site and forgotten at the other.
    async fn admit_request(&self, text: &str) -> Result<(), PlanningError> {
        if text.len() > INTENT_MAX_BYTES {
            return Err(PlanningError::IntentTooLong {
                len: text.len(),
                max: INTENT_MAX_BYTES,
            });
        }
        if crate::prefs::contains_sensitive(text) {
            return Err(PlanningError::IntentContainsSensitiveData);
        }
        if let Some(ref rl) = self.rate_limiter {
            if let Err(retry_after_secs) = std::sync::Arc::clone(rl).check_and_consume_async().await
            {
                return Err(PlanningError::RateLimitExceeded { retry_after_secs });
            }
        }
        Ok(())
    }

    /// Generate a plain-language summary of a short prompt, bypassing the
    /// tool-use loop. Used for post-execution review.
    ///
    /// Returns the raw text content from the LLM. No tools are provided, so
    /// the LLM is constrained to text-only output.
    pub async fn summarize(&self, prompt: &str) -> Result<String, PlanningError> {
        self.admit_request(prompt).await?;

        let messages = vec![Message::user_text(prompt)];
        let completion = self
            .provider
            .complete(
                "You are a concise technical writer. Respond with a short plain-language summary. Do not use markdown formatting.",
                &messages,
                &[], // no tools
                SUMMARIZATION_MAX_TOKENS,
            )
            .await
            .map_err(PlanningError::from)?;

        // Extract text from the completion
        let text = completion
            .content
            .iter()
            .filter_map(|b| {
                if let ContentBlock::Text { text } = b {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        if text.is_empty() {
            Err(PlanningError::NoPlanProposed)
        } else {
            Ok(text)
        }
    }

    /// One turn's provider call, re-attempted on failures that could plausibly
    /// succeed a moment later.
    ///
    /// The turn loop already retries the *model's* mistakes; a provider-level
    /// failure used to end planning outright, so one 502 or one truncated payload
    /// wasted an entire intent with most of the turn budget unused.
    /// [`ProviderError::is_retryable`] draws the line — notably `Auth` and
    /// `CassetteMiss` are attempted exactly once, because neither can change its
    /// answer.
    ///
    /// Retries consume a rate-limiter token like any other request, rather than
    /// slipping around the limiter: a retry storm during a provider outage is
    /// precisely the traffic the limiter exists to cap. If the limiter declines,
    /// the retry is abandoned and the original provider error is returned — the
    /// operator needs to see what actually failed, not a rate-limit error that
    /// only describes our own reaction to it.
    async fn complete_with_retry(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> Result<Completion, ProviderError> {
        let mut attempt: u32 = 0;
        // Owned, because a retry may need to say something the first attempt did
        // not. See `tool_call_correction` below.
        let mut messages: Vec<Message> = messages.to_vec();
        loop {
            let error = match self
                .provider
                .complete(system, &messages, tools, PLANNING_MAX_TOKENS)
                .await
            {
                Ok(completion) => return Ok(completion),
                Err(e) => e,
            };

            if !error.is_retryable() || attempt >= PROVIDER_RETRY_LIMIT {
                return Err(error);
            }

            // Some failures are the model's output being malformed rather than
            // our request being wrong, and for those a plain retry is not a
            // retry at all: the request is byte-identical, so the model
            // reproduces the same malformed answer. Observed live on Groq, three
            // attempts in a row naming a tool called `json` whose arguments were
            // a perfectly good plan — the three `failed_generation` payloads
            // differed only in prose wording. Changing the input is the whole
            // point, so say what went wrong before asking again.
            if let Some(correction) = tool_call_correction(&error, tools) {
                messages.push(Message::user_text(correction));
            }

            if let Some(ref rl) = self.rate_limiter {
                if std::sync::Arc::clone(rl)
                    .check_and_consume_async()
                    .await
                    .is_err()
                {
                    return Err(error);
                }
            }

            // Exponential, and longer when the provider has explicitly asked us
            // to slow down: retrying a 429 on the same schedule as a 502 is how a
            // rate limit becomes a rate-limit loop.
            let base = if matches!(
                error,
                ProviderError::RateLimit(_) | ProviderError::Http { status: 429, .. }
            ) {
                PROVIDER_RETRY_RATE_LIMIT_BACKOFF
            } else {
                PROVIDER_RETRY_BACKOFF
            };
            let backoff = base * 2_u32.pow(attempt);
            eprintln!(
                "[sysknife-brain] provider call failed ({error}); \
                 retrying in {:.1}s (attempt {}/{})",
                backoff.as_secs_f32(),
                attempt + 1,
                PROVIDER_RETRY_LIMIT,
            );
            tokio::time::sleep(backoff).await;
            attempt += 1;
        }
    }

    /// Run the planning loop for the given natural-language intent.
    ///
    /// Returns `Err(EmptyIntent)` immediately if the intent is blank.
    /// Returns `Err(PlannerStuck)` if `max_turns` elapse without a plan.
    /// Returns `Err(NoPlanProposed)` if the LLM ends the turn without a plan.
    pub async fn plan_intent(&self, intent: &str) -> Result<Plan, PlanningError> {
        let intent = intent.trim();
        if intent.is_empty() {
            return Err(PlanningError::EmptyIntent);
        }
        self.admit_request(intent).await?;

        let mut messages: Vec<Message> = vec![Message::user_text(intent)];

        // Rebuild the system prompt with current preferences and distro hint
        // on each call so that preferences saved during a prior `plan_intent`
        // are visible, and the distro routing section reflects the hint.
        let effective_prompt = {
            let prefs_content = match self.prefs_path.clone() {
                Some(p) => match crate::prefs::read_prefs_async(p.clone()).await {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!(
                            "[sysknife-brain] failed to read preferences from {}: {e}",
                            p.display()
                        );
                        None
                    }
                },
                None => None,
            };
            build_system_prompt(prefs_content.as_deref(), self.distro_hint.as_ref())
        };
        // Same lifetime as the prompt: one build per plan, reused across turns.
        let tools = self.tool_defs();

        for turn in 0..self.max_turns {
            self.emit(PlanEvent::Thinking);
            let completion = self
                .complete_with_retry(&effective_prompt, &messages, &tools)
                .await
                .map_err(PlanningError::from)?;

            messages.push(Message {
                role: Role::Assistant,
                content: completion.content.clone(),
            });

            match completion.stop_reason {
                StopReason::MaxTokens => {
                    return Err(PlanningError::NoPlanProposed);
                }
                StopReason::EndTurn => {
                    // Some providers (e.g. Gemini via rig) may output the plan
                    // as a plain-text JSON block instead of calling propose_plan.
                    // Inject a correction and let the model retry — but only if
                    // we have turns remaining.
                    let has_text = completion
                        .content
                        .iter()
                        .any(|b| matches!(b, ContentBlock::Text { .. }));
                    if has_text && turn + 1 < self.max_turns {
                        messages.push(Message::user_text(
                            "You must call the `propose_plan` tool. \
                             Do not output JSON or text directly — \
                             your response must be a tool call to `propose_plan`.",
                        ));
                        continue;
                    }
                    if has_text {
                        eprintln!(
                            "[sysknife-brain] LLM returned text instead of propose_plan on \
                             the final turn (turn {}/{max}); discarding output.",
                            turn + 1,
                            max = self.max_turns
                        );
                    }
                    return Err(PlanningError::NoPlanProposed);
                }
                StopReason::ToolUse => {
                    let tool_calls: Vec<_> = completion
                        .content
                        .iter()
                        .filter_map(|b| {
                            if let ContentBlock::ToolUse {
                                id,
                                call_id,
                                name,
                                input,
                            } = b
                            {
                                Some((id.clone(), call_id.clone(), name.clone(), input.clone()))
                            } else {
                                None
                            }
                        })
                        .collect();

                    if tool_calls.is_empty() {
                        return Err(PlanningError::NoPlanProposed);
                    }

                    let mut tool_results: Vec<ToolResultBlock> =
                        Vec::with_capacity(tool_calls.len());

                    for (id, call_id, name, input) in &tool_calls {
                        // Emit a progress event before dispatching each tool.
                        self.emit(match name.as_str() {
                            "propose_plan" => PlanEvent::ProposingPlan,
                            "get_system_state" => PlanEvent::QueryingTool("system state".into()),
                            other => PlanEvent::QueryingTool(other.replace('_', " ")),
                        });

                        match name.as_str() {
                            "get_system_state" => {
                                let state = self.state_client.curated_state()?;
                                // Propagate serialisation errors: feeding `{}` to the LLM
                                // would cause it to plan against phantom data. In practice
                                // CuratedState is always serialisable (only String/Vec<String>
                                // fields), but this guards against future type changes.
                                let state_json = serde_json::to_string(&state).map_err(|e| {
                                    PlanningError::StateUnavailable(format!(
                                        "failed to serialize system state: {e}"
                                    ))
                                })?;
                                tool_results.push(
                                    sanitize_tool_output("get_system_state", &state_json)
                                        .into_tool_result(id.clone(), call_id.clone()),
                                );
                            }
                            "propose_plan" => {
                                // Parse and validate before returning.
                                // If validation fails, log the rejection (safety fence
                                // activations are security-relevant events) and feed the
                                // error back as a tool result so the LLM can self-correct
                                // within the remaining turns. Symmetric with the
                                // unknown-tool retry path below.
                                match parse_proposed_plan(intent, input) {
                                    Ok(plan) => return Ok(plan),
                                    Err(e) => {
                                        let reason = e.to_string();
                                        let raw_plan = input.to_string();
                                        eprintln!(
                                            "[SYSKNIFE SAFETY] propose_plan rejected \
                                             (turn {}/{max}): {reason}. Input: {raw_plan}",
                                            turn + 1,
                                            max = self.max_turns
                                        );
                                        if let Some(audit) = self.audit_log.clone() {
                                            audit
                                                .log_rejection_async(
                                                    intent.to_string(),
                                                    reason.clone(),
                                                    raw_plan.clone(),
                                                )
                                                .await;
                                        }
                                        tool_results.push(ToolResultBlock {
                                            tool_use_id: id.clone(),
                                            call_id: call_id.clone(),
                                            content: format!(
                                                "Plan rejected: {reason}. \
                                                 Correct the plan and call propose_plan again."
                                            ),
                                            is_error: true,
                                        });
                                    }
                                }
                            }
                            "refuse" => {
                                // A terminal state, like a valid propose_plan:
                                // the model has answered, and the answer is no.
                                match crate::planning_tools::refuse::parse_refusal(input) {
                                    Ok(refusal) => {
                                        return Err(PlanningError::Refused {
                                            reason: refusal.reason,
                                            suggestion: refusal.suggestion,
                                        });
                                    }
                                    Err(reason) => {
                                        // A refusal with no reason is the give-up
                                        // case in disguise. Feed it back and let
                                        // the model try again, exactly as a
                                        // malformed propose_plan does — accepting
                                        // it would reopen the hole `refuse` closes.
                                        eprintln!(
                                            "[SYSKNIFE SAFETY] refuse rejected (turn {}/{max}): \
                                             {reason}",
                                            turn + 1,
                                            max = self.max_turns
                                        );
                                        // audit.rs promises a record of ALL fence
                                        // activations. This path printed and did not
                                        // record, so a reviewer treating
                                        // safety-audit.jsonl as complete silently
                                        // missed every reasonless refusal.
                                        if let Some(audit) = self.audit_log.clone() {
                                            audit
                                                .log_rejection_async(
                                                    intent.to_string(),
                                                    reason.clone(),
                                                    input.to_string(),
                                                )
                                                .await;
                                        }
                                        tool_results.push(ToolResultBlock {
                                            tool_use_id: id.clone(),
                                            call_id: call_id.clone(),
                                            content: format!(
                                                "Refusal rejected: {reason}. Either call \
                                                 `refuse` again with a concrete reason, or \
                                                 propose a plan."
                                            ),
                                            is_error: true,
                                        });
                                    }
                                }
                            }
                            "remember" => {
                                let (result_text, err) = match self.prepare_pref_op(input, |fact| {
                                    crate::prefs::contains_sensitive(fact).then(|| {
                                        "Error: preference rejected — it appears to contain \
                                         sensitive data (passwords, tokens, keys). Preferences \
                                         must not store secrets."
                                            .to_string()
                                    })
                                }) {
                                    Ok((fact, prefs_path)) => {
                                        match crate::prefs::append_pref_async(
                                            prefs_path.clone(),
                                            fact.to_string(),
                                        )
                                        .await
                                        {
                                            Ok(()) => (format!("Preference saved: {fact}"), false),
                                            Err(e) => {
                                                eprintln!(
                                                    "[sysknife-brain] failed to save preference to {}: {e}",
                                                    prefs_path.display()
                                                );
                                                (format!("Error saving preference: {e}"), true)
                                            }
                                        }
                                    }
                                    Err(pair) => pair,
                                };
                                tool_results.push(ToolResultBlock {
                                    tool_use_id: id.clone(),
                                    call_id: call_id.clone(),
                                    content: result_text,
                                    is_error: err,
                                });
                            }
                            "forget" => {
                                let (result_text, err) = match self.prepare_pref_op(input, |_| None)
                                {
                                    Ok((fact, prefs_path)) => {
                                        match crate::prefs::remove_pref_async(
                                            prefs_path.clone(),
                                            fact.to_string(),
                                        )
                                        .await
                                        {
                                            Ok(true) => {
                                                (format!("Preference removed: {fact}"), false)
                                            }
                                            Ok(false) => {
                                                (format!("Preference not found: {fact}"), false)
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "[sysknife-brain] failed to remove preference from {}: {e}",
                                                    prefs_path.display()
                                                );
                                                (format!("Error removing preference: {e}"), true)
                                            }
                                        }
                                    }
                                    Err(pair) => pair,
                                };
                                tool_results.push(ToolResultBlock {
                                    tool_use_id: id.clone(),
                                    call_id: call_id.clone(),
                                    content: result_text,
                                    is_error: err,
                                });
                            }
                            // query_current_user is served from the client env —
                            // no daemon round-trip needed.
                            "query_current_user" => {
                                let (content, is_error) = match self.state_client.current_user() {
                                    Ok(u) => (format!("Current user: {u}"), false),
                                    Err(e) => {
                                        (format!("Error: cannot determine current user: {e}"), true)
                                    }
                                };
                                let sanitized =
                                    sanitize_tool_output("query_current_user", &content);
                                tool_results.push(if is_error {
                                    sanitized.into_error_tool_result(id.clone(), call_id.clone())
                                } else {
                                    sanitized.into_tool_result(id.clone(), call_id.clone())
                                });
                            }
                            other_name => {
                                match crate::planning_tools::query_tools::query_tool_to_action(
                                    other_name, input,
                                ) {
                                    Ok(Some((action_name, params))) => {
                                        match self.state_client.query_action(action_name, &params) {
                                            Ok(output) => {
                                                tool_results.push(
                                                    sanitize_tool_output(other_name, &output)
                                                        .into_tool_result(
                                                            id.clone(),
                                                            call_id.clone(),
                                                        ),
                                                );
                                            }
                                            Err(e) => {
                                                // Daemon errors are trusted (they come from us
                                                // and don't include attacker-controlled bytes
                                                // beyond the action name they reflect back), but
                                                // wrap anyway: it's a uniform contract for the
                                                // model and costs nothing.
                                                tool_results.push(
                                                    sanitize_tool_output(
                                                        other_name,
                                                        &format!("Query failed: {e}"),
                                                    )
                                                    .into_error_tool_result(
                                                        id.clone(),
                                                        call_id.clone(),
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                    Err(msg) => {
                                        // Missing required param — give the LLM a clear,
                                        // actionable message so it can retry correctly.
                                        tool_results.push(ToolResultBlock {
                                            tool_use_id: id.clone(),
                                            call_id: call_id.clone(),
                                            content: msg,
                                            is_error: true,
                                        });
                                    }
                                    Ok(None) => {
                                        // An unknown tool call is a protocol violation — log
                                        // it as a safety event and feed the error back so the
                                        // LLM has a chance to recover within the remaining
                                        // turns. The logging half of that sentence was missing:
                                        // this printed to stderr only, so the one fence event
                                        // that says "the model went off-protocol" was the one
                                        // absent from the audit trail.
                                        eprintln!(
                                            "[SYSKNIFE WARNING] LLM called unknown tool \
                                             '{other_name}' (turn {}/{max}); sending error \
                                             feedback.",
                                            turn + 1,
                                            max = self.max_turns
                                        );
                                        if let Some(audit) = self.audit_log.clone() {
                                            audit
                                                .log_rejection_async(
                                                    intent.to_string(),
                                                    format!("unknown tool: {other_name}"),
                                                    input.to_string(),
                                                )
                                                .await;
                                        }
                                        tool_results.push(ToolResultBlock {
                                            tool_use_id: id.clone(),
                                            call_id: call_id.clone(),
                                            content: format!("unknown tool: {other_name}"),
                                            is_error: true,
                                        });
                                    }
                                }
                            }
                        }
                    }

                    messages.push(Message::tool_results(tool_results));
                }
            }
        }

        Err(PlanningError::PlannerStuck)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (module-local helpers only — integration tests live in
// crates/sysknife-brain/tests/planner.rs).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var mutation is process-global; tests that touch it must be
    // serialised to avoid cross-test interference on a multi-threaded
    // test runner.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// A StateClient is required to build a planner but is never consulted by
    /// `from_config`, so the methods stay unreachable on purpose.
    struct UnusedState;

    impl crate::state_client::StateClient for UnusedState {
        fn curated_state(&self) -> Result<crate::state_client::CuratedState, PlanningError> {
            unreachable!("from_config must not query system state")
        }
        fn query_action(
            &self,
            _action: &str,
            _params: &serde_json::Value,
        ) -> Result<String, PlanningError> {
            unreachable!("from_config must not query the daemon")
        }
    }

    /// The limiter is consulted per `plan_intent`, before the provider call, so
    /// leaving it installed under replay throttled a 50-story suite at story 20 on
    /// the strength of requests that were never sent. A replay reaches neither
    /// spend nor provider load.
    #[test]
    fn replay_installs_no_rate_limiter_because_nothing_is_sent() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cassette = dir.path().join("c.json");
        std::fs::write(
            &cassette,
            serde_json::json!({"version": 1, "meta": {}, "entries": {}}).to_string(),
        )
        .unwrap();

        unsafe {
            std::env::set_var(crate::cassette::ENV_CASSETTE, &cassette);
            std::env::set_var(crate::cassette::ENV_CASSETTE_MODE, "replay");
        }
        let replaying = ollama_planner();
        unsafe {
            std::env::remove_var(crate::cassette::ENV_CASSETTE);
            std::env::remove_var(crate::cassette::ENV_CASSETTE_MODE);
        }
        let live = ollama_planner();

        assert!(
            replaying.rate_limiter.is_none(),
            "a replay sends nothing, so there is nothing to rate limit"
        );
        assert!(
            live.rate_limiter.is_some(),
            "a live run must keep its spend guard"
        );
    }

    /// Built twice in the test above; a helper so the env manipulation stays
    /// readable. Ollama needs no credentials, which is what makes it usable here.
    fn ollama_planner() -> LlmPlanner {
        LlmPlanner::from_config(BrainConfig::ollama_defaults(), Box::new(UnusedState))
            .expect("ollama defaults need no credentials")
    }

    #[test]
    fn into_authorized_replaces_every_step_risk() {
        let step = |name: &str, risk| {
            PlanStep::new(
                ActionName::parse(name).unwrap(),
                "s".into(),
                risk,
                serde_json::json!({}),
            )
            .unwrap()
        };
        let plan = Plan::new(
            "i".into(),
            "s".into(),
            "e".into(),
            vec![
                step("GetDiskUsage", PlanRiskLevel::High), // model over-rated
                step("RebootSystem", PlanRiskLevel::Low),  // model under-rated
            ],
        )
        .unwrap();

        // The caller-supplied mapping is authoritative; the LLM value is ignored.
        let authorized = plan.into_authorized(|name| match name {
            "GetDiskUsage" => PlanRiskLevel::Low,
            _ => PlanRiskLevel::High,
        });

        let risks: Vec<PlanRiskLevel> =
            authorized.steps().map(|s| s.risk_level().clone()).collect();
        assert_eq!(risks, vec![PlanRiskLevel::Low, PlanRiskLevel::High]);
        // highest_risk uses PlanRiskLevel: Ord.
        assert_eq!(authorized.highest_risk(), Some(&PlanRiskLevel::High));
    }

    #[test]
    fn resolve_think_auto_detects_qwen3() {
        let _g = ENV_LOCK.lock().unwrap();
        // SAFETY: single-threaded within this test under ENV_LOCK.
        unsafe { std::env::remove_var(SYSKNIFE_OLLAMA_THINK_ENV) };
        assert!(resolve_ollama_think("qwen3:8b"));
        assert!(resolve_ollama_think("Qwen3:30b-a3b"));
        assert!(resolve_ollama_think("qwq:32b"));
        assert!(resolve_ollama_think("deepseek-r1:7b"));
    }

    #[test]
    fn resolve_think_auto_detects_non_thinking_models() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(SYSKNIFE_OLLAMA_THINK_ENV) };
        assert!(!resolve_ollama_think("llama3.2:3b"));
        assert!(!resolve_ollama_think("gemma3:1b"));
        assert!(!resolve_ollama_think("qwen2.5:3b"));
        assert!(!resolve_ollama_think("mistral-small3.2:24b"));
    }

    #[test]
    fn resolve_think_env_override_true_wins_over_non_thinking_model() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(SYSKNIFE_OLLAMA_THINK_ENV, "true") };
        let got = resolve_ollama_think("llama3.2:3b");
        unsafe { std::env::remove_var(SYSKNIFE_OLLAMA_THINK_ENV) };
        assert!(got, "env override should force think=true");
    }

    #[test]
    fn resolve_think_env_override_false_wins_over_thinking_model() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(SYSKNIFE_OLLAMA_THINK_ENV, "false") };
        let got = resolve_ollama_think("qwen3:8b");
        unsafe { std::env::remove_var(SYSKNIFE_OLLAMA_THINK_ENV) };
        assert!(!got, "env override should force think=false");
    }

    #[test]
    fn resolve_think_env_override_case_insensitive() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(SYSKNIFE_OLLAMA_THINK_ENV, "  TRUE  ") };
        let got = resolve_ollama_think("llama3.2:3b");
        unsafe { std::env::remove_var(SYSKNIFE_OLLAMA_THINK_ENV) };
        assert!(got);
    }

    #[test]
    fn resolve_think_unparseable_env_falls_back_to_auto() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(SYSKNIFE_OLLAMA_THINK_ENV, "yes") };
        let qwen = resolve_ollama_think("qwen3:8b");
        let llama = resolve_ollama_think("llama3.2:3b");
        unsafe { std::env::remove_var(SYSKNIFE_OLLAMA_THINK_ENV) };
        assert!(qwen, "unparseable value should NOT disable auto-detection");
        assert!(!llama, "unparseable value should NOT force think on");
    }
}
