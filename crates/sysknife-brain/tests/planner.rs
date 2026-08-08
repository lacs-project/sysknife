//! Integration tests for `LlmPlanner`.
//!
//! All tests use `MockProvider` and `MockStateClient` — no network calls.
//! The `MockProvider` returns a pre-configured sequence of `Completion` values.
//! Async tests use `#[tokio::test]`; synchronous error-message stability tests
//! do not require a runtime.

use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use sysknife_brain::audit::SafetyAuditLog;
use sysknife_brain::planner::{LlmPlanner, PlanningError};
use sysknife_brain::provider::{
    Completion, ContentBlock, LlmProvider, Message, ProviderError, StopReason, ToolDefinition,
};
use sysknife_brain::state_client::{CuratedState, StateClient};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

struct MockProvider {
    turns: Mutex<VecDeque<Result<Completion, ProviderError>>>,
}

impl MockProvider {
    fn new(turns: impl IntoIterator<Item = Result<Completion, ProviderError>>) -> Self {
        Self {
            turns: Mutex::new(turns.into_iter().collect()),
        }
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    async fn complete(
        &self,
        _system: &str,
        _messages: &[Message],
        _tools: &[ToolDefinition],
        _max_tokens: u32,
    ) -> Result<Completion, ProviderError> {
        self.turns
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(ProviderError::Parse("mock provider exhausted".into())))
    }
}

#[derive(Default, Clone)]
struct MockStateClient {
    call_count: Arc<AtomicUsize>,
}

impl StateClient for MockStateClient {
    fn curated_state(&self) -> Result<CuratedState, PlanningError> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        CuratedState::new(
            "silverblue",
            "fedora/41",
            vec!["NetworkManager.service".into()],
            vec!["org.mozilla.firefox".into()],
            vec!["sysknife-dev".into()],
            vec!["vim".into()],
            vec!["dev-box".into()],
            vec!["alice".into()],
        )
        .map_err(PlanningError::StateUnavailable)
    }

    fn query_action(
        &self,
        action_name: &str,
        _params: &serde_json::Value,
    ) -> Result<String, PlanningError> {
        Ok(format!("[mock] {action_name} query result"))
    }
}

struct FailingStateClient {
    reason: String,
}

impl StateClient for FailingStateClient {
    fn curated_state(&self) -> Result<CuratedState, PlanningError> {
        Err(PlanningError::StateUnavailable(self.reason.clone()))
    }

    fn query_action(
        &self,
        _action_name: &str,
        _params: &serde_json::Value,
    ) -> Result<String, PlanningError> {
        Err(PlanningError::StateUnavailable(self.reason.clone()))
    }
}

// ---------------------------------------------------------------------------
// Completion builders
// ---------------------------------------------------------------------------

fn propose_plan(summary: &str, steps: &[(&str, &str, &str)]) -> Result<Completion, ProviderError> {
    let steps_json: Vec<serde_json::Value> = steps
        .iter()
        .map(|(name, step_summary, risk)| {
            serde_json::json!({
                "action_name": name,
                "summary": step_summary,
                "risk_level": risk,
                "params": {}
            })
        })
        .collect();

    Ok(Completion {
        content: vec![ContentBlock::ToolUse {
            id: "tu_001".into(),
            call_id: None,
            name: "propose_plan".into(),
            input: serde_json::json!({
                "summary": summary,
                "explanation": "Test plan explanation.",
                "steps": steps_json
            }),
        }],
        stop_reason: StopReason::ToolUse,
    })
}

fn get_system_state_call() -> Result<Completion, ProviderError> {
    Ok(Completion {
        content: vec![ContentBlock::ToolUse {
            id: "tu_state".into(),
            call_id: None,
            name: "get_system_state".into(),
            input: serde_json::json!({}),
        }],
        stop_reason: StopReason::ToolUse,
    })
}

fn end_turn_text(text: &str) -> Result<Completion, ProviderError> {
    Ok(Completion {
        content: vec![ContentBlock::Text { text: text.into() }],
        stop_reason: StopReason::EndTurn,
    })
}

fn make_planner(provider: MockProvider) -> LlmPlanner {
    LlmPlanner::new(Box::new(provider), Box::new(MockStateClient::default()), 5)
}

fn make_planner_with_state<S: StateClient + 'static>(
    provider: MockProvider,
    state: S,
) -> LlmPlanner {
    LlmPlanner::new(Box::new(provider), Box::new(state), 5)
}

// ---------------------------------------------------------------------------
// Empty / whitespace intent — guarded before any provider call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_intent_returns_error_without_calling_provider() {
    let planner = make_planner(MockProvider::new([]));
    assert_eq!(
        planner.plan_intent("").await.unwrap_err(),
        PlanningError::EmptyIntent
    );
}

#[tokio::test]
async fn whitespace_only_intent_returns_empty_intent_error() {
    let planner = make_planner(MockProvider::new([]));
    assert_eq!(
        planner.plan_intent("   \t\n  ").await.unwrap_err(),
        PlanningError::EmptyIntent
    );
}

// ---------------------------------------------------------------------------
// Intent validation — length cap and secret scan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn intent_exceeding_max_bytes_is_rejected_before_provider_call() {
    use sysknife_brain::planner::INTENT_MAX_BYTES;
    // Construct an intent that is exactly one byte over the limit.
    let long = "a".repeat(INTENT_MAX_BYTES + 1);
    let planner = make_planner(MockProvider::new([])); // no turns — must not be called
    let err = planner.plan_intent(&long).await.unwrap_err();
    assert!(
        matches!(
            err,
            PlanningError::IntentTooLong { len, max }
            if len == INTENT_MAX_BYTES + 1 && max == INTENT_MAX_BYTES
        ),
        "expected IntentTooLong, got: {err:?}"
    );
}

#[tokio::test]
async fn intent_at_max_bytes_is_accepted() {
    use sysknife_brain::planner::INTENT_MAX_BYTES;
    // An intent exactly at the limit must not be rejected by the length check.
    let exact = "a".repeat(INTENT_MAX_BYTES);
    let planner = make_planner(MockProvider::new([propose_plan(
        "disk check",
        &[("GetDiskUsage", "Check disk", "low")],
    )]));
    assert!(planner.plan_intent(&exact).await.is_ok());
}

#[tokio::test]
async fn intent_containing_api_key_prefix_is_rejected() {
    // "sk-" prefix matches OpenAI/Anthropic key pattern.
    let planner = make_planner(MockProvider::new([]));
    let err = planner
        .plan_intent("check disk usage sk-proj-abc123def456")
        .await
        .unwrap_err();
    assert_eq!(
        err,
        PlanningError::IntentContainsSensitiveData,
        "intent containing API key prefix must be rejected"
    );
}

#[tokio::test]
async fn intent_containing_password_keyword_is_rejected() {
    let planner = make_planner(MockProvider::new([]));
    let err = planner
        .plan_intent("my password is hunter2 please remember it")
        .await
        .unwrap_err();
    assert_eq!(
        err,
        PlanningError::IntentContainsSensitiveData,
        "intent containing 'password' must be rejected"
    );
}

#[tokio::test]
async fn intent_without_sensitive_data_is_not_rejected() {
    // Regression guard: a normal intent must not be falsely blocked.
    let planner = make_planner(MockProvider::new([propose_plan(
        "disk check",
        &[("GetDiskUsage", "Check disk", "low")],
    )]));
    assert!(planner
        .plan_intent("check how much disk space is left")
        .await
        .is_ok());
}

// ---------------------------------------------------------------------------
// Single-turn: propose_plan returned immediately
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_turn_propose_plan_returns_plan() {
    let planner = make_planner(MockProvider::new([propose_plan(
        "Inspect system state",
        &[("GetSystemState", "Read current deployment info", "low")],
    )]));

    let plan = planner.plan_intent("show me the system").await.unwrap();

    assert_eq!(plan.intent(), "show me the system");
    assert_eq!(plan.steps().len(), 1);
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");
    assert!(!plan.steps()[0].approval_required());
    assert_eq!(plan.steps()[0].proposed_risk_level().as_str(), "low");
}

#[tokio::test]
async fn plan_carries_summary_and_explanation() {
    let planner = make_planner(MockProvider::new([propose_plan(
        "Read-only inspection",
        &[("GetSystemState", "Read state", "low")],
    )]));

    let plan = planner.plan_intent("inspect").await.unwrap();

    assert_eq!(plan.summary(), "Read-only inspection");
    assert_eq!(plan.explanation(), "Test plan explanation.");
}

// ---------------------------------------------------------------------------
// Two-turn: get_system_state first, then propose_plan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_turn_state_then_plan_works() {
    let client = MockStateClient::default();
    let call_count = client.call_count.clone();

    let planner = make_planner_with_state(
        MockProvider::new([
            get_system_state_call(),
            propose_plan(
                "Install Firefox",
                &[("InstallFlatpak", "Install Firefox from Flathub", "medium")],
            ),
        ]),
        client,
    );

    let plan = planner.plan_intent("install firefox").await.unwrap();

    assert_eq!(plan.steps()[0].action_name(), "InstallFlatpak");
    assert!(plan.steps()[0].approval_required());
    assert_eq!(call_count.load(Ordering::Relaxed), 1);
}

// ---------------------------------------------------------------------------
// Risk level → approval_required derivation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn low_risk_step_has_no_approval_required() {
    let planner = make_planner(MockProvider::new([propose_plan(
        "Read only",
        &[("ListServices", "List all services", "low")],
    )]));
    let plan = planner.plan_intent("list services").await.unwrap();
    assert!(!plan.steps()[0].approval_required());
}

#[tokio::test]
async fn medium_risk_step_requires_approval() {
    let planner = make_planner(MockProvider::new([propose_plan(
        "Configure wifi",
        &[("ConfigureWifi", "Connect to home wifi", "medium")],
    )]));
    let plan = planner.plan_intent("connect to wifi").await.unwrap();
    assert!(plan.steps()[0].approval_required());
}

#[tokio::test]
async fn high_risk_step_requires_approval() {
    let planner = make_planner(MockProvider::new([propose_plan(
        "Rebase system",
        &[("RebaseSystem", "Rebase to Fedora 42", "high")],
    )]));
    let plan = planner.plan_intent("rebase to fedora 42").await.unwrap();
    assert!(plan.steps()[0].approval_required());
}

// ---------------------------------------------------------------------------
// Multi-step plan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_step_plan_preserves_order_and_approval_flags() {
    let planner = make_planner(MockProvider::new([propose_plan(
        "Layer vim and reboot",
        &[
            ("GetSystemState", "Check current state", "low"),
            ("InstallPackages", "Layer vim package", "high"),
            ("RebootSystem", "Reboot into new deployment", "high"),
        ],
    )]));

    let plan = planner.plan_intent("layer vim and reboot").await.unwrap();

    assert_eq!(plan.steps().len(), 3);
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");
    assert!(!plan.steps()[0].approval_required());
    assert_eq!(plan.steps()[1].action_name(), "InstallPackages");
    assert!(plan.steps()[1].approval_required());
    assert_eq!(plan.steps()[2].action_name(), "RebootSystem");
    assert!(plan.steps()[2].approval_required());
}

// ---------------------------------------------------------------------------
// params passthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plan_step_carries_params() {
    let planner = make_planner(MockProvider::new([Ok(Completion {
        content: vec![ContentBlock::ToolUse {
            id: "tu_p".into(),
            call_id: None,
            name: "propose_plan".into(),
            input: serde_json::json!({
                "summary": "Install vim",
                "explanation": "Layers vim.",
                "steps": [{
                    "action_name": "InstallPackages",
                    "summary": "Layer vim",
                    "risk_level": "high",
                    "params": { "packages": ["vim"] }
                }]
            }),
        }],
        stop_reason: StopReason::ToolUse,
    })]));

    let plan = planner.plan_intent("install vim").await.unwrap();
    let params = plan.steps()[0].params();
    assert_eq!(params["packages"][0], "vim");
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

/// A *persistent* 500 still propagates as a 500. 5xx is retryable, so one
/// scripted error would be followed by MockProvider's exhaustion fallback and
/// this would assert the fixture's variant instead of the failure's.
#[tokio::test(start_paused = true)]
async fn provider_error_propagates() {
    let http_500 = || {
        Err(ProviderError::Http {
            status: 500,
            body: "internal server error".into(),
        })
    };
    let planner = make_planner(MockProvider::new([http_500(), http_500(), http_500()]));

    assert!(matches!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::Provider(ProviderError::Http { status: 500, .. })
    ));
}

#[tokio::test]
async fn auth_error_propagates() {
    let planner = make_planner(MockProvider::new([Err(ProviderError::Auth(
        "invalid api key".into(),
    ))]));
    assert!(matches!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::Provider(ProviderError::Auth(_))
    ));
}

#[tokio::test]
async fn end_turn_correction_succeeds_on_retry() {
    // Turn 1: LLM outputs prose (EndTurn + text) instead of calling propose_plan.
    //         The planner injects a correction message.
    // Turn 2: LLM calls propose_plan correctly → plan is returned.
    let planner = make_planner(MockProvider::new([
        end_turn_text("Here is the plan in JSON: {...}"),
        propose_plan(
            "Inspect system",
            &[("GetSystemState", "Read current deployment", "low")],
        ),
    ]));
    let plan = planner.plan_intent("show me the system").await.unwrap();
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");
    assert_eq!(plan.intent(), "show me the system");
}

#[tokio::test]
async fn end_turn_without_plan_returns_no_plan_proposed() {
    // Turn 1: LLM outputs prose instead of calling propose_plan → planner sends
    //         a correction message and retries.
    // Turn 2: LLM still returns EndTurn but with no text content → NoPlanProposed.
    let planner = make_planner(MockProvider::new([
        end_turn_text("I cannot help with that."),
        Ok(Completion {
            content: vec![],
            stop_reason: StopReason::EndTurn,
        }),
    ]));
    assert_eq!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::NoPlanProposed
    );
}

#[tokio::test]
async fn planner_stuck_after_max_turns() {
    // Provider returns get_system_state on every turn — never proposes a plan.
    let turns: Vec<_> = (0..6).map(|_| get_system_state_call()).collect();
    let planner = make_planner(MockProvider::new(turns));
    assert_eq!(
        planner.plan_intent("loop forever").await.unwrap_err(),
        PlanningError::PlannerStuck
    );
}

#[tokio::test]
async fn state_client_error_propagates() {
    let planner = make_planner_with_state(
        MockProvider::new([get_system_state_call()]),
        FailingStateClient {
            reason: "socket closed".into(),
        },
    );
    assert_eq!(
        planner.plan_intent("check state").await.unwrap_err(),
        PlanningError::StateUnavailable("socket closed".into())
    );
}

#[tokio::test]
async fn invalid_plan_with_single_turn_returns_planner_stuck() {
    // With max_turns=1, a rejected propose_plan exhausts the only available turn.
    // The planner feeds the rejection back as a tool-result error but has no more
    // turns to retry, so it returns PlannerStuck. This verifies that the KNOWN_ACTIONS
    // fence correctly rejects unknown action names.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([Ok(Completion {
            content: vec![ContentBlock::ToolUse {
                id: "tu_bad".into(),
                call_id: None,
                name: "propose_plan".into(),
                input: serde_json::json!({
                    "summary": "bad plan",
                    "explanation": "using a fake action",
                    "steps": [{
                        "action_name": "RunShellCommand",
                        "summary": "run arbitrary shell",
                        "risk_level": "low",
                        "params": {}
                    }]
                }),
            }],
            stop_reason: StopReason::ToolUse,
        })])),
        Box::new(MockStateClient::default()),
        1,
    );

    assert_eq!(
        planner.plan_intent("run a command").await.unwrap_err(),
        PlanningError::PlannerStuck
    );
}

#[tokio::test]
async fn invalid_proposed_plan_is_retried_and_succeeds_on_second_call() {
    // Turn 1: LLM proposes a plan with an unknown action → safety fence rejects,
    //         error feedback is sent back as a tool result.
    // Turn 2: LLM corrects the plan with a valid action → accepted.
    // This verifies symmetry with the unknown-tool retry path.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_bad".into(),
                    call_id: None,
                    name: "propose_plan".into(),
                    input: serde_json::json!({
                        "summary": "bad plan",
                        "explanation": "using a fake action",
                        "steps": [{
                            "action_name": "RunShellCommand",
                            "summary": "run arbitrary shell",
                            "risk_level": "low",
                            "params": {}
                        }]
                    }),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Inspect system",
                &[("GetSystemState", "Read current deployment", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        3,
    );

    let plan = planner.plan_intent("inspect the system").await.unwrap();
    assert_eq!(plan.steps().len(), 1);
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");
    assert_eq!(plan.intent(), "inspect the system");
}

#[tokio::test]
async fn empty_steps_array_with_single_turn_returns_planner_stuck() {
    // A plan with zero steps is rejected by the safety fence and the error
    // is fed back as a tool result. With max_turns=1, no retry is possible.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([Ok(Completion {
            content: vec![ContentBlock::ToolUse {
                id: "tu_empty".into(),
                call_id: None,
                name: "propose_plan".into(),
                input: serde_json::json!({
                    "summary": "nothing to do",
                    "explanation": "no steps",
                    "steps": []
                }),
            }],
            stop_reason: StopReason::ToolUse,
        })])),
        Box::new(MockStateClient::default()),
        1,
    );

    assert_eq!(
        planner.plan_intent("do nothing").await.unwrap_err(),
        PlanningError::PlannerStuck
    );
}

// ---------------------------------------------------------------------------
// ToolUse stop reason with no actual tool-call blocks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tool_use_stop_reason_with_no_tool_blocks_returns_no_plan_proposed() {
    // A provider can return stop_reason=ToolUse but only include a Text block
    // (no ToolUse block). The planner must detect the empty tool_calls list
    // and return NoPlanProposed rather than looping indefinitely.
    let planner = make_planner(MockProvider::new([Ok(Completion {
        content: vec![ContentBlock::Text {
            text: "I was thinking out loud but forgot to call a tool".into(),
        }],
        stop_reason: StopReason::ToolUse,
    })]));
    assert_eq!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::NoPlanProposed
    );
}

// ---------------------------------------------------------------------------
// MaxTokens stop reason
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_tokens_stop_reason_returns_no_plan_proposed() {
    let planner = make_planner(MockProvider::new([Ok(Completion {
        content: vec![ContentBlock::Text {
            text: "I was about to say something useful but ran out of tokens...".into(),
        }],
        stop_reason: StopReason::MaxTokens,
    })]));
    assert_eq!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::NoPlanProposed
    );
}

// ---------------------------------------------------------------------------
// Unknown tool call — continues loop and eventually returns PlannerStuck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_tool_call_continues_loop_and_eventually_sticks() {
    // Provider always calls an unknown tool; the loop feeds back an error result
    // on every turn until max_turns is exhausted.
    let unknown_tool_call = || {
        Ok(Completion {
            content: vec![ContentBlock::ToolUse {
                id: "tu_x".into(),
                call_id: None,
                name: "fly_to_the_moon".into(),
                input: serde_json::json!({}),
            }],
            stop_reason: StopReason::ToolUse,
        })
    };
    let turns: Vec<_> = (0..6).map(|_| unknown_tool_call()).collect();
    let planner = make_planner(MockProvider::new(turns));
    assert_eq!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::PlannerStuck
    );
}

// ---------------------------------------------------------------------------
// max_turns = 1 with a state call on the first turn → PlannerStuck
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_turns_one_with_state_call_returns_planner_stuck() {
    // With max_turns=1, the single turn is consumed by get_system_state;
    // there is no turn left for propose_plan.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([get_system_state_call()])),
        Box::new(MockStateClient::default()),
        1,
    );
    assert_eq!(
        planner.plan_intent("show state").await.unwrap_err(),
        PlanningError::PlannerStuck
    );
}

// ---------------------------------------------------------------------------
// Safety audit log — structured persistent logging of fence activations
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejected_plan_is_written_to_safety_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("safety-audit.jsonl");
    let audit_log = SafetyAuditLog::new(&log_path);

    // LLM proposes a plan with an unknown action on turn 1 (rejected),
    // then corrects it on turn 2 (accepted). The rejection should be logged.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_bad".into(),
                    call_id: None,
                    name: "propose_plan".into(),
                    input: serde_json::json!({
                        "summary": "bad plan",
                        "explanation": "using a fake action",
                        "steps": [{
                            "action_name": "RunShellCommand",
                            "summary": "run arbitrary shell",
                            "risk_level": "low",
                            "params": {}
                        }]
                    }),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Inspect system",
                &[("GetSystemState", "Read current deployment", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        3,
    )
    .with_audit_log(audit_log);

    let plan = planner.plan_intent("inspect the system").await.unwrap();
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");

    // Verify the audit log file was written.
    let content = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected one rejection logged, got: {content}"
    );

    let entry: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(entry["event"], "safety_fence_rejection");
    assert_eq!(entry["intent"], "inspect the system");
    assert!(
        entry["reason"]
            .as_str()
            .unwrap()
            .contains("unknown action_name"),
        "reason should mention the unknown action: {}",
        entry["reason"]
    );
    assert!(
        entry["raw_plan"]
            .as_str()
            .unwrap()
            .contains("RunShellCommand"),
        "raw_plan should contain the offending input: {}",
        entry["raw_plan"]
    );
}

#[tokio::test]
async fn planner_without_audit_log_does_not_panic_on_rejection() {
    // Verify that the planner works correctly even without an audit log.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_bad".into(),
                    call_id: None,
                    name: "propose_plan".into(),
                    input: serde_json::json!({
                        "summary": "bad plan",
                        "explanation": "using a fake action",
                        "steps": [{
                            "action_name": "RunShellCommand",
                            "summary": "run stuff",
                            "risk_level": "low",
                            "params": {}
                        }]
                    }),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Inspect system",
                &[("GetSystemState", "Read deployment", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        3,
    );

    // No audit log attached, should still work.
    let plan = planner.plan_intent("inspect").await.unwrap();
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");
}

// ---------------------------------------------------------------------------
// Error message stability — pin human-readable strings
// ---------------------------------------------------------------------------

#[test]
fn planning_error_messages_are_stable() {
    assert_eq!(
        PlanningError::EmptyIntent.to_string(),
        "intent must not be empty"
    );
    assert_eq!(
        PlanningError::StateUnavailable("disk timeout".into()).to_string(),
        "state unavailable: disk timeout"
    );
    assert_eq!(
        PlanningError::PlannerStuck.to_string(),
        "planner did not propose a plan within the allowed turns"
    );
    assert_eq!(
        PlanningError::NoPlanProposed.to_string(),
        "planner ended without proposing a plan"
    );
}

// ---------------------------------------------------------------------------
// remember / forget tool calls
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remember_tool_saves_preference_and_planner_continues() {
    let dir = tempfile::tempdir().unwrap();
    let prefs_path = dir.path().join("prefs.md");

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_rem".into(),
                    call_id: None,
                    name: "remember".into(),
                    input: serde_json::json!({"fact": "prefer vim-enhanced over vim"}),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Confirm preference saved",
                &[("GetSystemState", "Confirm system is accessible", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_prefs_path(prefs_path.clone());

    let plan = planner
        .plan_intent("remember that I prefer vim-enhanced over vim")
        .await
        .unwrap();
    assert_eq!(plan.steps()[0].action_name(), "GetSystemState");

    // Verify the preference was written.
    let content = std::fs::read_to_string(&prefs_path).unwrap();
    assert!(content.contains("prefer vim-enhanced over vim"));
}

#[tokio::test]
async fn forget_tool_removes_preference() {
    let dir = tempfile::tempdir().unwrap();
    let prefs_path = dir.path().join("prefs.md");
    // Pre-seed a preference.
    std::fs::write(&prefs_path, "- prefer vim-enhanced over vim\n").unwrap();

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_fgt".into(),
                    call_id: None,
                    name: "forget".into(),
                    input: serde_json::json!({"fact": "prefer vim-enhanced over vim"}),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Preference removed",
                &[("GetSystemState", "Confirm system", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_prefs_path(prefs_path.clone());

    planner
        .plan_intent("forget my vim preference")
        .await
        .unwrap();

    let content = std::fs::read_to_string(&prefs_path).unwrap();
    assert!(!content.contains("vim-enhanced"));
}

#[tokio::test]
async fn remember_rejects_sensitive_data() {
    let dir = tempfile::tempdir().unwrap();
    let prefs_path = dir.path().join("prefs.md");

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_rem".into(),
                    call_id: None,
                    name: "remember".into(),
                    input: serde_json::json!({"fact": "my password is hunter2"}),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Cannot save sensitive data",
                &[("GetSystemState", "System check", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_prefs_path(prefs_path.clone());

    // Intent itself is benign — the sensitive data is inside the LLM's
    // remember tool call, which is what the prefs-layer rejection tests.
    planner.plan_intent("update my preferences").await.unwrap();

    // File should not exist or should be empty — the sensitive fact was rejected
    // by append_pref() before it could be written to disk.
    assert!(!prefs_path.exists() || std::fs::read_to_string(&prefs_path).unwrap().is_empty());
}

#[tokio::test]
async fn remember_without_prefs_path_returns_not_configured_error() {
    // When no prefs_path is set the planner must report "not configured"
    // with is_error=true so the LLM knows storage is unavailable.
    let provider = Box::new(MockProvider::new([
        Ok(Completion {
            content: vec![ContentBlock::ToolUse {
                id: "tu_rem2".into(),
                call_id: None,
                name: "remember".into(),
                input: serde_json::json!({"fact": "prefer dark theme"}),
            }],
            stop_reason: StopReason::ToolUse,
        }),
        propose_plan(
            "Storage not configured",
            &[("GetSystemState", "fallback", "low")],
        ),
    ]));

    // Intentionally omit `.with_prefs_path(...)`.
    let planner = LlmPlanner::new(provider, Box::new(MockStateClient::default()), 5);

    // Planning should still succeed — the error is returned to the LLM as a
    // tool result, not propagated as a Rust error.
    let plan = planner
        .plan_intent("remember that I prefer dark theme")
        .await
        .unwrap();
    let _ = plan; // LLM saw the error and still produced a plan
}

#[tokio::test]
async fn forget_without_prefs_path_returns_not_configured_error() {
    // Same as above but for the `forget` path.
    let provider = Box::new(MockProvider::new([
        Ok(Completion {
            content: vec![ContentBlock::ToolUse {
                id: "tu_fgt2".into(),
                call_id: None,
                name: "forget".into(),
                input: serde_json::json!({"fact": "prefer dark theme"}),
            }],
            stop_reason: StopReason::ToolUse,
        }),
        propose_plan(
            "Storage not configured",
            &[("GetSystemState", "fallback", "low")],
        ),
    ]));

    // Intentionally omit `.with_prefs_path(...)`.
    let planner = LlmPlanner::new(provider, Box::new(MockStateClient::default()), 5);

    let plan = planner
        .plan_intent("forget my dark theme preference")
        .await
        .unwrap();
    let _ = plan;
}

#[tokio::test]
async fn forget_returns_not_found_when_preference_absent() {
    // `remove_pref` returns Ok(false) when the fact isn't in the file.
    // The planner must return "Preference not found: X" with is_error=false
    // (the LLM should know, but it is not a hard error).
    let dir = tempfile::tempdir().unwrap();
    let prefs_path = dir.path().join("prefs.md");
    // File exists but does not contain the target fact.
    std::fs::write(&prefs_path, "- prefer dark theme\n").unwrap();

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_fgt3".into(),
                    call_id: None,
                    name: "forget".into(),
                    input: serde_json::json!({"fact": "prefer vim-enhanced over vim"}),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Nothing to forget",
                &[("GetSystemState", "fallback", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_prefs_path(prefs_path.clone());

    // Should succeed — "Preference not found" is informational, not an error.
    planner
        .plan_intent("forget my vim preference")
        .await
        .unwrap();

    // The file must be unchanged.
    let content = std::fs::read_to_string(&prefs_path).unwrap();
    assert!(
        content.contains("prefer dark theme"),
        "unrelated preference must still be present"
    );
}

#[tokio::test]
async fn remember_io_error_is_reported_to_llm() {
    // If `append_pref` fails (e.g. read-only directory) the planner must
    // return an error tool result so the LLM knows the write failed.
    // We simulate I/O failure by pointing prefs_path at a directory.
    let dir = tempfile::tempdir().unwrap();
    let prefs_path = dir.path().join("is_a_dir");
    std::fs::create_dir_all(&prefs_path).unwrap(); // path is a directory, not a file

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            Ok(Completion {
                content: vec![ContentBlock::ToolUse {
                    id: "tu_rem3".into(),
                    call_id: None,
                    name: "remember".into(),
                    input: serde_json::json!({"fact": "prefer dark theme"}),
                }],
                stop_reason: StopReason::ToolUse,
            }),
            propose_plan(
                "Preference save failed",
                &[("GetSystemState", "fallback", "low")],
            ),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_prefs_path(prefs_path);

    // Planning must still succeed — the I/O error is returned to the LLM,
    // not propagated as a Rust error.
    planner
        .plan_intent("remember that I prefer dark theme")
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limiter_allows_requests_within_limit() {
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    let rl = RateLimiter::new(dir.path().join("rate.log"), 3);

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            propose_plan("p1", &[("GetDiskUsage", "disk", "low")]),
            propose_plan("p2", &[("GetDiskUsage", "disk", "low")]),
            propose_plan("p3", &[("GetDiskUsage", "disk", "low")]),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_rate_limiter(rl);

    planner.plan_intent("check disk 1").await.unwrap();
    planner.plan_intent("check disk 2").await.unwrap();
    planner.plan_intent("check disk 3").await.unwrap();
}

#[tokio::test]
async fn rate_limiter_blocks_after_limit_exceeded() {
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    let rl = RateLimiter::new(dir.path().join("rate.log"), 2);

    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            propose_plan("p1", &[("GetDiskUsage", "disk", "low")]),
            propose_plan("p2", &[("GetDiskUsage", "disk", "low")]),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_rate_limiter(rl);

    planner.plan_intent("check disk 1").await.unwrap();
    planner.plan_intent("check disk 2").await.unwrap();

    let err = planner.plan_intent("check disk 3").await.unwrap_err();
    assert!(
        matches!(err, PlanningError::RateLimitExceeded { retry_after_secs } if retry_after_secs > 0),
        "expected RateLimitExceeded with retry_after > 0, got: {err:?}"
    );
}

#[tokio::test]
async fn planner_without_rate_limiter_is_unlimited() {
    // No rate limiter attached — many calls must all succeed.
    let planner = make_planner(MockProvider::new([
        propose_plan("p1", &[("GetDiskUsage", "disk", "low")]),
        propose_plan("p2", &[("GetDiskUsage", "disk", "low")]),
    ]));
    planner.plan_intent("check disk 1").await.unwrap();
    planner.plan_intent("check disk 2").await.unwrap();
}

// ---------------------------------------------------------------------------
// summarize() — same guards as plan_intent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn summarize_rejects_oversized_prompt() {
    use sysknife_brain::planner::INTENT_MAX_BYTES;
    let long = "a".repeat(INTENT_MAX_BYTES + 1);
    let planner = make_planner(MockProvider::new([]));
    let err = planner.summarize(&long).await.unwrap_err();
    assert!(
        matches!(
            err,
            PlanningError::IntentTooLong { len, max }
            if len == INTENT_MAX_BYTES + 1 && max == INTENT_MAX_BYTES
        ),
        "expected IntentTooLong, got: {err:?}"
    );
}

#[tokio::test]
async fn summarize_rejects_prompt_with_secret() {
    let planner = make_planner(MockProvider::new([]));
    let err = planner
        .summarize("execution output: token=ghp_abc123secrettoken")
        .await
        .unwrap_err();
    assert_eq!(
        err,
        PlanningError::IntentContainsSensitiveData,
        "summarize must reject prompts containing secret patterns"
    );
}

#[tokio::test]
async fn summarize_accepts_normal_output() {
    let planner = make_planner(MockProvider::new([Ok(
        sysknife_brain::provider::Completion {
            content: vec![sysknife_brain::provider::ContentBlock::Text {
                text: "System updated successfully.".into(),
            }],
            stop_reason: sysknife_brain::provider::StopReason::EndTurn,
        },
    )]));
    let result = planner
        .summarize("rpm-ostree status: idle\nDeployment: fedora/41/x86_64/silverblue")
        .await;
    assert!(result.is_ok(), "normal summarize must succeed: {result:?}");
}

#[tokio::test]
async fn summarize_at_max_bytes_is_accepted() {
    use sysknife_brain::planner::INTENT_MAX_BYTES;
    let exact = "a".repeat(INTENT_MAX_BYTES);
    let planner = make_planner(MockProvider::new([Ok(
        sysknife_brain::provider::Completion {
            content: vec![sysknife_brain::provider::ContentBlock::Text { text: "ok".into() }],
            stop_reason: sysknife_brain::provider::StopReason::EndTurn,
        },
    )]));
    assert!(
        planner.summarize(&exact).await.is_ok(),
        "summarize at exact INTENT_MAX_BYTES must not be rejected"
    );
}

#[tokio::test]
async fn summarize_does_not_reject_benign_output_with_common_words() {
    // Regression guard: execution output containing "key" or "token" in a
    // non-secret context must not be falsely blocked.
    let planner = make_planner(MockProvider::new([Ok(
        sysknife_brain::provider::Completion {
            content: vec![sysknife_brain::provider::ContentBlock::Text {
                text: "SSH key fingerprint verified.".into(),
            }],
            stop_reason: sysknife_brain::provider::StopReason::EndTurn,
        },
    )]));
    let result = planner
        .summarize("authorized_keys updated, fingerprint: SHA256:abc")
        .await;
    assert!(
        result.is_ok(),
        "summarize must not reject benign output mentioning keys: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Rate limiter through summarize()
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limiter_blocks_summarize_after_limit_exceeded() {
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    // Shared rate file: both plan_intent and summarize consume the same window.
    let rl = RateLimiter::new(dir.path().join("rate.log"), 1);
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            // First call to summarize succeeds.
            Ok(sysknife_brain::provider::Completion {
                content: vec![sysknife_brain::provider::ContentBlock::Text {
                    text: "done".into(),
                }],
                stop_reason: sysknife_brain::provider::StopReason::EndTurn,
            }),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_rate_limiter(rl);

    planner.summarize("first call").await.unwrap();
    let err = planner.summarize("second call").await.unwrap_err();
    assert!(
        matches!(err, PlanningError::RateLimitExceeded { retry_after_secs } if retry_after_secs > 0 && retry_after_secs <= 60),
        "expected RateLimitExceeded (1..=60s), got: {err:?}"
    );
}

#[tokio::test]
async fn rate_limiter_blocks_after_limit_exceeded_retry_after_bounded() {
    // Tighter assertion: retry_after_secs must be in [1, 60].
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    let rl = RateLimiter::new(dir.path().join("rate.log"), 2);
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([
            propose_plan("p1", &[("GetDiskUsage", "disk", "low")]),
            propose_plan("p2", &[("GetDiskUsage", "disk", "low")]),
        ])),
        Box::new(MockStateClient::default()),
        5,
    )
    .with_rate_limiter(rl);

    planner.plan_intent("check disk 1").await.unwrap();
    planner.plan_intent("check disk 2").await.unwrap();
    let err = planner.plan_intent("check disk 3").await.unwrap_err();
    assert!(
        matches!(err, PlanningError::RateLimitExceeded { retry_after_secs } if (1..=60).contains(&retry_after_secs)),
        "retry_after_secs must be in [1, 60], got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// RateLimiter isolation unit tests
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_new_with_zero_panics() {
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    let result = std::panic::catch_unwind(|| {
        RateLimiter::new(dir.path().join("rate.log"), 0);
    });
    assert!(result.is_err(), "RateLimiter::new(path, 0) must panic");
}

#[test]
fn rate_limiter_file_persistence_across_instances() {
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rate.log");
    let limit = 2;

    // First instance consumes 1 slot.
    let rl1 = RateLimiter::new(path.clone(), limit);
    assert!(rl1.check_and_consume().is_ok());
    drop(rl1);

    // Second instance reads the file written by rl1 — sees 1 existing slot used.
    let rl2 = RateLimiter::new(path.clone(), limit);
    assert!(rl2.check_and_consume().is_ok()); // second slot used
    drop(rl2);

    // Third instance: window still has 2 calls (both within the last second).
    let rl3 = RateLimiter::new(path.clone(), limit);
    let err = rl3.check_and_consume().unwrap_err();
    assert!(
        (1..=60).contains(&err),
        "retry_after must be 1..=60, got {err}"
    );
}

#[test]
fn rate_limiter_io_fail_open_on_unreadable_parent() {
    use sysknife_brain::rate_limit::RateLimiter;
    // Point the rate limiter at a path with a non-existent parent
    // that tempdir doesn't own — should fail open (allow the call).
    let rl = RateLimiter::new(std::path::PathBuf::from("/nonexistent/dir/rate.log"), 5);
    // Must return Ok (fail-open), not panic.
    assert!(
        rl.check_and_consume().is_ok(),
        "rate limiter must fail open on unreadable path"
    );
}

#[test]
fn rate_limiter_file_is_compacted_after_calls() {
    use sysknife_brain::rate_limit::RateLimiter;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rate.log");
    let rl = RateLimiter::new(path.clone(), 10);

    // Make 3 calls.
    for _ in 0..3 {
        assert!(rl.check_and_consume().is_ok());
    }

    // File should have exactly 3 lines (no expired entries accumulated).
    let content = std::fs::read_to_string(&path).unwrap();
    let line_count = content.lines().count();
    assert_eq!(
        line_count, 3,
        "file should have 3 timestamp lines, got {line_count}"
    );
}

// ---------------------------------------------------------------------------
// DistroHint — prompt injection tests
// ---------------------------------------------------------------------------
//
// These tests verify that `LlmPlanner::with_distro` causes the system prompt
// to contain the correct distro-specific action family section and excludes the
// wrong one.  They do NOT call an LLM — they exercise `build_system_prompt`
// via a `MockProvider` that captures the `system` argument on the first call.

use std::sync::Mutex as StdMutex;
use sysknife_types::{DistroHint, DISTRO_FAMILY_DEBIAN, DISTRO_FAMILY_FEDORA};

/// A provider that captures the `system` string passed to its first `complete`
/// call so tests can inspect what the planner injected into the prompt.
struct CapturingProvider {
    captured_system: Arc<StdMutex<Option<String>>>,
    inner: MockProvider,
}

impl CapturingProvider {
    fn new(inner: MockProvider) -> (Self, Arc<StdMutex<Option<String>>>) {
        let captured = Arc::new(StdMutex::new(None));
        let provider = Self {
            captured_system: Arc::clone(&captured),
            inner,
        };
        (provider, captured)
    }
}

#[async_trait]
impl LlmProvider for CapturingProvider {
    async fn complete(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<Completion, ProviderError> {
        // Drop the lock guard before the await to keep the future Send.
        {
            let mut guard = self.captured_system.lock().unwrap();
            if guard.is_none() {
                *guard = Some(system.to_string());
            }
        }
        self.inner
            .complete(system, messages, tools, max_tokens)
            .await
    }
}

// Helper: build a planner that uses a CapturingProvider and returns the
// captured system string after plan_intent completes.
async fn run_and_capture_system(
    hint: Option<DistroHint>,
    provider_turns: impl IntoIterator<Item = Result<Completion, ProviderError>>,
) -> String {
    let mock = MockProvider::new(provider_turns);
    let (capturing, captured) = CapturingProvider::new(mock);
    let mut planner = LlmPlanner::new(Box::new(capturing), Box::new(MockStateClient::default()), 5);
    if let Some(h) = hint {
        planner = planner.with_distro(h);
    }
    let _ = planner
        .plan_intent("show disk usage")
        .await
        .expect("plan must succeed");
    let result = captured.lock().unwrap().clone().unwrap_or_default();
    result
}

// ---------------------------------------------------------------------------
// Test: prompt with Fedora hint contains Fedora actions and excludes apt
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prompt_with_fedora_hint_contains_fedora_actions_and_excludes_apt() {
    let hint = DistroHint {
        family: DISTRO_FAMILY_FEDORA,
        version: Some("Fedora 41".to_string()),
    };
    let system = run_and_capture_system(
        Some(hint),
        [propose_plan(
            "disk check",
            &[("GetDiskUsage", "Check disk", "low")],
        )],
    )
    .await;

    // Must contain the Fedora action family names.
    assert!(
        system.contains("AddLayeredPackage"),
        "Fedora prompt must mention AddLayeredPackage; got prompt length={}",
        system.len()
    );
    assert!(
        system.contains("RemoveLayeredPackage"),
        "Fedora prompt must mention RemoveLayeredPackage"
    );

    // Must mention the detected distro.
    assert!(
        system.contains("Fedora 41"),
        "Fedora prompt must mention the version string"
    );

    // Per ADR 0004 (per-distro prompt dispatch), the Fedora prompt must
    // not mention any Debian-family action by name. Exclusion is by
    // absence, not by enumeration in a "NOT available" list — the goal
    // is zero token spend on actions the LLM will never propose here.
    for forbidden in [
        "AptInstall",
        "AptUpdate",
        "SnapInstall",
        "UfwAllow",
        "UfwStatus",
        "NetplanApply",
        "DistroboxCreate",
    ] {
        assert!(
            !system.contains(forbidden),
            "Fedora prompt leaked Debian action: {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: prompt with Ubuntu hint contains apt and excludes rpm-ostree names
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prompt_with_ubuntu_hint_contains_apt_and_excludes_rpm_ostree() {
    let hint = DistroHint {
        family: DISTRO_FAMILY_DEBIAN,
        version: Some("Ubuntu 24.04".to_string()),
    };
    let system = run_and_capture_system(
        Some(hint),
        [propose_plan(
            "disk check",
            &[("GetDiskUsage", "Check disk", "low")],
        )],
    )
    .await;

    // Must contain the Debian/Ubuntu action family names.
    assert!(
        system.contains("AptInstall"),
        "Ubuntu prompt must mention AptInstall"
    );
    assert!(
        system.contains("AptRemove"),
        "Ubuntu prompt must mention AptRemove"
    );

    // Must mention the detected distro.
    assert!(
        system.contains("Ubuntu 24.04"),
        "Ubuntu prompt must mention the version string"
    );

    // Per ADR 0004, the Ubuntu prompt must not mention any Fedora-family
    // action by name. Exclusion is by absence.
    for forbidden in [
        "AddLayeredPackage",
        "RemoveLayeredPackage",
        "RebaseSystem",
        "RollbackDeployment",
        "GetLayeredPackages",
        // Use newline prefix to distinguish Fedora-only `InstallFlatpak` from
        // Ubuntu-only `UbuntuInstallFlatpak` — the latter is a valid Ubuntu
        // action that contains `InstallFlatpak` as a substring.
        "\nInstallFlatpak",
        "CreateToolbox",
        "ConfigureFirewall",
        "GetFirewallState",
    ] {
        assert!(
            !system.contains(forbidden),
            "Ubuntu prompt leaked Fedora action: {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: prompt with no distro hint is unchanged from baseline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prompt_with_no_distro_hint_is_unchanged_from_baseline() {
    use sysknife_brain::prompt::build_system_prompt;

    let system = run_and_capture_system(
        None,
        [propose_plan(
            "disk check",
            &[("GetDiskUsage", "Check disk", "low")],
        )],
    )
    .await;

    let baseline = build_system_prompt(None, None);
    assert_eq!(
        system, baseline,
        "prompt without a distro hint must equal the no-hint baseline"
    );
}

// ---------------------------------------------------------------------------
// Story-coverage tests: same intent → different action family per distro
// ---------------------------------------------------------------------------
//
// These tests verify that the distro hint causes the *prompt* to instruct the
// model to use the correct action family.  Because tests use MockProvider, we
// cannot verify the LLM's choice — we verify that the prompt contains the
// right routing instruction.  The distro_routing.rs tests verify the
// post-plan execution guard separately.

/// For each (intent_keyword, fedora_action, ubuntu_action) triple, assert:
/// - the Fedora prompt contains `fedora_action` and **does not** contain
///   `ubuntu_action` anywhere (per ADR 0004 — exclusion is by absence);
/// - the Ubuntu prompt contains `ubuntu_action` and **does not** contain
///   `fedora_action` anywhere.
struct StoryCoverage {
    description: &'static str,
    fedora_action: &'static str,
    ubuntu_action: &'static str,
}

fn story_coverage_cases() -> &'static [StoryCoverage] {
    &[
        StoryCoverage {
            description: "system-package install",
            fedora_action: "AddLayeredPackage",
            ubuntu_action: "AptInstall",
        },
        StoryCoverage {
            description: "system-package remove",
            fedora_action: "RemoveLayeredPackage",
            ubuntu_action: "AptRemove",
        },
        StoryCoverage {
            description: "firewall management",
            fedora_action: "ConfigureFirewall",
            ubuntu_action: "UfwAllow",
        },
    ]
}

#[tokio::test]
async fn story_coverage_fedora_prompt_contains_fedora_actions_and_excludes_ubuntu() {
    let fedora_hint = DistroHint {
        family: DISTRO_FAMILY_FEDORA,
        version: Some("Fedora 41".to_string()),
    };
    let system = run_and_capture_system(
        Some(fedora_hint),
        [propose_plan("action", &[("GetDiskUsage", "check", "low")])],
    )
    .await;

    for case in story_coverage_cases() {
        assert!(
            system.contains(case.fedora_action),
            "[{}] Fedora prompt must contain {}",
            case.description,
            case.fedora_action
        );
    }
    // Per ADR 0004, the Fedora prompt must not contain any Debian action.
    assert!(
        !system.contains("AptInstall"),
        "Fedora prompt leaked AptInstall"
    );
    assert!(
        !system.contains("SnapInstall"),
        "Fedora prompt leaked SnapInstall"
    );
}

#[tokio::test]
async fn story_coverage_ubuntu_prompt_contains_ubuntu_actions_and_excludes_fedora() {
    let ubuntu_hint = DistroHint {
        family: DISTRO_FAMILY_DEBIAN,
        version: Some("Ubuntu 24.04".to_string()),
    };
    let system = run_and_capture_system(
        Some(ubuntu_hint),
        [propose_plan("action", &[("GetDiskUsage", "check", "low")])],
    )
    .await;

    for case in story_coverage_cases() {
        assert!(
            system.contains(case.ubuntu_action),
            "[{}] Ubuntu prompt must contain {}",
            case.description,
            case.ubuntu_action
        );
    }
    // Per ADR 0004, the Ubuntu prompt must not contain any Fedora action.
    assert!(
        !system.contains("AddLayeredPackage"),
        "Ubuntu prompt leaked AddLayeredPackage"
    );
    assert!(
        !system.contains("RebaseSystem"),
        "Ubuntu prompt leaked RebaseSystem"
    );
}

#[tokio::test]
async fn story_coverage_second_fedora_case_install_packages() {
    // "install a system package" — Fedora uses AddLayeredPackage / InstallPackages, not AptInstall
    let fedora_hint = DistroHint {
        family: DISTRO_FAMILY_FEDORA,
        version: Some("FedoraSilverblue 41".to_string()),
    };
    let system = run_and_capture_system(
        Some(fedora_hint),
        [propose_plan(
            "install",
            &[("AddLayeredPackage", "layer vim", "high")],
        )],
    )
    .await;

    assert!(
        system.contains("AddLayeredPackage"),
        "prompt must list AddLayeredPackage"
    );
    assert!(
        !system.contains("AptInstall"),
        "Fedora prompt must not mention AptInstall"
    );
}

#[tokio::test]
async fn story_coverage_third_fedora_case_rollback() {
    // "rollback system" — Fedora uses RollbackDeployment, not an apt command
    let fedora_hint = DistroHint {
        family: DISTRO_FAMILY_FEDORA,
        version: Some("Fedora 42".to_string()),
    };
    let system = run_and_capture_system(
        Some(fedora_hint),
        [propose_plan(
            "rollback",
            &[("RollbackDeployment", "rollback", "high")],
        )],
    )
    .await;

    assert!(
        system.contains("RollbackDeployment"),
        "Fedora prompt must include RollbackDeployment"
    );
    assert!(
        !system.contains("AptInstall"),
        "Fedora prompt must not mention AptInstall"
    );
}

#[tokio::test]
async fn story_coverage_second_ubuntu_case_snap_install() {
    // "install via snap" — Ubuntu uses SnapInstall, not AddLayeredPackage
    let ubuntu_hint = DistroHint {
        family: DISTRO_FAMILY_DEBIAN,
        version: Some("Ubuntu 22.04".to_string()),
    };
    let system = run_and_capture_system(
        Some(ubuntu_hint),
        [propose_plan(
            "snap",
            &[("SnapInstall", "install snap", "medium")],
        )],
    )
    .await;

    assert!(
        system.contains("SnapInstall"),
        "Ubuntu prompt must include SnapInstall"
    );
    assert!(
        !system.contains("AddLayeredPackage"),
        "Ubuntu prompt must not mention AddLayeredPackage"
    );
}

#[tokio::test]
async fn story_coverage_third_ubuntu_case_apt_search() {
    // "search for a package" — Ubuntu uses AptSearch, not SearchFlatpakApps alone
    let ubuntu_hint = DistroHint {
        family: DISTRO_FAMILY_DEBIAN,
        version: Some("Ubuntu 26.04".to_string()),
    };
    let system = run_and_capture_system(
        Some(ubuntu_hint),
        [propose_plan(
            "search",
            &[("AptSearch", "search apt", "low")],
        )],
    )
    .await;

    assert!(
        system.contains("AptSearch"),
        "Ubuntu prompt must include AptSearch"
    );
    assert!(
        !system.contains("AddLayeredPackage"),
        "Ubuntu prompt must not mention AddLayeredPackage"
    );
}

/// Malformed provider JSON must surface as a planning failure, not be
/// swallowed into an empty plan. `ProviderError` has five variants; only
/// `Http` and `Auth` were exercised through `plan_intent`, leaving the
/// parse/rate-limit/request paths unproven.
#[tokio::test]
async fn provider_parse_error_propagates() {
    let planner = make_planner(MockProvider::new([Err(ProviderError::Parse(
        "model returned unparseable JSON".into(),
    ))]));

    // Asserting the variant, not just "some provider error": before
    // `PlanningError::Provider` carried a `ProviderError`, these three tests
    // made the identical assertion and could not tell a parse failure from a
    // rate limit.
    assert!(matches!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::Provider(ProviderError::Parse(_))
    ));
}

/// A *persistent* rate limit surfaces as `RateLimit`. Scripted three times
/// because the call is now retried: one scripted error would be followed by
/// MockProvider's exhaustion fallback, and the test would assert the variant of
/// the fixture rather than of the failure.
#[tokio::test(start_paused = true)]
async fn rate_limit_error_propagates() {
    let planner = make_planner(MockProvider::new([
        Err(ProviderError::RateLimit("429 slow down".into())),
        Err(ProviderError::RateLimit("429 slow down".into())),
        Err(ProviderError::RateLimit("429 slow down".into())),
    ]));

    assert!(matches!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::Provider(ProviderError::RateLimit(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn transport_request_error_propagates() {
    let planner = make_planner(MockProvider::new([
        Err(ProviderError::Request("connection reset".into())),
        Err(ProviderError::Request("connection reset".into())),
        Err(ProviderError::Request("connection reset".into())),
    ]));

    assert!(matches!(
        planner.plan_intent("do something").await.unwrap_err(),
        PlanningError::Provider(ProviderError::Request(_))
    ));
}

// ---------------------------------------------------------------------------
// Provider retry (#178)
//
// The turn loop retried the model's own mistakes — text instead of a tool call,
// a plan the safety fence rejected — but a provider-level failure ended planning
// on its first occurrence, with nine turns still unused. One 502, one truncated
// payload, one rate-limit response and the whole request was over.
//
// Retrying is not universally right, which is the point of these tests: two
// classes must still fail immediately, and one of them (CassetteMiss) would turn
// a fast, well-explained hermetic-replay failure into a slow one.
// ---------------------------------------------------------------------------

/// A provider that counts every call, so a test can assert how many attempts a
/// failure class actually produced rather than inferring it from the outcome.
struct CountingProvider {
    turns: Mutex<VecDeque<Result<Completion, ProviderError>>>,
    calls: Arc<AtomicUsize>,
    /// Returned once the scripted turns run out, so "retried forever" shows up
    /// as a bounded count rather than a hang.
    exhausted: Box<dyn Fn() -> Result<Completion, ProviderError> + Send + Sync>,
}

impl CountingProvider {
    fn new(
        turns: impl IntoIterator<Item = Result<Completion, ProviderError>>,
        exhausted: impl Fn() -> Result<Completion, ProviderError> + Send + Sync + 'static,
    ) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                turns: Mutex::new(turns.into_iter().collect()),
                calls: Arc::clone(&calls),
                exhausted: Box::new(exhausted),
            },
            calls,
        )
    }
}

#[async_trait]
impl LlmProvider for CountingProvider {
    async fn complete(
        &self,
        _system: &str,
        _messages: &[Message],
        _tools: &[ToolDefinition],
        _max_tokens: u32,
    ) -> Result<Completion, ProviderError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let next = self.turns.lock().unwrap().pop_front();
        next.unwrap_or_else(|| (self.exhausted)())
    }
}

fn counting_planner(provider: CountingProvider) -> LlmPlanner {
    LlmPlanner::new(Box::new(provider), Box::new(MockStateClient::default()), 5)
}

#[tokio::test(start_paused = true)]
async fn a_transient_provider_failure_is_retried_rather_than_ending_planning() {
    // A 502 from the provider says nothing about the request; the identical call
    // a moment later usually works.
    let (provider, calls) = CountingProvider::new(
        [
            Err(ProviderError::Http {
                status: 502,
                body: "bad gateway".into(),
            }),
            propose_plan("install vim", &[("AptInstall", "install vim", "medium")]),
        ],
        || Err(ProviderError::Parse("exhausted".into())),
    );
    let plan = counting_planner(provider)
        .plan_intent("install vim")
        .await
        .expect("a 502 must not end planning");
    assert_eq!(plan.summary(), "install vim");
    assert_eq!(calls.load(Ordering::Relaxed), 2, "must have retried once");
}

#[tokio::test(start_paused = true)]
async fn a_truncated_provider_payload_is_retried() {
    let (provider, calls) = CountingProvider::new(
        [
            Err(ProviderError::Parse("unexpected end of JSON".into())),
            propose_plan("list services", &[("ListServices", "list", "low")]),
        ],
        || Err(ProviderError::Parse("exhausted".into())),
    );
    assert!(counting_planner(provider)
        .plan_intent("list services")
        .await
        .is_ok());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn an_auth_failure_fails_fast_and_is_never_retried() {
    // A wrong key stays wrong. Retrying only delays the one message that tells
    // the operator what to fix.
    let (provider, calls) = CountingProvider::new(
        [
            Err(ProviderError::Auth("invalid api key".into())),
            propose_plan("install vim", &[("AptInstall", "install vim", "medium")]),
        ],
        || Err(ProviderError::Parse("exhausted".into())),
    );
    assert!(counting_planner(provider)
        .plan_intent("install vim")
        .await
        .is_err());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "auth failure must be attempted exactly once"
    );
}

#[tokio::test]
async fn a_cassette_miss_is_attempted_exactly_once() {
    // The cassette key is a hash of the call, so a retry issues the identical
    // lookup and misses identically. Retrying it would burn a replay-gated CI
    // job's timeout while printing nothing new.
    let (provider, calls) = CountingProvider::new(
        [
            Err(ProviderError::CassetteMiss("no recorded output".into())),
            propose_plan("install vim", &[("AptInstall", "install vim", "medium")]),
        ],
        || Err(ProviderError::Parse("exhausted".into())),
    );
    assert!(counting_planner(provider)
        .plan_intent("install vim")
        .await
        .is_err());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "a cassette miss is deterministic; retrying it is pure delay"
    );
}

#[tokio::test]
async fn a_client_error_is_not_retried() {
    // 4xx is a defect in the request we just built; building it again produces
    // the same bytes.
    let (provider, calls) = CountingProvider::new(
        [
            Err(ProviderError::Http {
                status: 400,
                body: "bad request".into(),
            }),
            propose_plan("install vim", &[("AptInstall", "install vim", "medium")]),
        ],
        || Err(ProviderError::Parse("exhausted".into())),
    );
    assert!(counting_planner(provider)
        .plan_intent("install vim")
        .await
        .is_err());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn retries_are_bounded_so_a_persistent_outage_still_terminates() {
    // Without a ceiling, a provider that is simply down turns one intent into an
    // unbounded retry loop.
    let (provider, calls) = CountingProvider::new([], || {
        Err(ProviderError::Http {
            status: 503,
            body: "service unavailable".into(),
        })
    });
    assert!(counting_planner(provider)
        .plan_intent("install vim")
        .await
        .is_err());
    let n = calls.load(Ordering::Relaxed);
    assert!(
        (2..=4).contains(&n),
        "a persistent outage must stop after a small bounded number of attempts, got {n}"
    );
}

// ---------------------------------------------------------------------------
// Refusal (#179)
//
// The plan schema had no shape for "there is nothing valid to do", so a request
// with no legitimate plan produced either an invented adjacent action or a
// PlannerStuck crash. Observed live: "block port 0 in the firewall" was answered
// with UfwStatus — a read-only query the user never asked for, with the refusal
// surviving only in the explanation prose of a plan doing something else.
// ---------------------------------------------------------------------------

fn refuse(reason: &str, suggestion: Option<&str>) -> Result<Completion, ProviderError> {
    let mut input = serde_json::json!({ "reason": reason });
    if let Some(s) = suggestion {
        input["suggestion"] = serde_json::json!(s);
    }
    Ok(Completion {
        content: vec![ContentBlock::ToolUse {
            id: "tu_refuse".into(),
            call_id: None,
            name: "refuse".into(),
            input,
        }],
        stop_reason: StopReason::ToolUse,
    })
}

#[tokio::test]
async fn an_impossible_request_is_refused_with_its_reason() {
    let planner = make_planner(MockProvider::new([refuse(
        "Port 0 is not a valid port number; firewall rules require 1-65535.",
        Some("Specify a port between 1 and 65535."),
    )]));
    let err = planner
        .plan_intent("block port 0 in the firewall")
        .await
        .unwrap_err();
    match err {
        PlanningError::Refused { reason, suggestion } => {
            assert!(
                reason.contains("Port 0"),
                "reason must be carried: {reason}"
            );
            assert_eq!(
                suggestion.as_deref(),
                Some("Specify a port between 1 and 65535.")
            );
        }
        other => panic!("expected Refused, got {other:?}"),
    }
}

/// A refusal must be distinguishable from the planner failing. Before this, both
/// arrived as PlannerStuck, which reads as an internal fault rather than an
/// answer.
#[tokio::test]
async fn a_refusal_is_not_reported_as_planner_stuck() {
    let planner = make_planner(MockProvider::new([refuse("No action can do that.", None)]));
    let err = planner.plan_intent("do the impossible").await.unwrap_err();
    assert!(
        !matches!(
            err,
            PlanningError::PlannerStuck | PlanningError::NoPlanProposed
        ),
        "a deliberate refusal must not masquerade as a planner failure: {err:?}"
    );
}

/// The fence must NOT be relaxed by this change. An empty `steps` array is still
/// how a model signals it gave up, and that is still rejected — the whole point
/// of adding a separate tool rather than loosening propose_plan.
#[tokio::test]
async fn an_empty_plan_is_still_rejected_by_the_fence() {
    let empty_plan = Ok(Completion {
        content: vec![ContentBlock::ToolUse {
            id: "tu_empty".into(),
            call_id: None,
            name: "propose_plan".into(),
            input: serde_json::json!({
                "summary": "Nothing to do",
                "explanation": "There is nothing to do.",
                "steps": []
            }),
        }],
        stop_reason: StopReason::ToolUse,
    });
    // Single turn, so a rejected plan cannot be retried into success.
    let planner = LlmPlanner::new(
        Box::new(MockProvider::new([empty_plan])),
        Box::new(MockStateClient::default()),
        1,
    );
    let err = planner.plan_intent("do nothing").await.unwrap_err();
    assert!(
        !matches!(err, PlanningError::Refused { .. }),
        "an empty steps array is a give-up, not a refusal: {err:?}"
    );
}

/// A refusal with no reason is the give-up case wearing a different hat. It must
/// be fed back for another attempt, not accepted.
#[tokio::test]
async fn a_reasonless_refusal_is_retried_rather_than_accepted() {
    let planner = make_planner(MockProvider::new([
        refuse("", None),
        propose_plan("install vim", &[("AptInstall", "install vim", "medium")]),
    ]));
    let plan = planner
        .plan_intent("install vim")
        .await
        .expect("the model must get another turn after an invalid refusal");
    assert_eq!(plan.summary(), "install vim");
}
