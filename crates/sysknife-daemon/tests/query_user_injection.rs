//! Query tools that need a user must reach the daemon with the caller's identity.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use sysknife_brain::planner::{LlmPlanner, PlanningError};
use sysknife_brain::provider::{
    Completion, ContentBlock, LlmProvider, Message, ProviderError, StopReason, ToolDefinition,
};
use sysknife_brain::state_client::{CuratedState, StateClient};
use sysknife_daemon::executor::build_action_spec;

struct OneTurnProvider(Mutex<Option<Completion>>);

impl OneTurnProvider {
    fn new(completion: Completion) -> Self {
        Self(Mutex::new(Some(completion)))
    }
}

#[async_trait]
impl LlmProvider for OneTurnProvider {
    async fn complete(
        &self,
        _system: &str,
        _messages: &[Message],
        _tools: &[ToolDefinition],
        _max_tokens: u32,
    ) -> Result<Completion, ProviderError> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| ProviderError::Parse("one-turn provider exhausted".into()))
    }
}

#[derive(Clone, Default)]
struct CapturingStateClient(Arc<Mutex<Vec<(String, Value)>>>);

impl StateClient for CapturingStateClient {
    fn curated_state(&self) -> Result<CuratedState, PlanningError> {
        CuratedState::new(
            "fixture-host",
            "ubuntu/24.04",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .map_err(PlanningError::StateUnavailable)
    }

    fn current_user(&self) -> Result<String, PlanningError> {
        Ok("fixture-user".into())
    }

    fn query_action(&self, action_name: &str, params: &Value) -> Result<String, PlanningError> {
        self.0
            .lock()
            .unwrap()
            .push((action_name.to_owned(), params.clone()));
        Ok("fixture query result".into())
    }
}

#[tokio::test]
async fn user_scoped_query_tools_inject_current_user_for_daemon_specs() {
    let query_tools = [
        ("query_containers", json!({}), "ListContainers"),
        ("query_flatpak_remotes", json!({}), "ListFlatpakRemotes"),
        ("query_toolboxes", json!({}), "ListToolboxes"),
        (
            "query_flatpak_info",
            json!({"app_id": "org.example.Fixture"}),
            "GetFlatpakAppInfo",
        ),
        (
            "query_container_info",
            json!({"name": "fixture"}),
            "GetContainerInfo",
        ),
        // An unrelated query must not receive an unnecessary username.
        ("query_services", json!({}), "ListServices"),
    ];

    let mut content: Vec<_> = query_tools
        .iter()
        .map(|(tool_name, input, _)| ContentBlock::ToolUse {
            id: (*tool_name).into(),
            call_id: None,
            name: (*tool_name).into(),
            input: input.clone(),
        })
        .collect();
    content.push(ContentBlock::ToolUse {
        id: "plan".into(),
        call_id: None,
        name: "propose_plan".into(),
        input: json!({
            "summary": "Inspect the system",
            "explanation": "Read the requested inventory.",
            "steps": [{
                "action_name": "GetDiskUsage",
                "summary": "Inspect disk usage",
                "risk_level": "low",
                "params": {}
            }]
        }),
    });

    let state_client = CapturingStateClient::default();
    let planner = LlmPlanner::new(
        Box::new(OneTurnProvider::new(Completion {
            content,
            stop_reason: StopReason::ToolUse,
        })),
        Box::new(state_client.clone()),
        1,
    );

    planner
        .plan_intent("inspect containers and installed software")
        .await
        .expect("the valid plan should be returned after its query calls");

    let calls = state_client.0.lock().unwrap();
    assert_eq!(calls.len(), query_tools.len());
    for (tool_name, _, action_name) in query_tools {
        let (_, params) = calls
            .iter()
            .find(|(action, _)| action == action_name)
            .unwrap_or_else(|| panic!("{tool_name} did not dispatch {action_name}"));

        if matches!(
            tool_name,
            "query_containers"
                | "query_flatpak_remotes"
                | "query_toolboxes"
                | "query_flatpak_info"
                | "query_container_info"
        ) {
            assert_eq!(params["username"], "fixture-user", "{tool_name}");
        } else {
            assert!(params.get("username").is_none(), "{tool_name}");
        }

        build_action_spec(action_name, params).unwrap_or_else(|error| {
            panic!("{tool_name} produced invalid {action_name} params: {error}")
        });
    }
}
