//! The `get_system_state` planning tool definition.
//!
//! This tool has no input parameters. When the LLM calls it, the planner
//! dispatches to `StateClient::curated_state()` and returns the serialised
//! result as a tool result block.

use crate::provider::ToolDefinition;

pub fn get_state_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "get_system_state".into(),
        description: "Retrieve the current curated system state from the SysKnife daemon. \
                       Call this before proposing a plan that depends on current system \
                       configuration: deployments, installed packages, services, containers, \
                       or user accounts."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
    }
}
