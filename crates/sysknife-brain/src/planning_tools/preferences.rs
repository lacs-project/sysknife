//! `remember` and `forget` planning tools.
//!
//! These tools let the LLM save or remove user preferences during planning.
//! They are brain-side-only and never touch the daemon. The actual file I/O
//! is handled by `crate::prefs` and dispatched in `planner.rs`.

use crate::provider::ToolDefinition;

pub fn remember_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "remember".into(),
        description: "Save a user preference that should apply to all future planning sessions. \
                       Use this when the user explicitly asks you to remember something about how \
                       they want their system managed. Do NOT use this to store system facts — only \
                       user preferences and stated intentions."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "fact": {
                    "type": "string",
                    "description": "The preference to save, in plain language. Be specific and actionable. Example: 'Prefer vim-enhanced over vim for package layering requests'."
                }
            },
            "required": ["fact"]
        }),
    }
}

pub fn forget_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "forget".into(),
        description: "Remove a previously saved user preference. Use this when the user asks \
                       you to forget or stop applying a preference. The fact string must match \
                       an existing preference exactly."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "fact": {
                    "type": "string",
                    "description": "The preference to remove. Must match an existing entry exactly."
                }
            },
            "required": ["fact"]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remember_tool_has_fact_param() {
        let def = remember_tool_def();
        assert_eq!(def.name, "remember");
        let props = def.input_schema["properties"].as_object().unwrap();
        assert!(props.contains_key("fact"));
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "fact"));
    }

    #[test]
    fn forget_tool_has_fact_param() {
        let def = forget_tool_def();
        assert_eq!(def.name, "forget");
        let props = def.input_schema["properties"].as_object().unwrap();
        assert!(props.contains_key("fact"));
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "fact"));
    }
}
