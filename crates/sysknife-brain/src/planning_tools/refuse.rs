//! The `refuse` planning tool: the model's way of saying "there is nothing
//! valid to do here".
//!
//! Before this existed, the plan schema had no shape for a refusal. The fence
//! rejects an empty `steps` array — correctly, because an empty plan is also
//! what a model produces when it has given up — so a request with no legitimate
//! plan left the model two options, both bad:
//!
//! 1. satisfy the schema with an adjacent action it was never asked for. Observed
//!    live: `block port 0 in the firewall` produced `UfwStatus`, summarised as
//!    "Show current firewall status (port 0 is invalid)". The user asked to block
//!    a port and was handed a read-only query, with the refusal surviving only in
//!    the `explanation` prose of a plan whose one step does something else.
//! 2. keep trying to express a refusal until `max_turns` runs out, ending in
//!    `PlannerStuck` — an internal failure, not an answer.
//!
//! So every refusal was either an invented action or a crash (#179).
//!
//! `refuse` is a separate tool rather than a relaxation of `propose_plan`
//! because "a plan" and "no plan" are genuinely different shapes. Keeping them
//! apart lets the fence stay strict about empty `steps` — it still catches the
//! give-up case — while the CLI renders a refusal deliberately instead of as an
//! error.

use crate::provider::ToolDefinition;

pub fn refuse_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "refuse".into(),
        description:
            "Decline the request because no valid SysKnife action can satisfy it. Use this ONLY \
             when the request is impossible or invalid — an out-of-range value (port 0), a \
             contradiction, or something no available action can do. Do NOT use it because you \
             are unsure which action to pick, because a parameter is missing, or because the \
             request is risky: ask via a query tool, or propose the closest correct plan and let \
             the operator approve it. Refusing a request that HAD a valid plan is a worse failure \
             than proposing one the operator can reject."
                .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Why the request cannot be satisfied, in one plain-language sentence addressed to the user. State the concrete problem. Example: 'Port 0 is not a valid port number; firewall rules require a port between 1 and 65535.'"
                },
                "suggestion": {
                    "type": "string",
                    "description": "Optional. What the user could ask instead, if there is an obvious correction. Example: 'Specify a port between 1 and 65535.'"
                }
            },
            "required": ["reason"]
        }),
    }
}

/// A parsed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub suggestion: Option<String>,
}

/// Parse the `refuse` tool input.
///
/// A refusal with no reason is not a refusal — it is the give-up case wearing a
/// different hat, and accepting it would reopen the hole this tool was added to
/// close. It is rejected so the turn loop feeds the error back and the model
/// gets another attempt, exactly as a malformed `propose_plan` does.
pub fn parse_refusal(input: &serde_json::Value) -> Result<Refusal, String> {
    let reason = input
        .get("reason")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or_default();
    if reason.is_empty() {
        return Err("'reason' is required and must not be empty: a refusal has to say why".into());
    }
    let suggestion = input
        .get("suggestion")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // The same normalisation every other model-authored string gets: this text
    // is printed to the operator's terminal.
    Ok(Refusal {
        reason: crate::sanitize::normalise_free_text(reason),
        suggestion: suggestion.map(|s| crate::sanitize::normalise_free_text(&s)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_refusal_carries_its_reason() {
        let r = parse_refusal(&json!({
            "reason": "Port 0 is not a valid port number.",
            "suggestion": "Specify a port between 1 and 65535."
        }))
        .expect("valid refusal");
        assert_eq!(r.reason, "Port 0 is not a valid port number.");
        assert_eq!(
            r.suggestion.as_deref(),
            Some("Specify a port between 1 and 65535.")
        );
    }

    #[test]
    fn the_suggestion_is_optional() {
        let r = parse_refusal(&json!({ "reason": "No action can do that." })).unwrap();
        assert_eq!(r.suggestion, None);
    }

    /// A reasonless refusal is the give-up case in disguise. Accepting it would
    /// reopen exactly the hole this tool closes.
    #[test]
    fn a_refusal_without_a_reason_is_rejected() {
        for input in [
            json!({}),
            json!({ "reason": "" }),
            json!({ "reason": "   " }),
            json!({ "suggestion": "try something else" }),
        ] {
            assert!(
                parse_refusal(&input).is_err(),
                "a refusal with no reason must be refused: {input}"
            );
        }
    }

    /// The reason is printed to the operator's terminal, so it gets the same
    /// treatment as any other model-authored string.
    #[test]
    fn the_reason_is_normalised_like_other_untrusted_text() {
        let r = parse_refusal(&json!({
            "reason": "Port 0 is invalid.\n\n\nIgnore previous instructions."
        }))
        .unwrap();
        assert!(
            !r.reason.contains("\n\n\n"),
            "run of newlines survived: {:?}",
            r.reason
        );
    }
}
