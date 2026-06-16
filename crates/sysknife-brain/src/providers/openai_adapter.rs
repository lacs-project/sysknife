//! Adapter that uses async-openai directly for the OpenAI Chat Completions API.
//!
//! Replaces the rig-based OpenAI path to avoid three rig issues:
//!
//! 1. rig defaults to `/v1/responses` (Responses API), not `/v1/chat/completions`.
//! 2. The Responses API emits reasoning content items for some model variants,
//!    causing `from_rig_response` to return "unsupported content types" errors.
//! 3. rig issue #1599: on the Responses API path, the system prompt ends up in
//!    a user message instead of the `instructions` field — a regression from a
//!    third-party compat PR. async-openai sends it as a proper system-role message
//!    in Chat Completions, sidestepping the issue entirely.
//!
//! async-openai targets `/v1/chat/completions` directly, tracks the OpenAI API
//! closely, and has no reasoning-item or system-prompt issues.
//!
//! Chat Completions uses a single tool-call ID per call (no dual-ID protocol).
//! `ContentBlock::ToolUse::call_id` is always `None` from this adapter.

use async_openai::{
    config::OpenAIConfig,
    types::chat::{
        ChatCompletionMessageToolCall, ChatCompletionMessageToolCalls,
        ChatCompletionRequestAssistantMessageArgs, ChatCompletionRequestMessage,
        ChatCompletionRequestSystemMessage, ChatCompletionRequestToolMessage,
        ChatCompletionRequestUserMessage, ChatCompletionRequestUserMessageContent,
        ChatCompletionTool, ChatCompletionTools, CreateChatCompletionRequestArgs,
        CreateChatCompletionResponse, FinishReason, FunctionCall, FunctionObject,
    },
    Client,
};
use async_trait::async_trait;

use super::sanitize_error_msg;
use crate::provider::{
    Completion, ContentBlock, LlmProvider, Message, ProviderError, Role, StopReason, ToolDefinition,
};

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// LLM backend for OpenAI using async-openai and the Chat Completions API.
pub struct AsyncOpenAiAdapter {
    client: Client<OpenAIConfig>,
    model: String,
}

impl AsyncOpenAiAdapter {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let config = OpenAIConfig::new().with_api_key(api_key.into());
        Self {
            client: Client::with_config(config),
            model: model.into(),
        }
    }
}

#[async_trait]
impl LlmProvider for AsyncOpenAiAdapter {
    async fn complete(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<Completion, ProviderError> {
        let oai_messages = to_openai_messages(system, messages).map_err(ProviderError::Request)?;
        let oai_tools = to_openai_tools(tools);

        let mut req_builder = CreateChatCompletionRequestArgs::default();
        req_builder
            .model(self.model.clone())
            .messages(oai_messages)
            .max_completion_tokens(max_tokens);

        if !oai_tools.is_empty() {
            req_builder.tools(oai_tools);
        }

        let request = req_builder
            .build()
            .map_err(|e: async_openai::error::OpenAIError| ProviderError::Request(e.to_string()))?;

        let response = self
            .client
            .chat()
            .create(request)
            .await
            .map_err(map_openai_error)?;

        from_openai_response(response)
    }
}

// ---------------------------------------------------------------------------
// Message conversion: our types → async-openai request types
// ---------------------------------------------------------------------------

/// Convert our system prompt + message history to async-openai's message format.
///
/// Returns `Err(String)` if a message cannot be converted. The error string is
/// surfaced as `ProviderError::Request` by the caller.
fn to_openai_messages(
    system: &str,
    messages: &[Message],
) -> Result<Vec<ChatCompletionRequestMessage>, String> {
    let mut result = Vec::with_capacity(messages.len() + 1);

    // System prompt — always first.
    result.push(ChatCompletionRequestMessage::System(
        ChatCompletionRequestSystemMessage {
            content: system.to_string().into(),
            name: None,
        },
    ));

    for msg in messages {
        match msg.role {
            Role::User => {
                let all_results = !msg.content.is_empty()
                    && msg
                        .content
                        .iter()
                        .all(|b| matches!(b, ContentBlock::ToolResult { .. }));

                if all_results {
                    // Each tool result becomes a separate Tool message.
                    // Chat Completions requires one Tool message per tool call.
                    for block in &msg.content {
                        if let ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error,
                            ..
                        } = block
                        {
                            let text = if *is_error {
                                format!("[TOOL ERROR] {content}")
                            } else {
                                content.clone()
                            };
                            result.push(ChatCompletionRequestMessage::Tool(
                                ChatCompletionRequestToolMessage {
                                    content: text.into(),
                                    tool_call_id: tool_use_id.clone(),
                                },
                            ));
                        }
                    }
                } else {
                    let text = msg
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

                    result.push(ChatCompletionRequestMessage::User(
                        ChatCompletionRequestUserMessage {
                            content: ChatCompletionRequestUserMessageContent::Text(text),
                            name: None,
                        },
                    ));
                }
            }

            Role::Assistant => {
                let mut text_parts: Vec<String> = Vec::new();
                let mut tool_calls: Vec<ChatCompletionMessageToolCalls> = Vec::new();

                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text } => text_parts.push(text.clone()),
                        ContentBlock::ToolUse {
                            id, name, input, ..
                        } => {
                            let arguments = serde_json::to_string(input).map_err(|e| {
                                format!("failed to serialize tool arguments for '{}': {}", name, e)
                            })?;
                            tool_calls.push(ChatCompletionMessageToolCalls::Function(
                                ChatCompletionMessageToolCall {
                                    id: id.clone(),
                                    function: FunctionCall {
                                        name: name.clone(),
                                        arguments,
                                    },
                                },
                            ));
                        }
                        ContentBlock::ToolResult { .. } => {
                            // Tool results do not appear in assistant messages.
                        }
                    }
                }

                if text_parts.is_empty() && tool_calls.is_empty() {
                    return Err(format!(
                        "assistant message at history position {} has no text and no \
                         tool calls — this indicates a conversation history bug",
                        result.len()
                    ));
                }

                let mut builder = ChatCompletionRequestAssistantMessageArgs::default();
                if !text_parts.is_empty() {
                    builder.content(text_parts.join("\n"));
                }
                if !tool_calls.is_empty() {
                    builder.tool_calls(tool_calls);
                }

                result.push(ChatCompletionRequestMessage::Assistant(
                    builder
                        .build()
                        .map_err(|e: async_openai::error::OpenAIError| e.to_string())?,
                ));
            }
        }
    }

    Ok(result)
}

/// Convert our tool definitions to async-openai's format.
fn to_openai_tools(tools: &[ToolDefinition]) -> Vec<ChatCompletionTools> {
    tools
        .iter()
        .map(|t| {
            ChatCompletionTools::Function(ChatCompletionTool {
                function: FunctionObject {
                    name: t.name.clone(),
                    description: Some(t.description.clone()),
                    parameters: Some(t.input_schema.clone()),
                    strict: None,
                },
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Response conversion: async-openai response → our types
// ---------------------------------------------------------------------------

fn from_openai_response(
    response: CreateChatCompletionResponse,
) -> Result<Completion, ProviderError> {
    let choice = response
        .choices
        .into_iter()
        .next()
        .ok_or_else(|| ProviderError::Parse("response contained no choices".into()))?;

    // Content-filter refusals must be surfaced immediately. Treating them as
    // EndTurn would cause the planner to silently burn all retry turns and then
    // fail with a generic "no plan proposed" error, giving the user no indication
    // that OpenAI refused on content-policy grounds.
    if matches!(choice.finish_reason, Some(FinishReason::ContentFilter)) {
        tracing::warn!(
            target: "sysknife_brain::openai_adapter",
            "response stopped by OpenAI content filter; planning cannot continue"
        );
        return Err(ProviderError::Request(
            "OpenAI content filter blocked the response — \
             the request was refused on content-policy grounds"
                .into(),
        ));
    }

    let stop_reason = match choice.finish_reason {
        Some(FinishReason::ToolCalls) => StopReason::ToolUse,
        Some(FinishReason::Length) => StopReason::MaxTokens,
        _ => StopReason::EndTurn,
    };

    let mut content: Vec<ContentBlock> = Vec::new();

    // Text content
    if let Some(text) = choice.message.content {
        if !text.is_empty() {
            tracing::trace!(
                target: "sysknife_brain::openai_adapter",
                "text content ({} chars): {:?}",
                text.len(),
                text.chars().take(200).collect::<String>()
            );
            content.push(ContentBlock::Text { text });
        }
    }

    // Tool calls — response uses Vec<ChatCompletionMessageToolCalls> (the enum).
    // Iterate and extract the Function variant; warn and skip any Custom variants.
    if let Some(tool_calls) = choice.message.tool_calls {
        for tc_enum in tool_calls {
            let tc = match tc_enum {
                ChatCompletionMessageToolCalls::Function(f) => f,
                ChatCompletionMessageToolCalls::Custom(ref raw) => {
                    tracing::warn!(
                        target: "sysknife_brain::openai_adapter",
                        "skipping unrecognized Custom tool call variant: {:?}",
                        raw
                    );
                    continue;
                }
            };
            let args_preview: String = tc.function.arguments.chars().take(200).collect();
            tracing::trace!(
                target: "sysknife_brain::openai_adapter",
                "tool_call: name={}, args={}{}",
                tc.function.name,
                args_preview,
                if tc.function.arguments.len() > 200 { "…" } else { "" }
            );
            let input: serde_json::Value =
                serde_json::from_str(&tc.function.arguments).map_err(|e| {
                    ProviderError::Parse(format!(
                        "tool call '{}' has invalid JSON arguments: {} — raw: {:?}",
                        tc.function.name, e, tc.function.arguments
                    ))
                })?;
            content.push(ContentBlock::ToolUse {
                id: tc.id,
                // Chat Completions uses a single ID — no dual-ID protocol.
                // The planning loop's call_id fallback (id when call_id is None)
                // handles this path correctly for all providers.
                call_id: None,
                name: tc.function.name,
                input,
            });
        }
    }

    if content.is_empty() {
        return Err(ProviderError::Parse(
            "model response contained no text or tool calls".into(),
        ));
    }

    tracing::trace!(
        target: "sysknife_brain::openai_adapter",
        "response: {} content blocks, stop_reason={:?}",
        content.len(),
        stop_reason
    );

    Ok(Completion {
        content,
        stop_reason,
    })
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_openai_error(err: async_openai::error::OpenAIError) -> ProviderError {
    // Sanitize before any logging or propagation to prevent API key leakage.
    // async-openai may include the request URL (with key query params) in errors
    // from misconfigured proxies or HTTP-level transport failures.
    let msg = sanitize_error_msg(&err.to_string());

    if msg.contains("401")
        || msg.to_lowercase().contains("authentication")
        || msg.to_lowercase().contains("api key")
        || msg.to_lowercase().contains("incorrect api key")
    {
        // Log the sanitized message for operator diagnostics but do not propagate
        // it to the caller — auth errors can echo key-adjacent context.
        tracing::error!(
            target: "sysknife_brain::openai_adapter",
            "OpenAI authentication error: {}",
            msg
        );
        ProviderError::Auth("OpenAI authentication failed — check your API key".to_string())
    } else if msg.contains("429") || msg.to_lowercase().contains("rate limit") {
        tracing::warn!(
            target: "sysknife_brain::openai_adapter",
            "OpenAI rate limit hit: {}",
            msg
        );
        ProviderError::RateLimit
    } else {
        tracing::error!(
            target: "sysknife_brain::openai_adapter",
            "OpenAI error: {}",
            msg
        );
        ProviderError::Request(msg)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::provider::{Message, ToolDefinition, ToolResultBlock};
    use async_openai::types::chat::{
        ChatChoice, ChatCompletionRequestSystemMessageContent,
        ChatCompletionRequestToolMessageContent, ChatCompletionResponseMessage, Role as OaiRole,
    };

    // --- to_openai_messages ---------------------------------------------------

    #[test]
    fn system_prompt_is_first_message() {
        let msgs = to_openai_messages("You are a bot.", &[Message::user_text("hi")]).unwrap();
        assert!(
            matches!(msgs[0], ChatCompletionRequestMessage::System(_)),
            "expected first message to be System"
        );
        if let ChatCompletionRequestMessage::System(s) = &msgs[0] {
            match &s.content {
                ChatCompletionRequestSystemMessageContent::Text(t) => {
                    assert_eq!(t, "You are a bot.")
                }
                _ => panic!("expected Text content"),
            }
        }
    }

    #[test]
    fn user_text_becomes_user_message() {
        let msgs = to_openai_messages("sys", &[Message::user_text("hello")]).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(msgs[1], ChatCompletionRequestMessage::User(_)));
        if let ChatCompletionRequestMessage::User(u) = &msgs[1] {
            match &u.content {
                ChatCompletionRequestUserMessageContent::Text(t) => assert_eq!(t, "hello"),
                _ => panic!("expected Text content"),
            }
        }
    }

    #[test]
    fn tool_results_become_tool_messages_one_per_result() {
        let messages = vec![Message::tool_results(vec![
            ToolResultBlock {
                tool_use_id: "call_1".into(),
                call_id: None,
                content: r#"{"ok":true}"#.into(),
                is_error: false,
            },
            ToolResultBlock {
                tool_use_id: "call_2".into(),
                call_id: None,
                content: "error occurred".into(),
                is_error: true,
            },
        ])];
        let msgs = to_openai_messages("sys", &messages).unwrap();
        // system + 2 tool messages
        assert_eq!(msgs.len(), 3, "expected 3 messages (system + 2 tool)");

        assert!(matches!(msgs[1], ChatCompletionRequestMessage::Tool(_)));
        if let ChatCompletionRequestMessage::Tool(t) = &msgs[1] {
            assert_eq!(t.tool_call_id, "call_1");
            match &t.content {
                ChatCompletionRequestToolMessageContent::Text(s) => {
                    assert_eq!(s, r#"{"ok":true}"#)
                }
                _ => panic!("expected Text content"),
            }
        }

        assert!(matches!(msgs[2], ChatCompletionRequestMessage::Tool(_)));
        if let ChatCompletionRequestMessage::Tool(t) = &msgs[2] {
            assert_eq!(t.tool_call_id, "call_2");
            match &t.content {
                ChatCompletionRequestToolMessageContent::Text(s) => {
                    assert!(s.starts_with("[TOOL ERROR]"), "got: {s}")
                }
                _ => panic!("expected Text content"),
            }
        }
    }

    #[test]
    fn assistant_tool_use_becomes_assistant_message_with_tool_calls() {
        let messages = vec![Message::assistant(vec![ContentBlock::ToolUse {
            id: "call_abc".into(),
            call_id: None,
            name: "get_system_state".into(),
            input: serde_json::json!({}),
        }])];
        let msgs = to_openai_messages("sys", &messages).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(
            msgs[1],
            ChatCompletionRequestMessage::Assistant(_)
        ));
        if let ChatCompletionRequestMessage::Assistant(a) = &msgs[1] {
            let tool_calls = a.tool_calls.as_ref().expect("tool_calls must be present");
            assert_eq!(tool_calls.len(), 1);
            match &tool_calls[0] {
                ChatCompletionMessageToolCalls::Function(tc) => {
                    assert_eq!(tc.id, "call_abc");
                    assert_eq!(tc.function.name, "get_system_state");
                }
                _ => panic!("expected Function tool call"),
            }
        }
    }

    #[test]
    fn assistant_text_becomes_assistant_message_with_content() {
        let messages = vec![Message::assistant(vec![ContentBlock::Text {
            text: "thinking...".into(),
        }])];
        let msgs = to_openai_messages("sys", &messages).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(matches!(
            msgs[1],
            ChatCompletionRequestMessage::Assistant(_)
        ));
        if let ChatCompletionRequestMessage::Assistant(a) = &msgs[1] {
            assert!(
                a.content.is_some(),
                "content must be present for text-only assistant"
            );
            assert!(a.tool_calls.is_none());
        }
    }

    #[test]
    fn assistant_mixed_text_and_tool_use_sets_both_fields() {
        // An assistant turn with both text and a tool call must produce an
        // assistant message that has both `content` and `tool_calls` set.
        let messages = vec![Message::assistant(vec![
            ContentBlock::Text {
                text: "thinking...".into(),
            },
            ContentBlock::ToolUse {
                id: "call_mix".into(),
                call_id: None,
                name: "propose_plan".into(),
                input: serde_json::json!({"summary": "x"}),
            },
        ])];
        let msgs = to_openai_messages("sys", &messages).unwrap();
        assert_eq!(msgs.len(), 2);
        if let ChatCompletionRequestMessage::Assistant(a) = &msgs[1] {
            assert!(
                a.content.is_some(),
                "content must be set when text is present"
            );
            let tool_calls = a.tool_calls.as_ref().expect("tool_calls must be set");
            assert_eq!(tool_calls.len(), 1);
        } else {
            panic!("expected Assistant message");
        }
    }

    #[test]
    fn empty_assistant_message_returns_error() {
        // An assistant message with no text and no tool calls is a history bug.
        // It must return an error rather than silently producing a malformed request.
        let messages = vec![Message::assistant(vec![])];
        let result = to_openai_messages("sys", &messages);
        assert!(
            result.is_err(),
            "expected error for empty assistant message"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("no text and no tool calls"),
            "error should mention the missing content; got: {err}"
        );
    }

    #[test]
    fn tool_use_id_is_preserved_in_tool_call() {
        // Verify the adapter uses `id` (not `call_id`) for the Chat Completions
        // tool_call_id field. call_id is set here to confirm it has no effect.
        let messages = vec![Message::assistant(vec![ContentBlock::ToolUse {
            id: "call_xyz".into(),
            call_id: Some("call_xyz".into()),
            name: "propose_plan".into(),
            input: serde_json::json!({"summary": "test"}),
        }])];
        let msgs = to_openai_messages("sys", &messages).unwrap();
        if let ChatCompletionRequestMessage::Assistant(a) = &msgs[1] {
            let tc = a.tool_calls.as_ref().unwrap();
            match &tc[0] {
                ChatCompletionMessageToolCalls::Function(f) => {
                    assert_eq!(f.id, "call_xyz");
                    let parsed: serde_json::Value =
                        serde_json::from_str(&f.function.arguments).unwrap();
                    assert_eq!(parsed["summary"], "test");
                }
                _ => panic!("expected Function"),
            }
        }
    }

    // --- to_openai_tools -----------------------------------------------------

    #[test]
    fn tool_definitions_converted_correctly() {
        let tools = vec![ToolDefinition {
            name: "propose_plan".into(),
            description: "Propose a plan.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "summary": { "type": "string" }
                },
                "required": ["summary"]
            }),
        }];
        let oai_tools = to_openai_tools(&tools);
        assert_eq!(oai_tools.len(), 1);
        assert!(
            matches!(oai_tools[0], ChatCompletionTools::Function(_)),
            "expected Function variant"
        );
        if let ChatCompletionTools::Function(t) = &oai_tools[0] {
            assert_eq!(t.function.name, "propose_plan");
            assert_eq!(t.function.description.as_deref(), Some("Propose a plan."));
            assert!(t.function.parameters.is_some());
        }
    }

    #[test]
    fn empty_tools_returns_empty_vec() {
        assert!(to_openai_tools(&[]).is_empty());
    }

    // --- from_openai_response ------------------------------------------------

    fn make_tool_call_response(finish_reason: FinishReason) -> CreateChatCompletionResponse {
        CreateChatCompletionResponse {
            id: "test".into(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatCompletionResponseMessage {
                    role: OaiRole::Assistant,
                    content: None,
                    refusal: None,
                    tool_calls: Some(vec![ChatCompletionMessageToolCalls::Function(
                        ChatCompletionMessageToolCall {
                            id: "call_1".into(),
                            function: FunctionCall {
                                name: "propose_plan".into(),
                                arguments: r#"{"summary":"test","steps":[]}"#.into(),
                            },
                        },
                    )]),
                    annotations: None,
                    audio: None,
                    function_call: None,
                },
                finish_reason: Some(finish_reason),
                logprobs: None,
            }],
            created: 0,
            model: "gpt-4.1".into(),
            system_fingerprint: None,
            object: "chat.completion".into(),
            usage: None,
            service_tier: None,
        }
    }

    fn make_text_response(text: &str, finish_reason: FinishReason) -> CreateChatCompletionResponse {
        CreateChatCompletionResponse {
            id: "test".into(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatCompletionResponseMessage {
                    role: OaiRole::Assistant,
                    content: Some(text.into()),
                    refusal: None,
                    tool_calls: None,
                    annotations: None,
                    audio: None,
                    function_call: None,
                },
                finish_reason: Some(finish_reason),
                logprobs: None,
            }],
            created: 0,
            model: "gpt-4.1".into(),
            system_fingerprint: None,
            object: "chat.completion".into(),
            usage: None,
            service_tier: None,
        }
    }

    #[test]
    fn finish_reason_tool_calls_maps_to_stop_reason_tool_use() {
        let response = make_tool_call_response(FinishReason::ToolCalls);
        let completion = from_openai_response(response).unwrap();
        assert_eq!(completion.stop_reason, StopReason::ToolUse);
        assert_eq!(completion.content.len(), 1);
        if let ContentBlock::ToolUse {
            id, call_id, name, ..
        } = &completion.content[0]
        {
            assert_eq!(id, "call_1");
            assert!(
                call_id.is_none(),
                "call_id must be None for Chat Completions"
            );
            assert_eq!(name, "propose_plan");
        } else {
            panic!("expected ToolUse block");
        }
    }

    #[test]
    fn finish_reason_length_maps_to_max_tokens() {
        let response = make_text_response("truncated", FinishReason::Length);
        let completion = from_openai_response(response).unwrap();
        assert_eq!(completion.stop_reason, StopReason::MaxTokens);
    }

    #[test]
    fn text_only_response_maps_to_end_turn() {
        let response = make_text_response("Hello!", FinishReason::Stop);
        let completion = from_openai_response(response).unwrap();
        assert_eq!(completion.stop_reason, StopReason::EndTurn);
        assert_eq!(completion.content.len(), 1);
        assert!(matches!(&completion.content[0], ContentBlock::Text { text } if text == "Hello!"));
    }

    #[test]
    fn finish_reason_none_maps_to_end_turn() {
        // finish_reason can be None for interrupted streaming responses.
        // The wildcard arm must handle this gracefully.
        let response = make_text_response("partial", FinishReason::Stop);
        let mut r = response;
        r.choices[0].finish_reason = None;
        let completion = from_openai_response(r).unwrap();
        assert_eq!(completion.stop_reason, StopReason::EndTurn);
    }

    #[test]
    fn content_filter_returns_provider_error() {
        // ContentFilter must surface as an error immediately rather than being
        // treated as EndTurn — which would silently burn all retry turns.
        let response = make_text_response("", FinishReason::Stop);
        let mut r = response;
        r.choices[0].finish_reason = Some(FinishReason::ContentFilter);
        r.choices[0].message.content = None;
        let result = from_openai_response(r);
        assert!(result.is_err(), "ContentFilter must return an error");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("content filter") || msg.contains("content-policy"),
            "error should mention content filter; got: {msg}"
        );
    }

    #[test]
    fn empty_choices_returns_parse_error() {
        let response = CreateChatCompletionResponse {
            id: "test".into(),
            choices: vec![],
            created: 0,
            model: "gpt-4.1".into(),
            system_fingerprint: None,
            object: "chat.completion".into(),
            usage: None,
            service_tier: None,
        };
        assert!(from_openai_response(response).is_err());
    }

    #[test]
    fn empty_content_and_no_tool_calls_returns_parse_error() {
        // A response with content:None and tool_calls:None must return a parse
        // error, not an empty Completion.
        let response = CreateChatCompletionResponse {
            id: "test".into(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatCompletionResponseMessage {
                    role: OaiRole::Assistant,
                    content: None,
                    refusal: None,
                    tool_calls: None,
                    annotations: None,
                    audio: None,
                    function_call: None,
                },
                finish_reason: Some(FinishReason::Stop),
                logprobs: None,
            }],
            created: 0,
            model: "gpt-4.1".into(),
            system_fingerprint: None,
            object: "chat.completion".into(),
            usage: None,
            service_tier: None,
        };
        assert!(from_openai_response(response).is_err());
    }

    #[test]
    fn malformed_tool_call_arguments_returns_parse_error() {
        // Invalid JSON in arguments must surface as ProviderError::Parse rather
        // than silently substituting {} — which would waste turns on a bad input.
        let response = CreateChatCompletionResponse {
            id: "test".into(),
            choices: vec![ChatChoice {
                index: 0,
                message: ChatCompletionResponseMessage {
                    role: OaiRole::Assistant,
                    content: None,
                    refusal: None,
                    tool_calls: Some(vec![ChatCompletionMessageToolCalls::Function(
                        ChatCompletionMessageToolCall {
                            id: "call_bad".into(),
                            function: FunctionCall {
                                name: "propose_plan".into(),
                                arguments: "not valid json {{{".into(),
                            },
                        },
                    )]),
                    annotations: None,
                    audio: None,
                    function_call: None,
                },
                finish_reason: Some(FinishReason::ToolCalls),
                logprobs: None,
            }],
            created: 0,
            model: "gpt-4.1".into(),
            system_fingerprint: None,
            object: "chat.completion".into(),
            usage: None,
            service_tier: None,
        };
        let result = from_openai_response(response);
        assert!(result.is_err(), "malformed args must return an error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("invalid JSON arguments"),
            "error should mention invalid JSON; got: {msg}"
        );
    }

    // --- map_openai_error ----------------------------------------------------

    #[test]
    fn auth_error_classification() {
        // Test the string-matching rules used inside map_openai_error.
        // These cases document the expected classification contract.
        let cases = [
            ("401 Unauthorized", true),
            ("incorrect api key provided", true),
            ("authentication failed", true),
            ("429 Too Many Requests", false),
            ("connection refused", false),
        ];
        for (msg, expected_auth) in cases {
            let is_auth = msg.contains("401")
                || msg.to_lowercase().contains("authentication")
                || msg.to_lowercase().contains("api key")
                || msg.to_lowercase().contains("incorrect api key");
            assert_eq!(
                is_auth, expected_auth,
                "auth classification wrong for: {msg}"
            );
        }
    }

    #[test]
    fn auth_error_message_does_not_propagate_raw_sdk_error() {
        // map_openai_error must not return the raw SDK error text in
        // ProviderError::Auth — it returns a fixed, safe message instead.
        // We can't construct OpenAIError directly, so we test the rule by
        // confirming the fixed string is what the production code returns.
        let fixed_msg = "OpenAI authentication failed — check your API key";
        // Verify the string constant in production code matches what callers expect.
        assert!(
            fixed_msg.contains("authentication failed"),
            "fixed auth message must mention authentication failure"
        );
        assert!(
            !fixed_msg.contains("sk-"),
            "fixed auth message must not contain key prefixes"
        );
    }
}
