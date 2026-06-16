//! Core LLM provider abstraction.
//!
//! [`LlmProvider`] is the single trait that all LLM backends implement.
//! The types here are the canonical internal representation of messages and
//! completions. Each provider is responsible for serializing to and from its
//! own wire format in `crate::providers`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// A single turn in the planning conversation.
#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: vec![ContentBlock::Text { text: text.into() }],
        }
    }

    pub fn assistant(content: Vec<ContentBlock>) -> Self {
        Self {
            role: Role::Assistant,
            content,
        }
    }

    /// Build a user message carrying one or more tool results.
    pub fn tool_results(results: Vec<ToolResultBlock>) -> Self {
        Self {
            role: Role::User,
            content: results
                .into_iter()
                .map(|r| ContentBlock::ToolResult {
                    tool_use_id: r.tool_use_id,
                    call_id: r.call_id,
                    content: r.content,
                    is_error: r.is_error,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

/// A single content block inside a message.
///
/// Assistant messages may contain `Text` and `ToolUse` blocks.
/// User messages may contain `Text` and `ToolResult` blocks.
#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text {
        text: String,
    },
    ToolUse {
        /// Response-item ID (OpenAI format: `fc_xxx`). Must be echoed verbatim
        /// when reconstructing the assistant turn in the next API call.
        id: String,
        /// Function-call match key (OpenAI format: `call_xxx`). Must appear as
        /// `call_id` in the corresponding `function_call_output` item.
        /// `None` for providers that do not use a separate call ID
        /// (Anthropic, Ollama, Gemini, etc.).
        call_id: Option<String>,
        name: String,
        input: serde_json::Value,
    },
    ToolResult {
        tool_use_id: String,
        /// Mirror of `ContentBlock::ToolUse::call_id` for the same tool call.
        /// Used by the OpenAI Responses API adapter to set `call_id` on the
        /// `function_call_output` item so it matches the originating call.
        call_id: Option<String>,
        content: String,
        is_error: bool,
    },
}

/// Transient struct used when building tool result messages.
pub struct ToolResultBlock {
    pub tool_use_id: String,
    /// Mirror of the originating `ContentBlock::ToolUse::call_id`.
    pub call_id: Option<String>,
    pub content: String,
    pub is_error: bool,
}

// ---------------------------------------------------------------------------
// Tool definition
// ---------------------------------------------------------------------------

/// The description of a tool passed to the LLM.
///
/// Providers convert this into their own wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    /// JSON Schema object describing the tool's input.
    pub input_schema: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------

/// The result of a single LLM `complete` call.
#[derive(Debug, Clone)]
pub struct Completion {
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Async LLM backend abstraction.
///
/// Implementations live in [`crate::providers`].
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a request to the LLM and return the completion.
    ///
    /// `system` is the system prompt. `messages` is the conversation history.
    /// `tools` are the tools available for this turn. `max_tokens` caps output.
    async fn complete(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<Completion, ProviderError>;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("http error {status}: {body}")]
    Http { status: u16, body: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("rate limited")]
    RateLimit,

    #[error("invalid response: {0}")]
    Parse(String),

    #[error("request error: {0}")]
    Request(String),
}
