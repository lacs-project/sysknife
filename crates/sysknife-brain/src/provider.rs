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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    User,
    Assistant,
}

/// A single content block inside a message.
///
/// Assistant messages may contain `Text` and `ToolUse` blocks.
/// User messages may contain `Text` and `ToolResult` blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Completion {
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// **No adapter constructs this.** A provider HTTP status is classified by
    /// `providers::classify_status` into [`Auth`](Self::Auth),
    /// [`RateLimit`](Self::RateLimit), or — for every other 4xx and 5xx —
    /// [`Request`](Self::Request). A Groq 400 carrying `tool_use_failed`
    /// arrives as `Request`, and a 500 does too.
    ///
    /// Say so here because a test double built from this variant tests a shape
    /// the system cannot produce. That is not hypothetical: the cassette's
    /// rejection recorder was first written to match `Http { status: 400, .. }`
    /// and passed three new tests while recording nothing at all on a real run.
    /// Reach for `Request` when doubling a provider failure.
    #[error("http error {status}: {body}")]
    Http { status: u16, body: String },

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("rate limited: {0}")]
    RateLimit(String),

    #[error("invalid response: {0}")]
    Parse(String),

    #[error("request error: {0}")]
    Request(String),

    /// A replay found no recorded output for this call. Deliberately a provider
    /// error rather than a silent fallthrough to the live model: a replay that
    /// quietly went to the network would report results the cassette never
    /// contained. See [`crate::cassette`].
    #[error("cassette miss: {0}")]
    CassetteMiss(String),
}

impl ProviderError {
    /// Whether re-issuing the identical request could plausibly succeed.
    ///
    /// The planner's turn loop retries the *model's* mistakes — text where a tool
    /// call belonged, a plan the safety fence rejected — but used to abandon
    /// planning on the first provider-level failure, with most of its turn budget
    /// unused. This is the classification that lets it retry the failures that
    /// deserve it without retrying the ones that never will.
    ///
    /// The two `false` arms matter more than the `true` ones:
    ///
    /// - [`Auth`](Self::Auth) — a wrong key stays wrong. Retrying only delays the
    ///   one message that tells the operator what to fix.
    /// - [`CassetteMiss`](Self::CassetteMiss) — the cassette key is a hash of the
    ///   call, so a retry issues the identical lookup and misses identically. It
    ///   is deterministic by construction; retrying converts an immediate,
    ///   well-explained hermetic-replay failure into a slow one, and under a
    ///   replay-gated CI run it would consume the job timeout printing nothing new.
    pub fn is_retryable(&self) -> bool {
        match self {
            // Truncated or malformed payloads are a transport/serialisation
            // artefact, not a statement about the request.
            ProviderError::Parse(_) => true,
            // Connection reset, DNS blip, timeout.
            ProviderError::Request(_) => true,
            // 5xx is the provider's own fault and usually momentary; 429 means
            // "later", which is exactly what a backoff provides. Every 4xx is a
            // defect in the request just built, and building it again produces
            // the same bytes.
            ProviderError::Http { status, .. } => *status >= 500 || *status == 429,
            ProviderError::RateLimit(_) => true,
            ProviderError::Auth(_) => false,
            ProviderError::CassetteMiss(_) => false,
        }
    }

    /// Whether the provider rejected the *request* because the model named a
    /// tool that does not exist.
    ///
    /// Two callers need this same answer and must never disagree:
    ///
    /// - `planner::tool_call_correction` — the only failure worth re-asking
    ///   about with a correction appended, because resending the same bytes
    ///   reproduces the same malformed answer.
    /// - `cassette::recordable_rejection` — the only failure worth *recording*,
    ///   because it is a deterministic function of the same bytes the cassette
    ///   key hashes. If the recorder kept a smaller set than the retrier, a
    ///   run that needed a retry could never replay; if it kept a larger one, a
    ///   transient failure would be served back for ever.
    ///
    /// Matched on the message, not the variant: no adapter constructs
    /// [`Http`](Self::Http), and Groq's 400 arrives as
    /// [`Request`](Self::Request) via `StatusClass::Other`. Groq words it
    /// `code: "tool_use_failed"` with a message naming the tool it refused —
    /// `attempted to call tool 'json' which was not in request.tools`. Both
    /// halves are matched because providers word it differently and neither
    /// string is one we control.
    pub fn is_invalid_tool_call(&self) -> bool {
        const MARKERS: &[&str] = &["tool_use_failed", "was not in request.tools"];
        // Auth and CassetteMiss are about this process, not the request, and a
        // cassette-miss diagnostic can quote a recorded message verbatim — which
        // would otherwise make a miss look like the rejection it is reporting.
        if matches!(self, Self::Auth(_) | Self::CassetteMiss(_)) {
            return false;
        }
        let text = self.to_string().to_lowercase();
        MARKERS.iter().any(|m| text.contains(&m.to_lowercase()))
    }
}

#[cfg(test)]
mod retryability_tests {
    use super::*;

    #[test]
    fn transient_failures_are_retryable() {
        assert!(ProviderError::Parse("truncated json".into()).is_retryable());
        assert!(ProviderError::Request("connection reset".into()).is_retryable());
        assert!(ProviderError::RateLimit("slow down".into()).is_retryable());
        for status in [500, 502, 503, 504, 429] {
            assert!(
                ProviderError::Http {
                    status,
                    body: String::new()
                }
                .is_retryable(),
                "HTTP {status} says nothing about the request and should be retried"
            );
        }
    }

    #[test]
    fn a_client_error_is_not_retryable() {
        // 4xx describes the request we just built. Building it again produces the
        // same bytes, so a retry is guaranteed to fail the same way.
        for status in [400, 401, 403, 404, 422] {
            assert!(
                !ProviderError::Http {
                    status,
                    body: String::new()
                }
                .is_retryable(),
                "HTTP {status} is a request defect and must not be retried"
            );
        }
    }

    #[test]
    fn auth_failure_is_not_retryable() {
        assert!(!ProviderError::Auth("invalid api key".into()).is_retryable());
    }

    /// The one that does real damage if handled carelessly: the cassette key is a
    /// hash of the call, so a retry issues the identical lookup and misses
    /// identically — turning an immediate hermetic-replay failure into a slow one.
    #[test]
    fn a_cassette_miss_is_never_retryable() {
        assert!(!ProviderError::CassetteMiss("no recorded output".into()).is_retryable());
    }
}
