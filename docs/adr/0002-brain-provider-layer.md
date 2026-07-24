# ADR 0002: Brain Provider Layer

## Status

Accepted.

## Context

`sysknife-brain` needs to talk to an LLM to plan system actions.
Different users will have different LLM setups: some will use the
Anthropic API, others will run a local model via Ollama, and future
contributors may want to add other providers.

Additionally, the API key must never be visible outside `sysknife-brain`
to prevent accidental logging or exposure through `sysknife-shell`.

## Decision

`sysknife-brain` exposes a single `LlmProvider` trait:

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<Completion, ProviderError>;
}
```

Two implementations ship with the crate:

- **`AnthropicProvider`** — POST `/v1/messages` with `input_schema`
  tool definitions (Anthropic wire format).
- **`OllamaProvider`** — POST `/v1/chat/completions` with OpenAI
  function-calling format (`parameters` field, `role: "tool"`
  messages).

`LlmPlanner::from_config(BrainConfig, Box<dyn StateClient>)` builds
the provider from environment-derived config, keeping the API key
inside `sysknife-brain`. `ProviderConfig` and `BrainConfig.provider` are
`pub(crate)` so the shell cannot read credentials.

`BrainConfig::from_env()` validates inputs at the boundary:

- `SYSKNIFE_BRAIN_MAX_TURNS` must be a positive integer when set.
- `ANTHROPIC_API_KEY` must be non-empty when provider is `anthropic`.

## Alternatives Considered

- **Single hard-coded Anthropic client** — ruled out; excludes local
  models and makes the project inaccessible to contributors without
  API keys.
- **Runtime plugin loading (`.so` / WASM)** — too complex for v0;
  the two-implementation trait covers the main use cases.

## Consequences

- Adding a new provider requires implementing `LlmProvider` and a new
  `ProviderConfig` variant; no changes to `LlmPlanner`.
- The shell layer cannot accidentally read or log API keys.
- Integration tests use `MockProvider` — no network calls in CI.

## Amendment (2026-07-23)

The original decision above described the two providers that shipped at the
time (Anthropic, Ollama). The `LlmProvider` trait design anticipated more —
see "Consequences" — and the provider set has since grown to **eight**:
`anthropic`, `ollama`, `openai`, `gemini`, `groq`, `deepseek`, `mistral`, and
`xai` (see `crates/sysknife-brain/src/config.rs`). Each new provider was a
pure addition — a new `ProviderConfig` variant and a `require_api_key`-backed
`from_env()` arm — with no change to `LlmPlanner` or the trait itself,
confirming the extensibility this ADR designed for. The original Decision
and Alternatives Considered sections above are left as written for historical
context; this amendment records the outcome.
