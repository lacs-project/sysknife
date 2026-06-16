//! Brain configuration loaded from environment variables.
//!
//! Resolution order:
//!   1. `SYSKNIFE_LLM_PROVIDER` — "anthropic" | "ollama" | "openai" | "gemini" | "groq" | "deepseek" | "mistral" | "xai"
//!      If unset: "anthropic" when `ANTHROPIC_API_KEY` is set and non-whitespace,
//!      else "ollama". Whitespace-only values are treated as absent.
//!   2. `ANTHROPIC_API_KEY` — required when provider is anthropic. Must be non-empty.
//!      Other providers require their own key env var (e.g. `OPENAI_API_KEY`, `GEMINI_API_KEY`).
//!   3. `SYSKNIFE_LLM_MODEL` — overrides the provider default model.
//!   4. `SYSKNIFE_ANTHROPIC_URL` — overrides the Anthropic base URL (default: <https://api.anthropic.com>).
//!   5. `SYSKNIFE_OLLAMA_URL` — overrides the Ollama base URL (default: http://localhost:11434).
//!   6. `SYSKNIFE_BRAIN_MAX_TURNS` — planning loop turn limit (default: 10). Must be >= 1 when set.

use std::fmt;

pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-4-6";
pub const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
/// Default Ollama model. qwen3:8b produces the most reliable tool
/// calls in the planning loop; the planner auto-enables thinking mode
/// for it via `THINKING_MODEL_PREFIXES` in `planner.rs`. CPU-only
/// hosts should either disable thinking (`ollama_think = false` in
/// `config.toml`) or pick a smaller non-thinking model —
/// see `HACKING.md` §8 for the full matrix.
pub const DEFAULT_OLLAMA_MODEL: &str = "qwen3:8b";
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";
pub const DEFAULT_OPENAI_MODEL: &str = "gpt-4.1";
pub const DEFAULT_GEMINI_MODEL: &str = "gemini-2.0-flash";
pub const DEFAULT_GROQ_MODEL: &str = "llama-3.3-70b-versatile";
pub const DEFAULT_DEEPSEEK_MODEL: &str = "deepseek-chat";
pub const DEFAULT_MISTRAL_MODEL: &str = "mistral-large-latest";
pub const DEFAULT_XAI_MODEL: &str = "grok-3";
pub const DEFAULT_MAX_TURNS: usize = 10;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Configuration for the planning LLM.
///
/// **Not `Clone`.**  The inner `ProviderConfig` holds the API key in
/// plaintext (rig's client builders take `String`, not `SecretString`), so
/// every clone would silently materialise an extra copy of the secret in
/// memory.  Keeping `BrainConfig` move-only forces every consumer to think
/// about who owns the key — the planner consumes it once in
/// `LlmPlanner::from_config` and the value is dropped immediately afterwards.
pub struct BrainConfig {
    pub(crate) provider: ProviderConfig,
    pub max_turns: usize,
}

/// Per-provider client configuration.  See [`BrainConfig`] for why this is
/// not `Clone`.
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum ProviderConfig {
    Anthropic {
        /// Never logged or exposed in error messages.
        api_key: String,
        model: String,
        base_url: String,
    },
    Ollama {
        base_url: String,
        model: String,
    },
    OpenAI {
        api_key: String,
        model: String,
    },
    Gemini {
        api_key: String,
        model: String,
    },
    Groq {
        api_key: String,
        model: String,
    },
    DeepSeek {
        api_key: String,
        model: String,
    },
    Mistral {
        api_key: String,
        model: String,
    },
    XAI {
        api_key: String,
        model: String,
    },
}

/// Custom Debug impl to redact the API key.
impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderConfig::Anthropic {
                model, base_url, ..
            } => f
                .debug_struct("Anthropic")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .field("base_url", base_url)
                .finish(),
            ProviderConfig::Ollama { base_url, model } => f
                .debug_struct("Ollama")
                .field("base_url", base_url)
                .field("model", model)
                .finish(),
            ProviderConfig::OpenAI { model, .. } => f
                .debug_struct("OpenAI")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .finish(),
            ProviderConfig::Gemini { model, .. } => f
                .debug_struct("Gemini")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .finish(),
            ProviderConfig::Groq { model, .. } => f
                .debug_struct("Groq")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .finish(),
            ProviderConfig::DeepSeek { model, .. } => f
                .debug_struct("DeepSeek")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .finish(),
            ProviderConfig::Mistral { model, .. } => f
                .debug_struct("Mistral")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .finish(),
            ProviderConfig::XAI { model, .. } => f
                .debug_struct("xAI")
                .field("api_key", &"[redacted]")
                .field("model", model)
                .finish(),
        }
    }
}

impl fmt::Debug for BrainConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrainConfig")
            .field("provider", &self.provider)
            .field("max_turns", &self.max_turns)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("ANTHROPIC_API_KEY is required when provider is 'anthropic' and must not be empty")]
    MissingAnthropicKey,

    #[error(
        "API key environment variable '{0}' is required for provider '{1}' and must not be empty"
    )]
    MissingApiKey(String, String),

    #[error("unknown provider '{0}': expected one of: anthropic, ollama, openai, gemini, groq, deepseek, mistral, xai")]
    UnknownProvider(String),

    #[error("SYSKNIFE_BRAIN_MAX_TURNS must be a positive integer (>= 1), got '{0}'")]
    InvalidMaxTurns(String),
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Read a required API key from an environment variable, returning
/// `ConfigError::MissingApiKey` if absent or whitespace-only.
fn require_api_key(env_var: &str, provider: &str) -> Result<String, ConfigError> {
    std::env::var(env_var)
        .ok()
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| ConfigError::MissingApiKey(env_var.into(), provider.into()))
}

impl BrainConfig {
    /// Load from environment variables.
    ///
    /// Returns `Err(ConfigError::InvalidMaxTurns)` if `SYSKNIFE_BRAIN_MAX_TURNS` is
    /// set to a non-positive integer or an unparseable value. Unset → default of 10.
    ///
    /// Returns `Err(ConfigError::MissingAnthropicKey)` if the provider is
    /// `anthropic` and `ANTHROPIC_API_KEY` is absent or empty.
    #[must_use = "config errors must be handled; ignoring them silently falls back to wrong provider"]
    pub fn from_env() -> Result<Self, ConfigError> {
        let model_override = std::env::var("SYSKNIFE_LLM_MODEL").ok();

        let max_turns = match std::env::var("SYSKNIFE_BRAIN_MAX_TURNS") {
            Err(_) => DEFAULT_MAX_TURNS, // not set → use default
            Ok(raw) => {
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| ConfigError::InvalidMaxTurns(raw.clone()))?;
                if parsed == 0 {
                    return Err(ConfigError::InvalidMaxTurns(raw));
                }
                parsed
            }
        };

        let provider_name = std::env::var("SYSKNIFE_LLM_PROVIDER").unwrap_or_else(|_| {
            // Auto-detect: use anthropic only when a non-whitespace key is present.
            // A whitespace-only key would pass is_ok() but fail validation below,
            // giving a confusing error. Unset ANTHROPIC_API_KEY to force Ollama.
            if std::env::var("ANTHROPIC_API_KEY")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
            {
                "anthropic".into()
            } else {
                "ollama".into()
            }
        });

        let provider = match provider_name.to_lowercase().as_str() {
            "anthropic" => {
                let api_key = std::env::var("ANTHROPIC_API_KEY")
                    .ok()
                    .filter(|k| !k.trim().is_empty())
                    .ok_or(ConfigError::MissingAnthropicKey)?;
                let base_url = std::env::var("SYSKNIFE_ANTHROPIC_URL")
                    .unwrap_or_else(|_| DEFAULT_ANTHROPIC_BASE_URL.into());
                ProviderConfig::Anthropic {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_ANTHROPIC_MODEL.into()),
                    base_url,
                }
            }
            "ollama" => {
                let base_url = std::env::var("SYSKNIFE_OLLAMA_URL")
                    .unwrap_or_else(|_| DEFAULT_OLLAMA_BASE_URL.into());
                ProviderConfig::Ollama {
                    base_url,
                    model: model_override.unwrap_or_else(|| DEFAULT_OLLAMA_MODEL.into()),
                }
            }
            "openai" => {
                let api_key = require_api_key("OPENAI_API_KEY", "openai")?;
                ProviderConfig::OpenAI {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_OPENAI_MODEL.into()),
                }
            }
            "gemini" => {
                let api_key = require_api_key("GEMINI_API_KEY", "gemini")?;
                ProviderConfig::Gemini {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_GEMINI_MODEL.into()),
                }
            }
            "groq" => {
                let api_key = require_api_key("GROQ_API_KEY", "groq")?;
                ProviderConfig::Groq {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_GROQ_MODEL.into()),
                }
            }
            "deepseek" => {
                let api_key = require_api_key("DEEPSEEK_API_KEY", "deepseek")?;
                ProviderConfig::DeepSeek {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_DEEPSEEK_MODEL.into()),
                }
            }
            "mistral" => {
                let api_key = require_api_key("MISTRAL_API_KEY", "mistral")?;
                ProviderConfig::Mistral {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_MISTRAL_MODEL.into()),
                }
            }
            "xai" => {
                let api_key = require_api_key("XAI_API_KEY", "xai")?;
                ProviderConfig::XAI {
                    api_key,
                    model: model_override.unwrap_or_else(|| DEFAULT_XAI_MODEL.into()),
                }
            }
            other => return Err(ConfigError::UnknownProvider(other.into())),
        };

        Ok(Self {
            provider,
            max_turns,
        })
    }

    /// Returns the provider name string (e.g. `"anthropic"`, `"ollama"`, `"openai"`).
    pub fn provider_name(&self) -> &str {
        match &self.provider {
            ProviderConfig::Anthropic { .. } => "anthropic",
            ProviderConfig::Ollama { .. } => "ollama",
            ProviderConfig::OpenAI { .. } => "openai",
            ProviderConfig::Gemini { .. } => "gemini",
            ProviderConfig::Groq { .. } => "groq",
            ProviderConfig::DeepSeek { .. } => "deepseek",
            ProviderConfig::Mistral { .. } => "mistral",
            ProviderConfig::XAI { .. } => "xai",
        }
    }

    /// Returns the model identifier string (e.g. `"claude-sonnet-4-6"` or `"qwen3:8b"`).
    pub fn model_name(&self) -> &str {
        match &self.provider {
            ProviderConfig::Anthropic { model, .. }
            | ProviderConfig::Ollama { model, .. }
            | ProviderConfig::OpenAI { model, .. }
            | ProviderConfig::Gemini { model, .. }
            | ProviderConfig::Groq { model, .. }
            | ProviderConfig::DeepSeek { model, .. }
            | ProviderConfig::Mistral { model, .. }
            | ProviderConfig::XAI { model, .. } => model,
        }
    }

    /// Ollama with defaults — used when no API key is configured.
    pub fn ollama_defaults() -> Self {
        Self {
            provider: ProviderConfig::Ollama {
                base_url: DEFAULT_OLLAMA_BASE_URL.into(),
                model: DEFAULT_OLLAMA_MODEL.into(),
            },
            max_turns: DEFAULT_MAX_TURNS,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_provider_returns_error() {
        // Validates ConfigError::UnknownProvider message formatting only
        // and does not set env vars, so no mutex is needed.
        let err = ConfigError::UnknownProvider("foobar".into());
        assert!(err.to_string().contains("foobar"));
    }

    #[test]
    fn ollama_defaults_is_valid() {
        let cfg = BrainConfig::ollama_defaults();
        assert!(matches!(cfg.provider, ProviderConfig::Ollama { .. }));
        assert_eq!(cfg.max_turns, DEFAULT_MAX_TURNS);
    }

    #[test]
    fn debug_redacts_api_key() {
        let cfg = ProviderConfig::Anthropic {
            api_key: "sk-secret-key".into(),
            model: "claude-sonnet-4-6".into(),
            base_url: DEFAULT_ANTHROPIC_BASE_URL.into(),
        };
        let debug_str = format!("{cfg:?}");
        assert!(!debug_str.contains("sk-secret-key"));
        assert!(debug_str.contains("[redacted]"));
    }

    // -- InvalidMaxTurns -------------------------------------------------------

    #[test]
    fn invalid_max_turns_error_message_includes_value() {
        let err = ConfigError::InvalidMaxTurns("0".into());
        assert!(err.to_string().contains("0"), "got: {err}");
    }

    #[test]
    fn invalid_max_turns_error_message_includes_non_numeric() {
        let err = ConfigError::InvalidMaxTurns("abc".into());
        assert!(err.to_string().contains("abc"), "got: {err}");
    }

    // -- env-var isolation tests ----------------------------------------------
    // These tests mutate process env vars and must not run concurrently.
    // A crate-level mutex ensures sequential execution.

    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn from_env_max_turns_zero_returns_error() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
            std::env::set_var("SYSKNIFE_BRAIN_MAX_TURNS", "0");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        assert!(
            matches!(result, Err(ConfigError::InvalidMaxTurns(_))),
            "expected InvalidMaxTurns, got: {result:?}"
        );
    }

    #[test]
    fn from_env_max_turns_non_numeric_returns_error() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
            std::env::set_var("SYSKNIFE_BRAIN_MAX_TURNS", "not-a-number");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        assert!(
            matches!(result, Err(ConfigError::InvalidMaxTurns(_))),
            "expected InvalidMaxTurns, got: {result:?}"
        );
    }

    #[test]
    fn from_env_auto_detects_anthropic_when_api_key_present() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::set_var("ANTHROPIC_API_KEY", "sk-test-key");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_ANTHROPIC_URL");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("ANTHROPIC_API_KEY");
        }
        let cfg = result.expect("auto-detect should select anthropic when key is present");
        assert!(
            matches!(cfg.provider, ProviderConfig::Anthropic { .. }),
            "expected Anthropic provider"
        );
    }

    #[test]
    fn from_env_whitespace_api_key_does_not_auto_detect_anthropic() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::set_var("ANTHROPIC_API_KEY", "   ");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("ANTHROPIC_API_KEY");
        }
        // whitespace-only key should fall through to Ollama, not fail with MissingAnthropicKey
        let cfg = result.expect("whitespace key should fall back to Ollama");
        assert!(
            matches!(cfg.provider, ProviderConfig::Ollama { .. }),
            "expected Ollama fallback for whitespace-only key"
        );
    }

    #[test]
    fn from_env_empty_api_key_returns_missing_key() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "anthropic");
            std::env::set_var("ANTHROPIC_API_KEY", "");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_ANTHROPIC_URL");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("ANTHROPIC_API_KEY");
        }
        assert!(
            matches!(result, Err(ConfigError::MissingAnthropicKey)),
            "expected MissingAnthropicKey for empty key, got: {result:?}"
        );
    }

    #[test]
    fn from_env_ollama_explicit_builds_config() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "ollama");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
        }
        let cfg = result.expect("ollama config should succeed");
        assert!(matches!(cfg.provider, ProviderConfig::Ollama { .. }));
        assert_eq!(cfg.max_turns, DEFAULT_MAX_TURNS);
    }

    #[test]
    fn from_env_model_override_is_applied() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "ollama");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::set_var("SYSKNIFE_LLM_MODEL", "custom-model");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
        }
        let cfg = result.expect("model override should not fail");
        if let ProviderConfig::Ollama { model, .. } = cfg.provider {
            assert_eq!(model, "custom-model");
        } else {
            panic!("expected Ollama provider");
        }
    }

    #[test]
    fn from_env_max_turns_valid_override() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "ollama");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
            std::env::set_var("SYSKNIFE_BRAIN_MAX_TURNS", "3");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let cfg = result.expect("config with max_turns=3 should succeed");
        assert_eq!(cfg.max_turns, 3);
    }

    #[test]
    fn from_env_anthropic_url_override_is_applied() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "anthropic");
            std::env::set_var("ANTHROPIC_API_KEY", "sk-test");
            std::env::set_var("SYSKNIFE_ANTHROPIC_URL", "https://proxy.internal");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("SYSKNIFE_ANTHROPIC_URL");
        }
        let cfg = result.expect("anthropic config with url override should succeed");
        if let ProviderConfig::Anthropic { base_url, .. } = cfg.provider {
            assert_eq!(base_url, "https://proxy.internal");
        } else {
            panic!("expected Anthropic provider");
        }
    }

    #[test]
    fn from_env_ollama_url_override_is_applied() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "ollama");
            std::env::remove_var("ANTHROPIC_API_KEY");
            std::env::remove_var("SYSKNIFE_LLM_MODEL");
            std::env::set_var("SYSKNIFE_OLLAMA_URL", "http://gpu-box.local:11434");
            std::env::remove_var("SYSKNIFE_BRAIN_MAX_TURNS");
        }
        let result = BrainConfig::from_env();
        unsafe {
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
            std::env::remove_var("SYSKNIFE_OLLAMA_URL");
        }
        let cfg = result.expect("ollama config with url override should succeed");
        if let ProviderConfig::Ollama { base_url, .. } = cfg.provider {
            assert_eq!(base_url, "http://gpu-box.local:11434");
        } else {
            panic!("expected Ollama provider");
        }
    }
}
