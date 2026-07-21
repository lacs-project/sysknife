'use strict';

/**
 * providers.js — the single source of truth for the LLM providers the setup
 * wizard offers.
 *
 * These three maps must stay in lock-step with the engine (sysknife-brain):
 *   - the provider list          → crates/sysknife-brain/src/config.rs (from_env match)
 *   - the API-key env var names   → crates/sysknife-brain/src/config.rs (require_api_key)
 *   - the default model per provider → crates/sysknife-brain/src/config.rs (DEFAULT_*_MODEL)
 *
 * Extracted from index.js so the invariants above are unit-testable without
 * executing the wizard (mirrors mcp-config.js). If the engine gains a provider,
 * add it here and the wizard's provider prompt, key prompt, and model prompt all
 * pick it up automatically.
 */

/** Providers the wizard prompts for. Index 0 (`openai`) is the default. */
const PROVIDERS = [
  'openai',
  'anthropic',
  'gemini',
  'ollama',
  'groq',
  'deepseek',
  'mistral',
  'xai',
];

/**
 * Default model per provider. Must match the DEFAULT_*_MODEL constants in
 * crates/sysknife-brain/src/config.rs so the wizard's suggestion equals what the
 * engine would pick on its own.
 */
const MODEL_DEFAULTS = {
  openai:   'gpt-4.1',
  anthropic:'claude-sonnet-4-6',
  gemini:   'gemini-2.5-pro',
  ollama:   'qwen3:8b',
  groq:     'llama-3.3-70b-versatile',
  deepseek: 'deepseek-chat',
  mistral:  'mistral-large-latest',
  xai:      'grok-3',
};

/**
 * API-key environment variable per provider (null when the provider needs no
 * key). Names must match `require_api_key(...)` in the engine's config.rs.
 */
const API_KEY_VARS = {
  openai:   'OPENAI_API_KEY',
  anthropic:'ANTHROPIC_API_KEY',
  gemini:   'GEMINI_API_KEY',
  ollama:   null,
  groq:     'GROQ_API_KEY',
  deepseek: 'DEEPSEEK_API_KEY',
  mistral:  'MISTRAL_API_KEY',
  xai:      'XAI_API_KEY',
};

module.exports = { PROVIDERS, MODEL_DEFAULTS, API_KEY_VARS };
