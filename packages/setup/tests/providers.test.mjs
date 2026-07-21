import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const require = createRequire(import.meta.url);
const { PROVIDERS, MODEL_DEFAULTS, API_KEY_VARS } = require('../providers.js');

// The wizard must offer every provider the engine (sysknife-brain) supports, so
// a user never has to hand-edit config.toml just to pick groq/deepseek/mistral/xai.
// Source of truth: crates/sysknife-brain/src/config.rs (from_env) + planner.rs.
const ENGINE_PROVIDERS = [
  'openai',
  'anthropic',
  'gemini',
  'ollama',
  'groq',
  'deepseek',
  'mistral',
  'xai',
];

test('offers every provider the engine supports', () => {
  for (const p of ENGINE_PROVIDERS) {
    assert.ok(PROVIDERS.includes(p), `PROVIDERS is missing "${p}"`);
  }
  assert.equal(PROVIDERS.length, ENGINE_PROVIDERS.length, 'PROVIDERS has unexpected extras');
});

test('openai stays the first/default provider', () => {
  assert.equal(PROVIDERS[0], 'openai');
});

test('maps each new provider to its engine API-key env var', () => {
  assert.equal(API_KEY_VARS.groq, 'GROQ_API_KEY');
  assert.equal(API_KEY_VARS.deepseek, 'DEEPSEEK_API_KEY');
  assert.equal(API_KEY_VARS.mistral, 'MISTRAL_API_KEY');
  assert.equal(API_KEY_VARS.xai, 'XAI_API_KEY');
  // Existing providers unchanged; ollama needs no key.
  assert.equal(API_KEY_VARS.openai, 'OPENAI_API_KEY');
  assert.equal(API_KEY_VARS.anthropic, 'ANTHROPIC_API_KEY');
  assert.equal(API_KEY_VARS.gemini, 'GEMINI_API_KEY');
  assert.equal(API_KEY_VARS.ollama, null);
});

test('all eight model defaults match the engine defaults', () => {
  // Must equal the DEFAULT_*_MODEL constants in
  // crates/sysknife-brain/src/config.rs (all 8, not just the new 4 — a stale
  // pre-existing default is drift too).
  assert.equal(MODEL_DEFAULTS.openai, 'gpt-4.1');
  assert.equal(MODEL_DEFAULTS.anthropic, 'claude-sonnet-4-6');
  assert.equal(MODEL_DEFAULTS.gemini, 'gemini-2.0-flash');
  assert.equal(MODEL_DEFAULTS.ollama, 'qwen3:8b');
  assert.equal(MODEL_DEFAULTS.groq, 'llama-3.3-70b-versatile');
  assert.equal(MODEL_DEFAULTS.deepseek, 'deepseek-chat');
  assert.equal(MODEL_DEFAULTS.mistral, 'mistral-large-latest');
  assert.equal(MODEL_DEFAULTS.xai, 'grok-3');
});

test('every offered provider has a model default and an api-key entry', () => {
  for (const p of PROVIDERS) {
    assert.ok(MODEL_DEFAULTS[p], `MODEL_DEFAULTS is missing "${p}"`);
    assert.ok(p in API_KEY_VARS, `API_KEY_VARS is missing "${p}"`);
  }
});
