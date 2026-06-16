# Configuration reference

SysKnife reads configuration from three places, in **lowest-to-highest
priority**:

1. **Built-in defaults** — compiled into `sysknife-brain` and `sysknife-core`
2. **`~/.config/sysknife/config.toml`** — optional, user-owned
3. **Environment variables** — always win

Set whatever's stable for your install in `config.toml`; override with env
vars when you need to (CI runs, ad-hoc experiments, distro packagers).

## `config.toml` reference

Path: `$XDG_CONFIG_HOME/sysknife/config.toml`, falling back to
`~/.config/sysknife/config.toml`. The daemon and CLI read this on every
startup; the GUI reloads it after the wizard finishes.

```toml
# ─── [daemon] ────────────────────────────────────────────────────────
[daemon]
# Unix socket path the daemon listens on. CLI / shell connect here.
socket   = "/run/sysknife/daemon.sock"
# SQLite database path for the local audit log.
# Production deployments should switch to [storage] backend = "postgres"
# (see below).
database = "/var/lib/sysknife/daemon.sqlite"

# ─── [llm] ───────────────────────────────────────────────────────────
[llm]
provider     = "ollama"          # ollama | anthropic | openai | gemini |
                                 # groq | deepseek | mistral | xai
model        = "qwen3:8b"        # provider-specific model identifier
ollama_url   = "http://localhost:11434"
anthropic_url = "https://api.anthropic.com"
max_turns    = 10                # planning loop turn limit (>= 1)

# Optional: override the auto-detected thinking mode for Ollama.
# Default: auto-detect from the model name (qwen3 / qwq / deepseek-r → true).
# Set to `false` on CPU-only hosts running thinking models — thinking
# traces exceed Ollama's internal request timeout on 4 vCPUs.
# ollama_think = false

# ─── [storage] ───────────────────────────────────────────────────────
# Audit-log backend. Default (absent or backend = "sqlite") uses the
# local rusqlite store at [daemon].database. Production deployments
# should set backend = "postgres" — the SQLite path dies with the host.
[storage]
backend = "postgres"
url     = "postgres://sysknife:${PG_PASSWORD}@db.example.com:5432/audit?sslmode=verify-full"

[storage.pool]
max_connections          = 8
acquire_timeout_secs     = 10
statement_cache_capacity = 100   # set to 0 for Supabase pooler / CockroachDB

# ─── [policy] ────────────────────────────────────────────────────────
# Per-action risk-level overrides. Map from action name → risk level
# ("Low" | "Medium" | "High"). Validated at startup; unknown action
# names or attempted downgrades are fatal — overrides may only RAISE
# the minimum role required, never lower it.
[policy.risk_overrides]
InstallFlatpak = "High"     # require Admin in this org (default: Medium/Dev)

# ─── [audit.forward] ─────────────────────────────────────────────────
# Optional SIEM forwarding. Best-effort — never blocks daemon execution.
# Phase 1 ships RFC 5424 syslog over UDP; CEF and NDJSON-over-TCP
# arrive in follow-up PRs.
[audit.forward.syslog]
host     = "siem.internal:514"
facility = 1                 # 1 = user-level (default)
```

## Environment variables

Env vars **always win** over `config.toml`. Useful for CI runs, distro
packagers, and ad-hoc experiments. Variable names mirror the config
file's section.field path.

| Variable | Default | What it sets |
|---|---|---|
| `SYSKNIFE_LISTEN_URI` | `unix:///run/sysknife/daemon.sock` | Daemon socket / vsock URI |
| `SYSKNIFE_DATABASE_PATH` | `/var/lib/sysknife/daemon.sqlite` | SQLite audit log path |
| `SYSKNIFE_LLM_PROVIDER` | auto-detect | LLM provider name (8 supported) |
| `SYSKNIFE_LLM_MODEL` | provider default | Model identifier |
| `SYSKNIFE_OLLAMA_URL` | `http://localhost:11434` | Ollama base URL |
| `SYSKNIFE_OLLAMA_THINK` | auto-detect | `true` / `false` thinking-mode override |
| `SYSKNIFE_ANTHROPIC_URL` | `https://api.anthropic.com` | Anthropic base URL |
| `SYSKNIFE_BRAIN_MAX_TURNS` | `10` | Planning loop turn limit |
| `SYSKNIFE_MAX_RPM` | `20` | Rate limit (requests / 60s sliding window) |
| `SYSKNIFE_AUDIT_KEY_PATH` | `<db_dir>/audit-key` | HMAC key path for audit chain |
| `SYSKNIFE_SOCKET` | `unix:///run/sysknife/daemon.sock` | CLI / MCP daemon address |
| `SYSKNIFE_TOKEN` | — | Vsock auth token (when daemon runs in a VM) |
| `XDG_CONFIG_HOME` | `~/.config` | Base path for `sysknife/config.toml` |

### Provider API keys

Required when the corresponding provider is selected:

- `OPENAI_API_KEY` — OpenAI
- `ANTHROPIC_API_KEY` — Anthropic
- `GEMINI_API_KEY` — Gemini
- `GROQ_API_KEY` — Groq
- `DEEPSEEK_API_KEY` — DeepSeek
- `MISTRAL_API_KEY` — Mistral
- `XAI_API_KEY` — xAI
- _none_ — Ollama (local, no key)

## Daemon-only configuration

These environment variables are read only by `sysknife-daemon`, not by
the CLI / shell:

| Variable | Purpose |
|---|---|
| `SYSKNIFE_VSOCK_TOKEN_PATH` | Vsock auth token file (default: `/etc/sysknife/vsock-token`) |
| `SYSKNIFE_AUDIT_KEY_PATH` | HMAC chain key path (default: alongside the database) |

## Validating your config

```sh
sysknife doctor
```

Reports the resolved configuration (socket, host, provider, model, audit
backend) plus a quick chain-integrity check. A failing `doctor` is the
fastest way to catch a typo'd env var or a bad path.

## Where each setting lives in the source

For maintainers — the canonical types are:

- `crates/sysknife-core/src/config.rs` — `LacsConfig`, `DaemonSection`,
  `LlmSection`, `PolicySection`, `AuditSection`, `StorageSection`,
  `StoragePoolSection`
- `crates/sysknife-brain/src/config.rs` — `BrainConfig`, `ProviderConfig`
- `crates/sysknife-core/src/lib.rs` — `default_listen_uri`,
  `default_database_path`, `prefs_path`

Adding a new config knob: add the field to `LacsConfig`, surface the env
var in `apply_defaults_to_env`, and update this document. A test in
`crates/sysknife-core/src/config.rs` should cover the new field.
