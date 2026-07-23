# Developer Guide

Welcome to SysKnife. This guide gets you from zero to a running dev
environment and covers everything you need to contribute confidently.

## Read First

- [Architecture overview](architecture.md) — understand the four-crate
  structure and the trust boundary before writing code
- [ADR 0001: System boundaries](adr/0001-system-boundaries.md)
- [ADR 0002: Brain provider layer](adr/0002-brain-provider-layer.md)
- [ADR 0003: IPC wire protocol](adr/0003-ipc-wire-protocol.md)

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust stable | latest stable | [rustup.rs](https://rustup.rs) |
| Node.js | 20+ | [nodejs.org](https://nodejs.org) or your distro |
| pnpm | latest | `npm install -g pnpm` |
| Tauri system deps | — | [tauri.app/start/prerequisites](https://tauri.app/start/prerequisites/) |
| pre-commit | latest | `pip install pre-commit` |

No API key is required to get started. SysKnife auto-detects a local
Ollama instance (`http://localhost:11434`) when no cloud API key is set.
If you do not have Ollama installed, you can still run all unit and
integration tests without it.

## Clone and Set Up

```sh
git clone https://github.com/lacs-project/sysknife
cd sysknife

# Install git hooks (run once)
pip install pre-commit
pre-commit install

# Install frontend dependencies
cd apps/sysknife-shell && pnpm install && cd ../..
```

## Building

```sh
# Build all Rust crates (fast, no linking of the Tauri app)
cargo build --workspace

# Build the Tauri app (includes the GUI)
cd apps/sysknife-shell && pnpm tauri build
```

## Running Tests

These run in under 15 seconds and are required before every push:

```sh
# Rust unit + integration tests
cargo nextest run --workspace --locked

# TypeScript / React tests
cd apps/sysknife-shell && pnpm test && pnpm exec tsc --noEmit
```

See [docs/contributing/testing.md](contributing/testing.md) for the
full test pyramid, including how to run the LLM-driven E2E stories
on your workstation and in a Fedora Atomic VM.

## Running the Full Stack Locally

You need two terminals.

**Terminal 1 — daemon**

```sh
# Starts on /tmp/sysknife-daemon.sock by default.
# Privileged system actions (rpm-ostree, useradd, etc.) require root.
# For development you can run without root — read-only queries still work.
cargo run -p sysknife-daemon
```

**Terminal 2 — shell (GUI)**

```sh
cd apps/sysknife-shell
pnpm tauri dev
```

The shell opens as a desktop window. Type an intent and the daemon
responds. The LLM is auto-detected from your environment.

## Running the E2E Stories on Your Dev Machine

`tests/e2e/dev-stories.sh` runs the 7 read-only user stories without
a VM. It validates that the LLM proposes the correct typed plan — it
does not execute the actions against your host.

```sh
# With an Anthropic key
ANTHROPIC_API_KEY=sk-ant-... tests/e2e/dev-stories.sh

# With an OpenAI key
OPENAI_API_KEY=sk-proj-... tests/e2e/dev-stories.sh

# With local Ollama (must have a tool-capable model pulled)
tests/e2e/dev-stories.sh

# Specific stories only
OPENAI_API_KEY=sk-... tests/e2e/dev-stories.sh 3 6 7
```

Run this tier after any change to `crates/sysknife-brain/src/prompt.rs` or
the planning tools. See the testing guide for full details.

## Inspecting the IPC Protocol

The daemon speaks length-prefixed JSON over a Unix socket. You can
poke it manually without the GUI:

```sh
cargo run -p sysknife-daemon &
socat - UNIX-CONNECT:/tmp/sysknife-daemon.sock
```

Type or paste a JSON message (with a 4-byte LE length prefix). This
is useful for debugging the dispatcher or previewing action output.

## Pre-commit Hooks

Pre-commit runs on every `git commit`. Run all hooks manually before
pushing:

```sh
pre-commit run --all-files
```

Hooks included:

| Hook | What it checks |
|---|---|
| trailing-whitespace | Removes trailing spaces |
| end-of-file-fixer | Ensures files end with a newline |
| check-yaml / check-toml / check-json | Syntax validity |
| no-commit-to-branch | Blocks direct commits to `main` |
| gitleaks | Detects hardcoded secrets |
| cargo fmt | Rust formatting (`--check` mode) |
| cargo check | Workspace compilation |
| tsc --noEmit | TypeScript type checking |
| markdownlint-cli2 | Markdown style |
| yamllint | YAML style |

Intentionally excluded from pre-commit (they run in CI instead):
`cargo clippy` (20–30 s), `cargo nextest run` (minutes), `vitest` (minutes).

## Configuration

Config file: `~/.config/sysknife/config.toml` (created manually, optional):

```toml
[daemon]
socket   = "/run/sysknife/daemon.sock"    # raw path, not URI
database = "/var/lib/sysknife/daemon.sqlite"

[llm]
provider   = "ollama"                 # ollama | anthropic | openai | gemini | groq | deepseek | mistral | xai
model      = "llama3.2:3b"
ollama_url = "http://localhost:11434"
max_turns  = 10
```

Config file values act as defaults. Environment variables always win.

| Variable | Default | Description |
|---|---|---|
| `SYSKNIFE_LISTEN_URI` | `$XDG_RUNTIME_DIR/sysknife/daemon.sock` (prod: `/run/sysknife/daemon.sock`) | Daemon socket URI |
| `SYSKNIFE_DATABASE_PATH` | `$XDG_STATE_HOME/sysknife/daemon.sqlite` (fallback `~/.local/state/sysknife/daemon.sqlite`) | SQLite database path |
| `SYSKNIFE_LLM_PROVIDER` | auto-detect | `anthropic`, `openai`, `gemini`, `ollama`, `groq`, `deepseek`, `mistral`, or `xai` |
| `ANTHROPIC_API_KEY` | — | Required for the Anthropic provider |
| `OPENAI_API_KEY` | — | Required for the OpenAI provider |
| `GEMINI_API_KEY` | — | Required for the Gemini provider |
| `GROQ_API_KEY` | — | Required for the Groq provider |
| `DEEPSEEK_API_KEY` | — | Required for the DeepSeek provider |
| `MISTRAL_API_KEY` | — | Required for the Mistral provider |
| `XAI_API_KEY` | — | Required for the xAI provider |
| `SYSKNIFE_OLLAMA_URL` | `http://localhost:11434` | Ollama base URL |
| `SYSKNIFE_LLM_MODEL` | provider default | Override the model name |
| `SYSKNIFE_BRAIN_MAX_TURNS` | `10` | Planning loop turn limit |

## User Preferences

SysKnife remembers user preferences in `~/.config/sysknife/prefs.md`. The
planner injects them at the start of each `plan_intent()` call.

Preferences are user-stated intentions that inform planning decisions.
Do not store system facts as preferences — those are queried live.

Manage preferences through natural language:

- "Remember that I always prefer vim-enhanced over vim"
- "Forget my vim preference"

Or edit `~/.config/sysknife/prefs.md` directly. Maximum 10 KB; SysKnife
rejects passwords, API keys, and tokens automatically.

## Transaction History

The `ListJobHistory` action and `query_job_history` planning tool
expose the daemon's SQLite transaction log. Ask "what has SysKnife done
recently?" or "did my update succeed?" and the planner queries the
log directly.

`ListJobHistory` is Observer-level (read-only, no approval required).

## Repository Layout

```text
crates/
  sysknife-brain/     LLM planner, provider adapters, safety fence
  sysknife-types/     Shared domain types (CallerRole, RiskLevel, JobState, …)
  sysknife-core/      Config loading, shared constants
  sysknife-daemon/    Privileged executor, 189 actions, IPC, rollback, SQLite
  sysknife-proto/     Protobuf definitions (future use)
apps/
  sysknife-shell/     Tauri + React GUI
tests/
  e2e/
    dev-stories.sh  Run E2E stories on any Linux host (uses sysknife --dry-run --json)
    atomic-vm.sh  Manage a Silverblue QEMU/KVM VM for full E2E
docs/
  adr/            Architectural decision records
  contributing/   Testing guide
```

## CI

CI runs on every pull request and push to `main`.

| Check | Command |
|---|---|
| Rust formatting | `cargo fmt --all --check` |
| Clippy (warnings as errors) | `cargo clippy --workspace --all-features --locked -- -D warnings` |
| Rust tests | `cargo nextest run --workspace --locked` |
| TypeScript type check | `npx tsc --noEmit` (in `apps/sysknife-shell`) |
| Frontend tests | `pnpm test` (in `apps/sysknife-shell`) |
| Markdown lint | `markdownlint-cli2` on contributor-facing docs |
| Link check | `markdown-link-check` on contributor-facing docs |
| YAML lint | `yamllint` on issue templates and workflows |

Run the Rust checks locally before pushing:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-features --locked -- -D warnings
cargo nextest run --workspace --locked
```

## Working Style

- keep changes small and reviewable
- keep behavior typed and explicit
- keep the daemon as the only privileged executor
- update docs when user-facing behavior changes
- add or update tests for every behavior change
- write the failing test first; verify it fails before writing code

## Quality Bar

Before merging, a change should be:

- understandable without reading every dependency
- covered by deterministic tests
- documented if it changes user-visible behavior
- safe by default (fail closed, not open)
- consistent with the trust boundary (daemon is the only executor)
