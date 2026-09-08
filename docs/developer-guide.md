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

**Required.** Without these nothing builds:

| Tool | Version | Install |
|---|---|---|
| Rust stable | latest stable | [rustup.rs](https://rustup.rs) |
| A C compiler and linker | — | `sudo apt-get install -y build-essential` |
| Node.js | 20+ | [nodejs.org](https://nodejs.org) or your distro |
| `cargo-nextest` | latest | `cargo install cargo-nextest --locked` |

**Required to reproduce the `docs-and-hygiene` job**, which is one of the five
checks `main` requires:

| Tool | Version | Install |
|---|---|---|
| ShellCheck | distro | `sudo apt-get install -y shellcheck` |
| Python | 3.10+ | usually already present |
| `markdownlint-cli2` | 0.23.2 | `npm install --global markdownlint-cli2@0.23.2` |
| `markdown-link-check` | 3.15.0 | `npm install --global markdown-link-check@3.15.0` |

**Required only for the jobs that name them:**

| Tool | Needed by | Install |
|---|---|---|
| Podman or Docker | the live `postgres-contract` job | `sudo apt-get install -y podman` |
| Tauri system deps | building the paused GUI app | [tauri.app/start/prerequisites](https://tauri.app/start/prerequisites/) |

> **Install `cargo-nextest` before you trust a green run.** `scripts/ci-local.sh`
> reports `WARN ... SKIPPED` rather than failing when it is missing, so the whole
> Rust test step silently does not run and the summary still ends `ci-local: PASS`.

This project uses **npm**. `apps/sysknife-shell` carries a `package-lock.json`
and CI runs `npm ci` against it. There is no pnpm or yarn lockfile in the tree.

No API key is required to get started. SysKnife auto-detects a local
Ollama instance (`http://localhost:11434`) when no cloud API key is set.
If you do not have Ollama installed, you can still run all unit and
integration tests without it.

## Clone and Set Up

```sh
git clone https://github.com/lacs-project/sysknife
cd sysknife

# Install the git hooks (run once). This sets core.hooksPath to .githooks,
# which is what wires up the real pre-commit and pre-push gates.
scripts/ci-local.sh --install-hooks

# Install frontend dependencies
npm ci --prefix apps/sysknife-shell
```

> Do **not** use `pip install pre-commit && pre-commit install`. This repository
> drives its hooks through `core.hooksPath`, so anything written into
> `.git/hooks` is ignored by Git and you would end up with no gate at all.
> `.pre-commit-config.yaml` is left over from an earlier setup and is not used.

## Building

The workspace builds native code (TLS via aws-lc-sys/ring, SQLite via
libsqlite3-sys), so a C compiler and linker are required on top of rustup:
`sudo apt-get install -y build-essential` on Debian/Ubuntu. Without one the
build stops at `error: linker cc not found`. `cmake` is not required.

```sh
# Build all Rust crates (fast, no linking of the Tauri app)
cargo build --workspace

# Build the Tauri app (includes the GUI)
npm run tauri --prefix apps/sysknife-shell -- build
```

## Running Tests

These run in under 15 seconds and are required before every push:

```sh
# Rust unit + integration tests
cargo nextest run --workspace --locked

# TypeScript / React tests
npm test --prefix apps/sysknife-shell
npm exec --prefix apps/sysknife-shell -- tsc --noEmit
```

See [docs/contributing/testing.md](contributing/testing.md) for the
full test pyramid, including how to run the LLM-driven E2E stories
on your workstation and in a Fedora Atomic VM.

## Reproducing the Required Checks

`main` requires five checks. `scripts/ci-local.sh` runs most of them in one go
and is the command to reach for first:

```sh
scripts/ci-local.sh          # everything it can run here
scripts/ci-local.sh --fast   # what the pre-push hook runs
```

Read its summary rather than its exit code. A tool it cannot find becomes a
`WARN ... SKIPPED` line and the run still ends `ci-local: PASS`, so an absent
`cargo-nextest` means the Rust suite never ran at all.

### Use `cargo nextest`, not `cargo test`

CI and every script here run `cargo nextest run --workspace --locked`. Plain
`cargo test` runs the whole binary's tests as threads in one process, and a few
tests here set process-global environment variables, so it fails intermittently
on `main` through no fault of your branch. `nextest` gives each test its own
process and does not have that problem. If you have no choice, `cargo test --
--test-threads=1` is stable.

### The live Postgres contract

`postgres-contract` is the only required check that needs a server, and it is
the one people assume they cannot run. You can. CI starts `postgres:17-alpine`
as a service container; do the same locally:

```sh
podman run -d --name sysknife-pg -p 55987:5432 \
  -e POSTGRES_USER=sysknife -e POSTGRES_PASSWORD=sysknife \
  -e POSTGRES_DB=sysknife_test docker.io/library/postgres:17-alpine

export SYSKNIFE_TEST_POSTGRES_URL=postgres://sysknife:sysknife@127.0.0.1:55987/sysknife_test
export SYSKNIFE_REQUIRE_POSTGRES=1
cargo test -p sysknife-daemon --test postgres_store --locked -- --include-ignored

podman rm -f sysknife-pg
```

Those tests are `#[ignore]` by default, so a normal run reports them as ignored
rather than passing over a database that was never there. `SYSKNIFE_REQUIRE_POSTGRES=1`
without a URL panics on purpose: a misnamed variable used to report success.

Podman works rootless and needs no daemon. Docker works too; on some hosts its
published ports reset the connection, in which case use podman.

### The hygiene guards

`docs-and-hygiene` runs about two dozen host-side scripts under `tests/release/`
and `scripts/`. They are plain shell and Python, they need no build, and each
one runs on its own in well under a second:

```sh
bash tests/release/public-claims.test.sh
bash scripts/check_release_versions.sh
```

If one goes red with no output, that is [#347](https://github.com/lacs-project/sysknife/issues/347),
not you.

### Running a contributor's branch safely

Reviewing someone else's PR means running their code. Do it in a container with
no network and nothing from your home directory mounted:

```sh
podman run --rm --network=none -v "$PWD:/repo:z" -w /repo \
  docker.io/library/python:3-slim bash -c 'bash tests/release/public-claims.test.sh'
```

For Rust, give the container a throwaway copy of your cargo home with an overlay
mount so a build script cannot write to yours, and point `CARGO_HOME` at it. The
official `rust` image sets `CARGO_HOME=/usr/local/cargo`, so a mount alone is
ignored:

```sh
podman run --rm --network=none -v "$PWD:/repo:z" -v "$HOME/.cargo:/cargo:O" \
  -w /repo -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/repo/.container-target \
  -e CARGO_NET_OFFLINE=true docker.io/library/rust:1-slim \
  cargo test -p sysknife-cli --bins --offline
```

`sysknife-cli` is a binary crate, so its unit tests need `--bins`; `--lib` finds
no target.

## Running the Full Stack Locally

You need two terminals.

**Terminal 1 — daemon**

```sh
# Binds $SYSKNIFE_LISTEN_URI, else $XDG_RUNTIME_DIR/sysknife/daemon.sock
# (last resort /tmp/sysknife-$UID.sock). The CLI resolves the same default,
# so `sysknife doctor` works without setting a socket env var.
# Privileged system actions (rpm-ostree, useradd, etc.) require root.
# For development you can run without root — read-only queries still work.
cargo run -p sysknife-daemon
```

**Terminal 2 — shell (GUI)**

```sh
cd apps/sysknife-shell
npm run tauri --prefix apps/sysknife-shell -- dev
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
socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/sysknife/daemon.sock"
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
| `SYSKNIFE_LISTEN_URI` | `$XDG_RUNTIME_DIR/sysknife/daemon.sock` (prod: `/run/sysknife/daemon.sock`) | Daemon socket URI (where the daemon binds) |
| `SYSKNIFE_SOCKET` | falls back to the same default as `SYSKNIFE_LISTEN_URI` | CLI / MCP-server socket override — where the client dials (`unix://`, `vsock://`, or a bare path) |
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
  sysknife-daemon/    Privileged executor, 189 actions with an `ActionSpec`,
                      IPC, rollback, SQLite
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
| Frontend tests | `npm test --prefix apps/sysknife-shell` |
| Markdown lint | `markdownlint-cli2` on contributor-facing docs |
| Link check | `markdown-link-check` on contributor-facing docs |
| YAML lint | `yamllint` on issue templates and workflows |

Run the Rust checks locally before pushing:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-features --locked -- -D warnings
cargo nextest run --workspace --locked
```

## Running CI locally

`scripts/ci-local.sh` mirrors the runnable jobs from
`.github/workflows/ci.yml` (rust, frontend, hygiene, security, and the
optional postgres-contract job) so you catch failures before pushing,
without spending GitHub Actions minutes:

```sh
# Full run — everything CI runs, including the optional Postgres contract
# test if docker/podman is available (or SYSKNIFE_TEST_POSTGRES_URL is set)
scripts/ci-local.sh

# Fast subset — rust fmt/clippy/nextest + frontend tsc/vitest only
scripts/ci-local.sh --fast

# Skip the postgres-contract job even if a container runtime is available
scripts/ci-local.sh --no-postgres
```

It detects which tools are installed first: `cargo` and `node` are required
(missing either is a hard failure with an install link); an optional linter
that's missing (`cargo-nextest`, `cargo-audit`, `markdownlint-cli2`,
`markdown-link-check`, `yamllint`, `shellcheck`) just prints a warning with
an install hint and skips that one check. Every check still runs even after
an earlier one fails — a PASS/FAIL/WARN/SKIP summary prints at the end, and
the script exits non-zero only if something in the summary actually failed.

### Pre-push hook

`scripts/ci-local.sh --install-hooks` runs `git config core.hooksPath
.githooks`, which wires up `.githooks/pre-push` to run `scripts/ci-local.sh
--fast` automatically before every `git push` and block the push on
failure. Bypass a single push with `git push --no-verify`; undo the hook
entirely with `git config --unset core.hooksPath`.

`.githooks/` already ships a `pre-commit` hook (`cargo fmt --all --check` +
`cargo nextest run --workspace --locked`) alongside the new `pre-push` one.
Both are opt-in via the same `core.hooksPath` setting. Note that
`core.hooksPath` is a single switch: pointing it at `.githooks` means Git
stops looking in `.git/hooks`, so it supersedes hooks installed by the
`pre-commit` framework (see [Pre-commit Hooks](#pre-commit-hooks) above) —
use one mechanism or the other, not both, per clone.

### Full workflow replay

`ci-local.sh` runs the same commands as CI, but not inside the same
container/runner image, so it cannot catch environment-specific breakage.
For an exact, Docker-based replay of the GitHub Actions workflow (all jobs,
the real `ubuntu-latest` image), use
[`act`](https://github.com/nektos/act) instead.

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
