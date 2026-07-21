# Architecture

SysKnife is a local Linux control plane built around a strict boundary
between planning, presentation, and execution.

## Crate and App Layout

| Location | Package | Role |
|---|---|---|
| `crates/sysknife-brain/` | `sysknife-brain` | Unprivileged LLM planner |
| `crates/sysknife-types/` | `sysknife-types` | Shared domain types |
| `crates/sysknife-core/` | `sysknife-core` | Config file loading, constants |
| `crates/sysknife-daemon/` | `sysknife-daemon` | Privileged executor |
| `crates/sysknife-proto/` | `sysknife-proto` | Protobuf definitions (future use) |
| `apps/sysknife-shell/` | `sysknife-shell` | Tauri + React GUI |
| `apps/sysknife-cli/` | `sysknife` | Production CLI — also used headlessly by E2E stories (`--dry-run --json`) |

### sysknife-brain

Unprivileged. Reads the user's intent, queries the daemon for system
state, then calls the LLM in a tool-use loop until a typed plan is
produced. Provides:

- `LlmPlanner` — the planning loop entry point
- `BrainConfig` — provider and model selection
- Provider adapters: Anthropic, OpenAI, Gemini, Ollama, Groq, DeepSeek, Mistral, xAI
- Planning tools: `get_system_state`, `query_*`, `propose_plan`, `remember`, `forget`
- Safety fence: validates every action name and risk level before a plan
  leaves the brain

#### Prompt construction — per-distro dispatch

`build_system_prompt` in `crates/sysknife-brain/src/prompt.rs` dispatches to one
of three pure render functions based on `distro_hint.family`:

| Distro family | Render function | Actions included |
|---|---|---|
| Fedora (`fedora`) | `render_fedora_prompt` | rpm-ostree, flatpak, toolbox, firewalld, … |
| Debian (`debian`) | `render_debian_prompt` | apt, snap, distrobox, ufw, netplan, … |
| Unknown | `render_generic_prompt` | Cross-distro actions only |

Each render function concatenates shared `const` blocks (role, rule, examples)
with per-distro `const` blocks (action catalogue, worked examples, parameter
reference). Fedora prompts never contain Debian action names and vice versa —
the isolation is structural. This prevents the model from proposing
`AptInstall` on Fedora or `AddLayeredPackage` on Ubuntu regardless of what the
user types.

The prompt is rebuilt on every `plan_intent()` call so that injected user
preferences (`~/.config/sysknife/prefs.md`) are always current.

See [ADR 0004](adr/0004-per-distro-prompt-dispatch.md) for the full rationale.

### sysknife-types

Shared domain types used by every crate. Contains:

- `CallerRole` — `Observer` | `Dev` | `Admin` | `Boot`
- `RiskLevel` — `Low` | `Medium` | `High`
- `JobState` — `Queued` | `Running` | `Succeeded` | `Failed` | `Canceled` |
  `RolledBack` | `NeedsReboot`
- Request and result envelopes for IPC messages

### sysknife-core

Shared constants and `~/.config/sysknife/config.toml` loading via
`LacsConfig`. Config file values become env-var defaults so every
component uses the same resolution order.

### sysknife-daemon

Privileged. The only component that touches the system. Provides:

- 140+ typed actions (rpm-ostree, systemd, firewall, users, containers,
  flatpak, toolbox, SSH, kernel args, …)
- Role-based authorization (`Observer` → `Dev` → `Admin`)
- Policy enforcement: stale-approval detection, request hash validation
- Preview generation: risk level, side effects, reboot flag, rollback
  metadata, content hash
- IPC dispatcher over a Unix domain socket
- Live stdout streaming as `JobProgress` frames
- Automatic rollback for supported high-risk actions that fail
- SQLite transaction audit log

### sysknife-shell

The user-facing surface. A Tauri app (Rust backend + React frontend)
that provides:

- Intent entry pane
- Plan review with risk badges and previews
- Approval gate (explicit checkbox for Medium; typed action name for High)
- Live job timeline with streaming output
- Setup wizard for first-run LLM configuration

### sysknife-cli

The production CLI (`apps/sysknife-cli/`). Accepts a natural-language intent,
calls the LLM planner, and prints or executes the resulting plan.
`--dry-run --json` mode emits the plan as JSON on stdout without executing —
this is the mode used by every E2E story script.

## Trust Boundary

The daemon is trusted. The brain and shell are not trusted with raw
privileged execution.

```text
sysknife-brain  ──plan──►  sysknife-shell  ──approval──►  sysknife-daemon
 (planner)               (approval)                 (executor)
```

The daemon owns:

- authorization (role-based: Observer → Dev → Admin)
- policy (stale-approval detection, request validation)
- previews (risk level, side effects, rollback metadata)
- jobs (execution, live output streaming)
- transaction records (SQLite audit log)
- rollback (automatic on failure for supported actions)

Neither the brain nor the shell can execute a privileged action directly. The
daemon verifies and atomically consumes a one-time approval receipt before
running anything.

## Request Flow

1. A user enters intent in the shell.
2. The brain proposes a typed plan.
3. The shell sends each mutating step to the daemon for preview.
4. The daemon persists an immutable preview and returns its transaction ID,
   risk level, side effects, reboot requirement, and rollback availability.
5. The shell shows the preview and captures approval.
   High-risk steps require the user to type the action name explicitly.
6. The daemon issues a deterministic, domain-separated Ed25519 receipt and
   stores its SHA-256 commitment inside the signed transaction row.
7. The client sends the exact transaction, action, params, and receipt.
8. The daemon verifies the preview is fresh and atomically consumes the
   receipt, then runs the action.
9. During execution, the daemon streams live stdout output line-by-line
   as `JobProgress` frames.
10. The shell displays each line as it arrives.
11. On failure, if `rollback_available` is true, the daemon runs the
    rollback action automatically and reports the result.
12. The transaction is persisted to the configured SQLite or PostgreSQL store
    with the final job state.

## IPC Protocol

The shell and daemon communicate over a Unix domain socket
(`/tmp/sysknife-daemon.sock` by default, overridable via `SYSKNIFE_LISTEN_URI`).

The framing is a 4-byte little-endian `u32` length prefix followed by
a UTF-8 JSON body. Each message carries a `"type"` discriminant so
the dispatcher can route without a full decode.

Maximum message size is 4 MiB. The daemon limits concurrent
connections to 16 via a tokio semaphore; excess connections are
dropped immediately rather than queued.

The protocol is human-readable. You can inspect live traffic with:

```sh
socat - UNIX-CONNECT:/tmp/sysknife-daemon.sock
```

See [ADR 0003](adr/0003-ipc-wire-protocol.md) for the rationale
behind length-prefixed JSON over gRPC or binary protobuf.

## Design Principles

- typed instead of free-form
- local instead of remote
- auditable instead of opaque
- rollback-aware instead of irreversible
- explicit approval instead of hidden mutation
