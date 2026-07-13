<p align="center">
  <a href="https://github.com/lacs-project/sysknife">
    <img src="assets/logo/sysknife.svg" alt="SysKnife" width="170" height="170"/>
  </a>
</p>

<h1 align="center">SysKnife</h1>

<p align="center">
  <em>Your sysadmin co-pilot. Plan. Approve. Audit.</em>
</p>

<p align="center">
  <a href="https://github.com/lacs-project/sysknife/actions"><img src="https://img.shields.io/github/actions/workflow/status/lacs-project/sysknife/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI"></a>
  <a href="https://github.com/lacs-project/sysknife/blob/main/LICENSE"><img src="https://img.shields.io/github/license/lacs-project/sysknife?style=flat-square" alt="License"></a>
  <a href="https://github.com/lacs-project/sysknife/stargazers"><img src="https://img.shields.io/github/stars/lacs-project/sysknife?style=flat-square&logo=github" alt="Stars"></a>
  <a href="https://github.com/lacs-project/sysknife/issues"><img src="https://img.shields.io/github/issues/lacs-project/sysknife?style=flat-square" alt="Issues"></a>
  <a href="https://github.com/lacs-project/sysknife/discussions"><img src="https://img.shields.io/github/discussions/lacs-project/sysknife?style=flat-square&label=discuss" alt="Discussions"></a>
  <a href="https://www.npmjs.com/package/sysknife-setup"><img src="https://img.shields.io/npm/v/sysknife-setup?style=flat-square&logo=npm&label=npx%20setup" alt="npm version"></a>
</p>

<p align="center">
  <strong>Distros</strong>&nbsp;
  <img src="https://img.shields.io/badge/Fedora%2041%2B-✓-294172?style=flat-square&logo=fedora&logoColor=white" alt="Fedora 41+">
  <img src="https://img.shields.io/badge/Silverblue%2041%2B-✓-294172?style=flat-square&logo=fedora&logoColor=white" alt="Silverblue 41+">
  <img src="https://img.shields.io/badge/Ubuntu%2026.04-✓-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu 26.04">
  <img src="https://img.shields.io/badge/Ubuntu%2024.04-✓-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu 24.04">
  <img src="https://img.shields.io/badge/Ubuntu%2022.04-✓-E95420?style=flat-square&logo=ubuntu&logoColor=white" alt="Ubuntu 22.04">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#why-not-just-x">Why not <em>X</em>?</a> ·
  <a href="docs/distro-support.md">Distro matrix</a> ·
  <a href="ROADMAP.md">Roadmap</a> ·
  <a href="CONTRIBUTING.md">Contribute</a> ·
  <a href="https://github.com/lacs-project/sysknife/discussions">Discuss</a>
</p>

<p align="center">
  <img src="assets/demo/mcp-flow.gif" alt="SysKnife in Claude Code via MCP" width="900"/>
</p>

<p align="center">
  <em>Illustrative reproduction of the Claude Code MCP flow — same flow works in Cursor and Codex CLI.</em><br/>
  <em>Looking for the standalone CLI? See <a href="docs/cli.md">the CLI guide</a>.</em>
</p>

> **Describe what you want in plain language.** Review a typed plan with risk
> levels. Approve explicitly. Watch it execute with live output. Atomic-host
> changes (rpm-ostree) roll back automatically on failure. Every action is
> Ed25519-signed and audited.

SysKnife never runs a shell command. Every action is a **typed operation**
with a formal risk level. The AI cannot touch your system directly. A
privileged daemon executes only what you approve, writes a tamper-evident
HMAC-SHA256 audit chain, and rolls back automatically if a high-risk step
fails.

---

## Install

The fastest path is the setup wizard. It installs the daemon and wires
SysKnife into your AI IDE — Claude Code, Cursor, or Codex CLI — so you can
plan and execute from chat.

```sh
npx sysknife-setup
```

[![npm version](https://img.shields.io/npm/v/sysknife-setup?style=flat-square&logo=npm)](https://www.npmjs.com/package/sysknife-setup)

What this does:

1. Detects the sysknife binary (or tells you how to build it).
2. Asks for your LLM provider + key (OpenAI / Anthropic / Gemini / Ollama).
3. Asks which AI integration to wire up, or lets you pick `--claude`,
   `--cursor`, `--codex`, or `--all` directly.
4. Writes the integration-specific MCP config so the next chat session sees
   `sysknife_plan` and `sysknife_execute` as first-class tools.

| Client          | Files written                                        |
|-----------------|------------------------------------------------------|
| **Claude Code** | `.mcp.json` + `.claude/hookify.*.local.md`           |
| **Cursor**      | `.cursor/mcp.json` + `.cursor/rules/sysknife.mdc`    |
| **Codex CLI**   | `~/.codex/config.toml` (appended) + `AGENTS.md`      |

Then in your chat: ask for what you want, review the plan with risk pills,
approve, watch it execute. The MCP layer enforces the same approval contract
as the CLI — `sysknife_plan` always runs before `sysknife_execute`, never
in the same turn.

> **Prefer the standalone CLI?** Same engine, no IDE — see the
> [CLI guide](docs/cli.md) for `sysknife "..."`, `--dry-run`, `--json`,
> approval prompts, and audit-log inspection.

<details>
<summary><strong>Manual install — Fedora 41+ / Silverblue 41+ · Ubuntu 22.04 / 24.04 / 26.04</strong></summary>

```sh
# Build + install the daemon the wizard configures
git clone https://github.com/lacs-project/sysknife
cd sysknife
make build
sudo make install
sudo systemctl enable --now sysknife-daemon

# Then run the wizard (local-clone path until npm publish lands)
node packages/setup/index.js
```

The same steps work on every supported distro. The Ubuntu 24.04 action set is
validated (65/65 stories pass on a live VM with gpt-4.1); Ubuntu 22.04 (jammy)
and 26.04 (resolute) VM tooling is complete with smoke tests passing on all
three LTSes. See [`docs/distro-support.md`](docs/distro-support.md) for the full
matrix.
</details>

<details>
<summary><strong>Dry run — plan only, nothing executes</strong></summary>

```sh
# Requires the sysknife binary (see manual install above, or `npx sysknife-setup`).
# Plans only: no daemon, no approval, no execution.
export ANTHROPIC_API_KEY=sk-ant-...
sysknife --dry-run "show disk usage and list services that ate cpu in the last hour"
```
</details>

## How it works

```
sysknife-brain   →   sysknife-shell   →   sysknife-daemon
  (planner)         (approval gate)        (executor)
   talks to LLM      shows the plan,        only privileged
   never to OS       takes y/n              process; signs
                                            every action
```

1. You type a natural-language request.
2. The brain proposes a plan — each step is a **typed action** with
   a risk level (`Low` · `Medium` · `High`).
3. The shell shows the plan with previews, side-effects, and rollback
   metadata.
4. You approve each step explicitly (or set `--yes` up to a risk ceiling).
5. The daemon executes, streams live output, rolls back automatically on
   high-risk failure.
6. Every execution is logged to a hash-chained SQLite or Postgres audit
   trail you can verify with `sysknife audit verify`.

The brain *proposes*; only the daemon is privileged. The daemon *enforces*
policy, executes typed actions, writes the signed chain, and triggers
atomic-host rollback (rpm-ostree) on failure. The trust boundary is
mechanical: no shell strings cross the wire.

## Why not just X?

| Tool | The gap |
|---|---|
| **Open Interpreter** | Runs arbitrary Python/Shell. No formal risk model. No audit chain. |
| **Goose / Continue** | General-purpose. Ad-hoc confirmation, not typed risk levels. |
| **Claude Computer Use** | Uncontrolled desktop automation, not system administration. |
| **Ansible** | YAML written in advance. Not conversational. No risk classification. |
| **shell-gpt / Copilot** | Suggests raw shell commands. You still run raw shell. |
| **Manual** | No audit trail. No rollback. One typo = lost work. |

SysKnife is different by construction: typed actions, an Ed25519-signed audit
chain, explicit approval gate, automatic rollback for atomic-host (rpm-ostree)
changes, polkit-mediated privilege boundary. The AI never holds a shell.

## Status

The trust chain is built, tested, and shipping. Multi-distro is the active
milestone.

| Component | State |
|---|---|
| `sysknife-brain` — LLM planner, tool loop, safety fence | ✅ |
| `sysknife-daemon` — 140+ typed actions, auth, preview, transactions | ✅ |
| Live IPC + streaming + atomic-host rollback (rpm-ostree) | ✅ |
| Tauri shell — intent, plan, approval gate | ✅ |
| MCP server (Claude Code / Cursor / any MCP client) | ✅ |
| Tamper-evident HMAC-SHA256 audit chain | ✅ |
| RFC 5424 syslog forwarding (Splunk / Sentinel / QRadar) | ✅ |
| Postgres backend (RDS / Cloud SQL / Neon / Supabase) | ✅ |
| **Ubuntu 24.04 support** — 65/65 stories pass on a live VM with gpt-4.1 | ✅ |
| **Ubuntu 22.04 / 26.04 VM tooling** — smoke tests pass on all three LTSes | ✅ |
| Telegram approval interface | 📋 roadmap |

**1,227 tests** pass across Rust and TypeScript on every commit.

## Configure your LLM

SysKnife works with **Ollama** (no key, recommended for privacy / offline /
homelab) or **OpenAI**, **Anthropic**, **Gemini**, **Groq**, **DeepSeek**,
**Mistral**, **xAI**.

```toml
# ~/.config/sysknife/config.toml
[llm]
provider     = "ollama"          # or anthropic / openai / gemini / groq / ...
model        = "qwen3:8b"        # provider-specific
ollama_url   = "http://localhost:11434"
max_turns    = 10

[daemon]
socket   = "/run/sysknife/daemon.sock"
database = "/var/lib/sysknife/daemon.sqlite"

[storage]                         # production-recommended
backend = "postgres"
url     = "postgres://sysknife:${PG_PASSWORD}@db.example.com/audit?sslmode=verify-full"
```

Env vars always win over the config file. Full reference in
[`docs/configuration.md`](docs/configuration.md).

## MCP protocol

SysKnife implements the [Model Context Protocol](https://modelcontextprotocol.io/)
and exposes two tools — `sysknife_plan` and `sysknife_execute`. The MCP layer
enforces the same approval contract as the CLI: agents must call
`sysknife_plan` first, present the plan, wait for explicit human approval,
then call `sysknife_execute`. High-risk actions are refused outright at the
MCP boundary — they require the CLI/GUI confirmation flow.

Use the setup wizard (above) to wire it into Claude Code, Cursor, or Codex CLI.
All config files that may contain API keys are created with `chmod 0600`.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full milestone breakdown.

- ✅ **Ubuntu 24.04** — 65/65 stories validated on a live VM (gpt-4.1)
- ✅ **Ubuntu 22.04 / 26.04** — VM tooling complete; smoke tests pass on all three LTSes
- 📋 Telegram inline-button approvals
- 📋 `sysknife audit export` (CEF / NDJSON for SIEM ingest)
- 📋 Fleet plan/execute (one plan, N targets, parallel approval)
- 📋 GUI (Tauri shell) for Wayland desktop linux

## Protocol

SysKnife is the reference implementation of the **LACS (Linux Agent Control
Standard)** protocol — typed actions, risk classification, approval gates,
audit requirements. The spec is CC0 (public domain):

→ **[lacs-project/specification](https://github.com/lacs-project/specification)**

Other implementations for other distros and languages are explicitly
encouraged.

## Contributing

We want help. **Multi-distro** is the highest-impact area to plug into right
now — see [`docs/distro-support.md`](docs/distro-support.md) for the
roadmap matrix and [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow.

Issues labelled
[`good first issue`](https://github.com/lacs-project/sysknife/labels/good%20first%20issue)
are scoped with clear acceptance criteria.

## Documentation

- [Architecture overview](docs/architecture.md)
- [Distro support matrix](docs/distro-support.md)
- [Developer guide](docs/developer-guide.md)
- [Testing guide](docs/contributing/testing.md)
- [VM daemon setup](docs/vm-daemon-setup.md)
- [Security policy](SECURITY.md)
- [Roadmap](ROADMAP.md)
- [ADR 0001 — System boundaries](docs/adr/0001-system-boundaries.md)
- [ADR 0002 — Brain provider layer](docs/adr/0002-brain-provider-layer.md)
- [ADR 0003 — IPC wire protocol](docs/adr/0003-ipc-wire-protocol.md)

## Where to find SysKnife

| Channel | Install | Notes |
|---------|---------|-------|
| **npm** | `npx sysknife-setup` | [npmjs.com/package/sysknife-setup](https://www.npmjs.com/package/sysknife-setup) — zero-install setup wizard |
| **crates.io** | `cargo install sysknife-cli` / `cargo install sysknife-daemon` | Available once `CARGO_REGISTRY_TOKEN` is configured — see [docs/release.md](docs/release.md) |
| **GitHub Releases** | Download from [Releases](https://github.com/lacs-project/sysknife/releases) | Prebuilt x86_64 + aarch64 binaries with SHA-256 checksums on every tag |

## License

[MIT](LICENSE). Free to use, modify, distribute, and embed in proprietary
products without restriction.

The [LACS specification](https://github.com/lacs-project/specification) is
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) — public domain.

---

<p align="center">
  Built by <a href="https://github.com/vladimirrotariu">Vladimir Rotariu</a>.
  ·
  Issues, ideas, war stories — <a href="https://github.com/lacs-project/sysknife/discussions">come say hi</a>.
</p>
