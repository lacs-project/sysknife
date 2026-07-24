<img src="images/sysknife.svg" alt="SysKnife" class="sysknife-logo"/>

<p class="sysknife-tagline">Your Linux sysadmin co-pilot. Plain language in. Typed plan out. You approve. Daemon executes.</p>

<div class="cta-row">
  <a href="quickstart.html" class="cta-btn cta-btn-primary">Get started →</a>
  <a href="mcp.html" class="cta-btn cta-btn-secondary">Use with Claude Code / Cursor</a>
</div>

<img
  src="https://raw.githubusercontent.com/lacs-project/sysknife/main/assets/demo/mcp-flow.gif"
  alt="SysKnife in Claude Code via MCP — plan in chat, approve in a terminal, execute with a one-time receipt"
  class="sysknife-demo"
/>

---

## What SysKnife does

You describe a task in plain language. SysKnife asks an LLM to turn it into a
**typed plan** — a list of named actions with formal risk levels. You review the
plan, approve it, and the daemon executes it step by step with live output and
automatic rollback on failure.

```sh
$ sysknife "install neovim and make sure it starts on login"

Plan  (2 steps)
──────────────────────────────────────────────────────────
 1  AddLayeredPackage  neovim             risk: high
 2  SetServiceEnabled  neovim.service     risk: medium
──────────────────────────────────────────────────────────
Approve? [y/N]
```

The AI cannot run a shell command. It can only propose typed actions. The daemon
is the only process that touches your system — and only after you say yes.

---

## Why not just paste the shell command the AI gives you?

Because you find out what it did after. There is no record, no rollback, and no
way to verify the AI proposed the minimal change rather than a sledgehammer.

SysKnife gives you:

- **Typed actions** — not shell strings. `AddLayeredPackage neovim` not `rpm-ostree install neovim && ...`
- **Risk levels** — Low (read-only), Medium (reversible), High (irreversible, access-control, or reboot-required)
- **Preview before execution** — see the exact commands before they run
- **Automatic rollback** — if a high-risk action fails, the daemon reverses what it can
- **Immutable audit trail** — every execution is Ed25519-signed and hash-chained

---

## How it works

```
┌─────────────────┐   plan    ┌──────────────────┐  approve  ┌─────────────────┐
│  sysknife-brain │ ────────► │  sysknife-shell  │ ────────► │ sysknife-daemon │
│  (unprivileged) │           │  (approval gate) │           │  (root, locked) │
└─────────────────┘           └──────────────────┘           └─────────────────┘
   LLM + tools                   you review here               executes + audits
```

| Component | Privilege | Job |
|---|---|---|
| **brain** | none | Talks to the LLM, proposes a typed plan |
| **shell** | user | Shows you the plan, collects your approval |
| **daemon** | root | Executes approved actions, writes the audit log |

The brain proposes but **cannot touch the system**. The daemon executes but
**cannot be reached without an approved plan**.

---

## Fastest path: use via your AI coding tool (MCP)

MCP is how most people use SysKnife in 2026 — it's the dominant way AI tools
talk to real systems, and Claude Code, Cursor, and Codex CLI all support it. One
command wires it up:

```sh
npx sysknife-setup
```

The demo above shows the whole loop: plan in chat, approve in a terminal,
execute with a one-time receipt. See the [MCP Server guide](mcp.md) for full
setup and the approval-gate hook.

---

## Prefer the terminal? The CLI is a first-class path

No IDE and no MCP client — the same planner, approval gate, and Ed25519 audit
chain, driven straight from your shell. This is a fully supported way to run
SysKnife, not an afterthought.

<img
  src="https://raw.githubusercontent.com/lacs-project/sysknife/main/assets/demo/demo.gif"
  alt="sysknife CLI — plain language to a typed plan to live execution in the terminal"
  class="sysknife-demo"
/>

> **ℹ️ Distro support**
>
> Ubuntu 24.04 is validated with the full 65-story VM suite. Ubuntu 22.04 and
> 26.04 are smoke-tested. Fedora Atomic is supported by the rpm-ostree action
> family, but a current Silverblue 44 VM run is a release gate. Plain Fedora
> remains experimental until the `dnf` action family ships.
> See [Distro Support](distro-support.md) for the full matrix.

```sh
git clone https://github.com/lacs-project/sysknife
cd sysknife && make build && sudo make install
sudo systemctl enable --now sysknife-daemon
sysknife "show disk usage"
```

No API key needed if you have [Ollama](https://ollama.com) running locally —
SysKnife auto-detects it. See [Quick Start](quickstart.md).

---

## Also: a desktop GUI (a distant third option)

There is an experimental desktop GUI (`sysknife-shell`, built with Tauri) that
wraps the same plan → approve → execute loop in a window. It is the least
frequently maintained surface — a distant third behind the MCP integration and
the CLI — so reach for it only if you specifically want a graphical approval
flow.

---

## Status

189 typed actions · 1,405 Rust tests + 72 frontend tests · MIT

SysKnife is the reference implementation of the
[LACS specification](https://github.com/lacs-project/specification) — a
CC0 public-domain protocol for AI agents that operate at the Linux system level.
