# Quick Start

> **💡 Prefer your AI coding tool?**
>
> If you use Claude Code, Cursor, or Codex CLI — run `npx sysknife-setup` and
> follow the wizard. See [MCP Server](mcp.md) for the full guide. You can skip
> this page entirely.

## Step 1 — Install

**Prerequisites:** Rust stable (`rustup update stable`) and an LLM provider
(see Step 2).

```sh
git clone https://github.com/lacs-project/sysknife
cd sysknife
make build
sudo make install
sudo systemctl enable --now sysknife-daemon
```

> **ℹ️ Fedora / Silverblue**
>
> All 140+ actions are fully supported and tested on Fedora 41+ and Silverblue 41+.
> Ubuntu 22.04 / 24.04 / 26.04 LTS are supported; 24.04 is validated (65/65 stories on a live VM). See [distro support](distro-support.md).

## Step 2 — Choose an LLM

Pick one. No account needed for Ollama.

**Ollama — local, fully offline, recommended for homelabs:**

```sh
ollama pull qwen3:8b        # runs well on 16 GB RAM
# SysKnife auto-detects Ollama when no cloud key is set
```

**Anthropic:**

```sh
export ANTHROPIC_API_KEY=sk-ant-...
```

**OpenAI / Gemini / others** — see [Configuration](configuration.md) for the
full list of supported providers.

**Optional config file** (`~/.config/sysknife/config.toml`):

```toml
[llm]
provider = "ollama"
model    = "qwen3:8b"
```

## Step 3 — Run

```sh
# Safe first run — plan only, nothing executes
sysknife --dry-run "show disk usage"

# Full run with the daemon
sysknife "what packages do I have installed as layers?"
```

> **⚠️ Daemon required for execution**
>
> `--dry-run` works anywhere and is a great way to test the planner without
> installing the daemon. Full execution requires `sysknife-daemon` running
> as root (enabled in Step 1).

That's it. The planner proposes a typed plan, you approve, the daemon executes.

---

## Try without installing anything

On any Linux machine with an API key:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
cargo run --bin sysknife -- --dry-run "show disk usage"
```

Plans the intent and prints the result. No daemon, no root, no installation.
Useful for evaluating the planner or running in CI.

---

## What to read next

- [CLI Reference](cli.md) — all flags, subcommands, and output formats
- [MCP Server](mcp.md) — use SysKnife from Claude Code, Cursor, Codex CLI
- [Configuration](configuration.md) — full provider and storage options
- [Distro Support](distro-support.md) — what works on which distributions
