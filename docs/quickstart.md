# Quick Start

This is the canonical install page. Everywhere else links here rather than
repeating a second, slightly different sequence.

> **💡 Prefer your AI coding tool?**
>
> If you use Claude Code, Cursor, or Codex CLI — run `npx sysknife-setup` and
> follow the wizard. See [MCP Server](mcp.md) for the full guide. You can skip
> this page entirely.

## Step 1 — Install

Two paths. The wizard needs no toolchain and no compile; building from source
needs both.

### Fastest: prebuilt binaries

```sh
npx sysknife-setup
```

**Prerequisites:** Node 18 or newer. On Ubuntu 22.04, `apt install nodejs`
installs Node 12, which is too old — the installer will tell you so and how to
get a current Node. It downloads SHA-256-verified binaries from the release
page, installs the daemon service, and writes your MCP client config.

Unattended runs must say which daemon to install, because the choice decides
what will work:

```sh
npx sysknife-setup --claude --no-prompts --daemon-mode=system
```

`--daemon-mode=user` installs an unprivileged service that runs as you: read-only
actions work, and anything mutating (installing packages, restarting services)
does not, because the sudoers grants belong to the `sysknife` system user.

### From source

**Prerequisites:** Rust stable (`rustup update stable`), **a C compiler and
linker**, and an LLM provider (see Step 2). The TLS and SQLite dependencies
build native code, so a machine with only `rustup` fails at
`error: linker cc not found`. `cmake` is not required.

```sh
sudo apt-get install -y build-essential   # Debian/Ubuntu
git clone https://github.com/lacs-project/sysknife
cd sysknife
make build
sudo make install
sudo systemctl enable --now sysknife-daemon
```

`make build` compiles around 400 crates: expect 7 to 12 minutes on a first
build (measured 6m56s on Ubuntu 24.04, 11m43s on 22.04).

> **ℹ️ Fedora / Silverblue**
>
> Ubuntu 24.04 is validated with 65/65 stories on a live VM. Ubuntu 22.04 and
> 26.04 have smoke-test coverage. Fedora Atomic uses the rpm-ostree action
> family and requires a current Silverblue 44 validation run for each release.
> Plain Fedora remains experimental. See [distro support](distro-support.md).

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

## Try the planner without the daemon

On any Linux machine with an API key:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
cargo run --bin sysknife -- --dry-run "show disk usage"
```

Plans the intent and prints the result. No daemon and no root: nothing
privileged runs, so this is the way to evaluate the planner or run it in CI.

It is not, however, free of installation — `cargo run` builds the workspace, so
it needs Rust plus `build-essential` and the same 7 to 12 minutes as any other
first build. If what you want is the quickest look at SysKnife, use
`npx sysknife-setup` and the prebuilt binaries instead.

---

## What to read next

- [CLI Reference](cli.md) — all flags, subcommands, and output formats
- [MCP Server](mcp.md) — use SysKnife from Claude Code, Cursor, Codex CLI
- [Configuration](configuration.md) — full provider and storage options
- [Distro Support](distro-support.md) — what works on which distributions
