# `sysknife` CLI Reference

`sysknife` is the command-line interface to the SysKnife daemon. It turns a
natural-language intent into a risk-labelled plan, asks for approval where
needed, and streams execution output in real time.

If you want SysKnife inside Claude Code / Cursor / Codex CLI instead, see
the [main README](../README.md) and run `npx sysknife-setup`. Both paths
share the daemon, the audit chain, and the typed-action set.

<img
  src="https://raw.githubusercontent.com/lacs-project/sysknife/main/assets/demo/demo.gif"
  alt="sysknife CLI demo"
  class="sysknife-demo"
/>

---

## Quick start

```sh
# Check that the daemon is reachable
sysknife doctor

# Plan + execute a single intent
sysknife "check disk usage"

# Preview the plan without executing
sysknife --dry-run "list running containers"

# Open the interactive REPL
sysknife
```

---

## Synopsis

```text
sysknife [GLOBAL FLAGS] [SUBCOMMAND | INTENT WORDS...]
```

When no subcommand is given and no intent words are provided, `sysknife` starts
an interactive REPL.

---

## Subcommands

### `sysknife <intent>`

Plan and (optionally) execute a natural-language intent.

```sh
sysknife "check disk usage"
sysknife check disk usage            # words are joined — same result
sysknife "list running containers"
sysknife "is firewalld active?"
sysknife "layer vim via rpm-ostree"
```

**What happens:**

1. A spinner appears while the LLM plans (`Thinking…` → `Querying …` →
   `Proposing plan…`).
2. The coloured plan is printed — each step shows a risk badge
   (`● low` / `● medium` / `● HIGH`), the action name, and a summary.
3. If any step requires approval, you are prompted.  HIGH-risk steps always
   require confirmation regardless of `--yes`.
4. Execution streams output line by line with a `›` prefix; a `✓` / `✗`
   result icon is printed after each step.

---

### `sysknife doctor`

Check daemon connectivity and print the resolved configuration.

```sh
sysknife doctor
sysknife --json doctor      # machine-readable
```

Exit code `0` on success, non-zero if the daemon is unreachable.

Sample output:

```text
✓  daemon ok
  socket    /run/sysknife/daemon.sock
  host      my-silverblue
  provider  anthropic
  model     claude-sonnet-4-6
```

---

### `sysknife history`

Query past SysKnife execution history.

```sh
sysknife history
sysknife history --limit 50
sysknife history --status failed
sysknife history --action InstallPackages
sysknife history --since 2026-04-01T00:00:00Z
sysknife history --status succeeded --limit 5 --since 2026-04-10T00:00:00Z
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--limit N` | `20` | Maximum entries to return |
| `--status STATUS` | — | Filter by job status (`succeeded`, `failed`, `canceled`, …) |
| `--action ACTION` | — | Filter by action name (e.g. `InstallPackages`) |
| `--since DATETIME` | — | Only entries after this UTC RFC 3339 timestamp |

---

### `sysknife approve`

Issue a one-time receipt for a transaction returned by the MCP
`sysknife_plan` tool. This command requires an interactive terminal. It first
loads and displays the daemon-authoritative action, risk, summary, and proposed
change so an agent cannot substitute an opaque transaction ID. It mints the
receipt only after confirmation; high-risk approvals require typing the exact
action name.

```sh
sysknife approve 018f2c9d-...
sysknife --json approve 018f2c9d-...
```

Give the printed `approval_receipt` to the MCP client for that exact step. The
receipt expires after 15 minutes, is bound to the preview's action and params,
and is consumed on first execution. A chat message saying "approved" is not a
receipt.

---

### `sysknife audit`

Inspect and anchor the tamper-evident, Ed25519-signed audit chain the daemon
writes for every executed action.

#### `sysknife audit verify`

Verify the audit chain. Exits `0` if intact, `1` if any row is broken
(tampered), `2` if the chain cannot be verified (missing key, unreadable
database).

```sh
sysknife audit verify
sysknife audit verify --json
sysknife audit verify --pubkey /etc/sysknife/audit-key.pub
```

| Flag | Description |
|---|---|
| `--json` | Machine-readable JSON report instead of human text |
| `--pubkey FILE` | Verify with only the exported public key (`<audit-key>.pub`), no private key: the third-party / auditor path. Works with SQLite and PostgreSQL and proves the chain without signing access. |

#### `sysknife audit checkpoint`

Sign the current chain tip as a checkpoint and anchor it to an external
append-only database, then verify all anchored checkpoints against the local
chain. Anchoring the tip off-box is what makes tail-truncation and rewrite of
the local chain detectable.

```sh
# credentials via env (preferred; keeps them off the command line)
SYSKNIFE_CHECKPOINT_DB=postgres://user@host/db sysknife audit checkpoint
# or explicitly
sysknife audit checkpoint --db postgres://user@host/db
```

| Flag | Description |
|---|---|
| `--db URL` | Postgres URL of the append-only checkpoint database. Prefer `SYSKNIFE_CHECKPOINT_DB` so credentials are not exposed via `ps` / shell history. |

Each row is signed with Ed25519; verification uses the public key, so an
auditor can verify without the ability to forge. See
[configuration](./configuration.md) for the key and checkpoint-DB env vars.

---

### `sysknife completions <shell>`

Print a shell completion script to stdout.

```sh
sysknife completions bash   >> ~/.bashrc
sysknife completions zsh    >> ~/.zshrc
sysknife completions fish   >> ~/.config/fish/completions/sysknife.fish
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

---

### REPL (no arguments)

```sh
sysknife
```

Starts an interactive session.  Each line is treated as a natural-language
intent and planned + executed in sequence.

**Key bindings:**

| Key | Action |
|---|---|
| ↑ / ↓ | Navigate command history |
| Ctrl+R | Reverse incremental history search |
| Ctrl+A / Ctrl+E | Jump to line start / end |
| Ctrl+W | Delete word before cursor |
| Ctrl+C | Cancel current line (does not exit) |
| Ctrl+D | Exit the REPL |
| `exit` / `quit` | Exit the REPL |

History is persisted to `~/.local/share/sysknife/history` between sessions.

---

## Global flags

All flags apply to every subcommand and to free-form intents.

| Flag | Description |
|---|---|
| `--yes` | Auto-approve LOW-risk steps.  With `--max-risk medium`, also approves MEDIUM.  HIGH always requires human confirmation. |
| `--max-risk LEVEL` | Abort if the plan contains any step above this ceiling.  Values: `low`, `medium`, `high`. |
| `--non-interactive` | Fail immediately (`exit 3`) if any step would require interactive approval.  Use in scripts and CI. |
| `--dry-run` | Print the plan and exit without executing anything. |
| `--step-by-step` | Prompt for approval before each individual step instead of once for the whole plan. |
| `--json` | Emit NDJSON to stdout — one JSON object per event (plan, preview, result).  All colour and spinner output is suppressed.  Safe to pipe. |
| `--timeout SECS` | Hard wall-clock timeout in seconds.  Aborts the whole operation if exceeded. |
| `--log-to FILE` | Tee all stdout output to FILE in addition to the terminal.  Appends if the file exists. |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Planning failed (LLM error, provider unreachable, …) |
| `2` | User rejected the plan or a step |
| `3` | Non-interactive mode but approval was required |
| `4` | Configuration or daemon error |
| `5` | Risk ceiling exceeded |
| `124` | Operation timed out (`--timeout`) |

---

## Environment variables

### LLM provider

`sysknife` auto-detects the provider from API keys.  Set `SYSKNIFE_LLM_PROVIDER`
to override.

| Variable | Description |
|---|---|
| `SYSKNIFE_LLM_PROVIDER` | Force a provider: `anthropic`, `openai`, `gemini`, `ollama`, `groq`, `deepseek`, `mistral`, `xai` |
| `SYSKNIFE_LLM_MODEL` | Override the model name for the selected provider |
| `ANTHROPIC_API_KEY` | Use the Anthropic provider (default model: `claude-sonnet-4-6`) |
| `OPENAI_API_KEY` | Use the OpenAI provider (default model: `gpt-4.1`) |
| `GEMINI_API_KEY` | Use the Gemini provider (default model: `gemini-2.0-flash`) |
| `GROQ_API_KEY` | Use the Groq provider (default model: `llama-3.3-70b-versatile`) |
| `DEEPSEEK_API_KEY` | Use the DeepSeek provider (default model: `deepseek-chat`) |
| `MISTRAL_API_KEY` | Use the Mistral provider (default model: `mistral-large-latest`) |
| `XAI_API_KEY` | Use the xAI provider (default model: `grok-3`) |
| `SYSKNIFE_ANTHROPIC_URL` | Override the Anthropic base URL (default: `https://api.anthropic.com`) |
| `SYSKNIFE_OLLAMA_URL` | Override the Ollama base URL (default: `http://localhost:11434`) |
| `SYSKNIFE_BRAIN_MAX_TURNS` | Planning loop turn limit — integer ≥ 1 (default: `10`) |
| `SYSKNIFE_OLLAMA_THINK` | Set `true`/`false` to override thinking-mode detection for Ollama models |

**Auto-detection order** (when `SYSKNIFE_LLM_PROVIDER` is not set):

1. `ANTHROPIC_API_KEY` present and non-empty → `anthropic`
2. `OPENAI_API_KEY` present → `openai`
3. `GEMINI_API_KEY` present → `gemini`
4. Otherwise → `ollama` (must be running locally)

### Daemon socket

| Variable | Description |
|---|---|
| `SYSKNIFE_SOCKET` | Path to the daemon Unix socket (default: `/run/sysknife/daemon.sock`) |

---

## Scripting and CI

For non-interactive use (scripts, CI pipelines), combine `--json`,
`--non-interactive`, and `--max-risk`:

```sh
# Plan only — parse the JSON to inspect before executing
PLAN=$(sysknife --dry-run --json "check disk usage")
echo "$PLAN" | jq '.plan.steps[].action'

# Execute automatically up to medium risk; fail if anything higher appears
sysknife --yes --max-risk medium --non-interactive "list layered packages"

# Full pipeline with a timeout and log
sysknife --yes --max-risk low --non-interactive --timeout 60 \
     --log-to /var/log/sysknife/run.log \
     "check disk usage"
```

The `--json` output schema:

```jsonc
// Planning output
{ "plan": { "intent": "…", "summary": "…", "steps": [
    { "action": "GetDiskUsage", "summary": "…", "risk": "low", "params": {} }
] } }

// Per-step preview (before execution)
{ "summary": "…", "risk_level": "low", "reboot_required": false,
  "warnings": [], "request_hash": "…", … }

// Per-step result (after execution)
{ "status": "succeeded", "summary": "…", "job_id": "…",
  "needs_reboot": false, "warnings": [], … }
```

---

## Examples

```sh
# Check if any services are failing
sysknife "which systemd services are failed?"

# See recent SysKnife activity
sysknife history --limit 10

# Dry-run a destructive action to inspect the plan
sysknife --dry-run "layer vim via rpm-ostree"

# Execute step-by-step with manual approval of each action
sysknife --step-by-step "update system"

# Non-interactive: fail fast if the plan needs a human
sysknife --non-interactive --max-risk low "check memory pressure"

# Get JSON output and parse with jq
sysknife --dry-run --json "list containers" | jq '.plan.steps[].action'

# Override the LLM for a single run
SYSKNIFE_LLM_PROVIDER=openai OPENAI_API_KEY=sk-... sysknife "check disk usage"

# Use a local Ollama model
SYSKNIFE_LLM_PROVIDER=ollama SYSKNIFE_LLM_MODEL=llama3.2:3b sysknife "list services"
```

---

## Shell completion setup

Run once per shell:

```sh
# bash (add to ~/.bashrc)
eval "$(sysknife completions bash)"

# zsh (add to ~/.zshrc)
eval "$(sysknife completions zsh)"

# fish
sysknife completions fish | source
```

---

## Related

- [Architecture overview](architecture.md) — trust boundary between CLI, shell,
  and daemon
- [Developer guide](developer-guide.md) — building and testing locally
- [User stories](user-stories.md) — end-to-end scenario descriptions
