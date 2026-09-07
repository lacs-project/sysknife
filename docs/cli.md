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

#### `sysknife audit export`

Export the transaction-chain rows from the configured SQLite or PostgreSQL
audit store as a JSON array, in ascending `seq` order. Each object contains the
17 stored `ChainRow` columns, including `prev_chain_hash` and `chain_hash`.
The latter is the Ed25519 signature and is deliberately not renamed. Optional
values that were not recorded are JSON `null`; `argv`, `outcome`, and a
separate `signature` field are not reconstructed.

```sh
sysknife audit export
sysknife audit export --since 2026-08-01T00:00:00Z --limit 500
```

| Flag | Description |
|---|---|
| `--since DATETIME` | Include rows recorded at or after this RFC 3339 timestamp |
| `--limit N` | Emit at most N matching rows; omitted means all matching rows |

An export is not a redacted artifact. It inherits the confidentiality class of
the audit database, which the daemon keeps `0600` inside a `0700` directory, and
writing one moves that content across the boundary those modes exist to hold.

Every row carries `request_hash`, a single unsalted SHA-256 over the action name
and the **unredacted** parameters. `compute_request_hash` runs before
`redact_params`, so redaction never reaches the hashed preimage. Where an
action's parameters are low entropy and partly public the hash is worth
attacking: for `ConfigureWifi` the SSID is broadcast, which leaves the
passphrase as the only unknown. High-entropy values such as `ProAttach` tokens
are unaffected.

The column cannot be dropped, because `request_hash` is part of the signed bytes
an offline verifier rebuilds. Treat an export with the same care as the database
itself rather than as a sanitised report.

#### `sysknife audit verify`

Verify the audit trail: the transaction chain, the approval-event chain, and
the binding between them. All three are reported and any one can fail the
command. Exits `0` if everything is intact, `1` if any check finds tampering,
`2` if a check cannot run at all (missing key, unreadable database). When the
checks disagree the worst wins, and `1` outranks `2` — if something is provably
broken, "could not verify" would understate it.

With `--json` the report is an object with a top-level `status` plus a `chain`,
`approval_events` and `binding` section, so a pipeline can act on which part
failed.

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

### `sysknife mcp-server`

Start an MCP (Model Context Protocol) server over stdio, so Claude Code, Claude
Desktop, Cursor, Codex, and any other MCP-capable agent can drive SysKnife.

```sh
sysknife mcp-server
```

It exposes five fixed tools backed by the SysKnife daemon: `sysknife_plan`,
`sysknife_execute`, `sysknife_history`, `sysknife_doctor`, and
`sysknife_audit_verify`. It also generates direct read-only query tools for the
detected distro, such as `sysknife_get_disk_usage`. Planning and execution stay
behind the same approval interlock as the CLI — `sysknife_plan` returns typed
steps with daemon-issued transaction IDs, and each step still requires an
explicit `sysknife approve <transaction-id>` in a real terminal before it can
run. Low risk is not treated as read-only: `AptUpdate` remains plan-only.

Register it with your agent by pointing it at the binary, e.g. in
`claude_desktop_config.json`:

```json
{ "mcpServers": { "sysknife": { "command": "sysknife", "args": ["mcp-server"] } } }
```

`npx sysknife-setup` writes this configuration for the common clients
automatically.

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
| `--non-interactive` | Fail immediately (`exit 1`) if any step would require interactive approval.  Use in scripts and CI. |
| `--dry-run` | Print the plan and exit without executing anything. |
| `--step-by-step` | Prompt for approval before each individual step instead of once for the whole plan.  Each prompt comes *after* that step's daemon preview is printed. |
| `--json` | Emit NDJSON to stdout — one JSON object per event (plan, preview, result).  All colour and spinner output is suppressed.  Safe to pipe. |
| `--timeout SECS` | Hard wall-clock timeout in seconds.  Aborts the whole operation if exceeded. |
| `--log-to FILE` | Tee all stdout output to FILE in addition to the terminal.  Appends if the file exists. |
| `--dangerously-skip-approval` | Auto-approve HIGH-risk steps as well, with no human confirmation.  Refuses to run unless `SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT=1` is also set.  See [Unattended mode](#unattended-mode). |

---

## Unattended mode

`--dangerously-skip-approval` lets a plan written by a language model execute
HIGH-risk actions with nobody confirming them. It exists for scheduled and
CI-driven runs, and it is the only way to lift the rule that `--yes` can never
auto-approve HIGH.

### Two keys, on purpose

The flag alone does nothing but print an explanation and exit 1. It needs the
environment variable as well:

```sh
SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT=1 \
  sysknife --dangerously-skip-approval --json "apply pending security updates"
```

Neither half is enough alone. A flag left in a script and a variable left in a
shell profile are the two ways this gets armed by accident, and requiring both
means neither accident is sufficient. Only the exact value `1` counts; `true`,
`yes` and `0` are all read as unset.

The flag has no short form and no abbreviation. Typing it has to be a decision.

### What it turns off

One thing: the approval gate.

- `--yes` may now auto-approve HIGH-risk steps. The cap moves from MEDIUM to
  HIGH.
- The post-preview confirmation on a HIGH step no longer asks. The preview is
  still fetched and still printed, because it is the only record of what the
  run was about to change.

An explicit `--max-risk` still wins. `--dangerously-skip-approval --max-risk
low` aborts on a MEDIUM step, because the flag removes the ceiling the project
imposes, not the one you asked for. `--dry-run` still executes nothing.

### What it does not turn off

Everything that makes SysKnife more than a shell:

- Only actions in the typed catalogue can run, with validated parameters. There
  is no path from this flag to an arbitrary command.
- The polkit allowlist still gates every privileged D-Bus call.
- The run still aborts if the daemon rates a step above what the CLI approved.
- Role-based authorization is unchanged. An account that cannot run an action
  still cannot run it.
- Every step is still previewed, still gets a transaction row, and is still
  signed into the audit chain.

If you want a tool that will run any command an LLM writes, this is not it, and
no flag here turns it into one.

### The audit trail records it

A transaction previewed in this mode carries this sentence in its `warnings`:

> Approved without a human: this step was previewed by a client running with
> --dangerously-skip-approval, so no operator confirmed it.

`warnings` is stored as `warnings_json`, and `warnings_json` is one of the
fields inside the row's Ed25519 signature. So the record is not a log line that
can be edited later: deleting it makes `sysknife audit verify` report that row
`Broken`. `sysknife audit export` carries it like any other field.

The CLI checks that the daemon sent the sentence back, and refuses to execute
if it did not. A daemon older than this field accepts the declaration and drops
it, which would leave an unattended run indistinguishable from an approved one.
Upgrade the daemon, or drop the flag.

### Before you use it

Run it against a machine you can rebuild. The failure mode is not a bad diff to
revert; it is a system change applied by a model with no one watching. A VM
snapshot beforehand costs less than the alternative.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Plan or step **refused** — you rejected it, it exceeded the configured risk ceiling, or approval was required but the session is non-interactive |
| `2` | **Execution failed** — the action ran but returned an error (also returned when `--timeout` expires) |
| `3` | **Planning failed** — LLM error, provider unreachable, or the intent could not be turned into a plan |
| `4` | **Configuration or daemon error** — invalid configuration, or the daemon could not be reached |

Subcommands with their own semantics (for example `sysknife audit verify`) pass
through their own exit code.

---

## Environment variables

### LLM provider

`sysknife` auto-detects between Anthropic and local Ollama from the presence of
`ANTHROPIC_API_KEY`. Every other provider must be selected explicitly with
`SYSKNIFE_LLM_PROVIDER` (and its matching API key set).

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

**Auto-detection** (when `SYSKNIFE_LLM_PROVIDER` is not set):

1. `ANTHROPIC_API_KEY` present and non-empty → `anthropic`
2. Otherwise → `ollama` (must be running locally)

The other providers (`openai`, `gemini`, `groq`, `deepseek`, `mistral`, `xai`)
are **not** auto-detected from their API-key variables. To use one, set
`SYSKNIFE_LLM_PROVIDER` to its name and provide the matching key from the table
above.

### Daemon socket

| Variable | Description |
|---|---|
| `SYSKNIFE_SOCKET` | Daemon socket the CLI dials (`unix://`, `vsock://`, or a bare path). Falls back to the same resolution as `SYSKNIFE_LISTEN_URI`: `$XDG_RUNTIME_DIR/sysknife/daemon.sock`, then `/tmp/sysknife-$UID.sock` as a last resort. Production deployments set this via the systemd unit to `/run/sysknife/daemon.sock`. |

### Unattended-mode consent

| Variable | Value | Meaning |
|---|---|---|
| `SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT` | exactly `1` | Second half of the two-key rule for `--dangerously-skip-approval`. Inert on its own: setting it changes nothing until the flag is also passed. Any other value, including `true` and `yes`, reads as unset. |

See [Unattended mode](#unattended-mode) for what the flag does and does not
turn off.

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

# Unattended, including HIGH-risk steps. Both keys are required, and every
# step is recorded in the signed chain as having had no human approval.
SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT=1 \
  sysknife --dangerously-skip-approval --json --timeout 300 \
     "apply pending security updates"
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
