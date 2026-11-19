# Demo assets

Four demo recordings live here: the Ubuntu MCP flow, the Fedora Atomic MCP
flow, the standalone CLI, and the audit-tamper demo. The first three replay a
mock script. The audit-tamper demo runs the shipped binaries.

Ubuntu is the primary target, so `ubuntu-flow.gif` is the README hero. Keep it
that way when adding recordings.

---

## Ubuntu MCP flow demo (primary hero)

`ubuntu-flow.tape` + `ubuntu-flow-mock.sh` -> `ubuntu-flow.gif`

Shows a Claude Code session on Ubuntu 24.04: `sysknife_plan` returns three
transaction IDs across all three risk tiers, the operator approves each one with
`sysknife approve <transaction-id>` in a separate terminal, and Claude passes the
one-time receipts to `sysknife_execute`. Receipts are consumed and the audit hash
is printed. A chat response alone is never presented as approval.

Every action name, risk level and command in the mock is the one the catalogue
carries, checked against `docs/action-reference.md`:

| action | command | risk |
|---|---|---|
| `UfwAllow` | `sudo ufw allow 22` | High |
| `AptInstall` | `sudo env DEBIAN_FRONTEND=noninteractive ... apt-get install -y curl` | Medium |
| `UfwStatus` | `sudo ufw status verbose` | Low |

`GetFirewallState` is deliberately absent: it runs `firewall-cmd`, which is
firewalld, so it has no meaning on an Ubuntu host.

### Regenerate the Ubuntu GIF

```bash
# Render raw GIF with VHS
vhs assets/demo/ubuntu-flow.tape

# Reduce the frame count and palette. The frame step is not cosmetic: LinkedIn
# freezes an uploaded GIF on its first frame above 400 frames, and a raw VHS
# render of this tape lands at 424. 10 fps keeps all 17 seconds and yields 170.
ffmpeg -y -i assets/demo/ubuntu-flow.gif \
  -vf "fps=10,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3" \
  assets/demo/ubuntu-flow.tmp.gif
mv assets/demo/ubuntu-flow.tmp.gif assets/demo/ubuntu-flow.gif
```

Budget: 1000 x 600, under 400 frames, under 5 MB. Current render is 170 frames,
17.0 s, 2.12 MB.

---

## Fedora Atomic MCP flow demo (secondary)

`mcp-flow.tape` + `mcp-flow-mock.sh` → `mcp-flow.gif`

Shows a Claude Code session where `sysknife_plan` returns daemon transaction
IDs, the user approves each accepted preview with
`sysknife approve <transaction-id>` in a separate terminal, and Claude passes
the one-time receipts to `sysknife_execute`. Execution streams back, receipts
are consumed, and the audit hash is printed. A chat response alone is never
presented as approval.

### Regenerate MCP GIF

```bash
# Render raw GIF with VHS
vhs assets/demo/mcp-flow.tape

# Deterministically reduce the palette after rendering
gifsicle -O3 --colors 128 assets/demo/mcp-flow.gif \
  -o assets/demo/mcp-flow.optimized.gif
mv assets/demo/mcp-flow.optimized.gif assets/demo/mcp-flow.gif
```

---

## CLI demo (secondary — CLI section of the README + CLI-specific docs)

`demo.tape` + `demo-mock.sh` → `demo.gif`

Shows the standalone `sysknife` CLI: planning spinner, plan card, approval
prompt, streamed step execution, audit hash. Mirrors the render styling of
`apps/sysknife-cli/src/render.rs`.

The tape runs `demo-mock.sh` inside a VHS `Hide`/`Show` block so the recording
opens directly on the `$ sysknife "…"` prompt, not on the bootstrap command that
launches the mock.

### Regenerate CLI GIF

```bash
# Install VHS (first time only)
go install github.com/charmbracelet/vhs@latest
# or: brew install charmbracelet/tap/vhs

# Render
vhs assets/demo/demo.tape
```

Output: `demo.gif`.

---

## Sizing rules

- **MCP width x height = 1000 x 600**; CLI width x height = 1200 x 720.
- Keep each GIF under 5 MB so the README remains usable on slower links.
- FontSize 18 for the MCP flow (more content fits on screen); 24 for the CLI demo.
- Keep the hero recording under 400 frames. Above that LinkedIn shows frame one
  as a still instead of animating, and a terminal recording's first frame is a
  near-empty header bar. `mcp-flow.gif` (822 frames) and `demo.gif` (602) both
  exceed it and are not meant for that surface.

## Why mocks instead of live binaries?

Recording against the live CLI or MCP server would require a daemon socket,
an LLM provider key, and a network round-trip, and would produce a different
recording on every run. The mock scripts are deterministic: every regeneration
produces byte-identical frames.

If you ever need to record against a real daemon, point the tape at the live
binary, but commit the resulting GIF only — never a tape that depends on
external side conditions.

---

## Audit-tamper demo (the audit chain, README "How it works")

`audit-tamper.tape` + `audit-tamper.sh` -> `audit-tamper.gif`

Shows what an operator sees the morning after an agent worked on a server, and
what `sysknife audit verify` does when someone edits the log. Unlike the three
recordings above it replays no mock: the daemon, `sysknife mcp-server`, the
approval receipts, the Ed25519 chain and `verify` are the real binaries, running
in an Ubuntu 26.04 container named `web01`.

| Piece | What it is |
|---|---|
| `audit-tamper.sh seed` | Runs one agent session and saves the daemon state under `~/.cache/sysknife-demo/state`. Needs a provider key. |
| `audit-tamper-agent.py` | A stand-in for the MCP client. It calls `sysknife_plan` on the real MCP server, fetches a receipt from `sysknife approve` for Low-risk steps only, and calls `sysknife_execute`. An LLM plans every request. |
| `audit-tamper-guest.sh` | Runs inside the container: creates the operator account, starts the daemon, opens the root prompt. |
| `audit-tamper.sh shell` | Opens a prompt on a copy of the saved state, so every recording starts from the same six rows. |
| `audit-tamper.tape` | The recording. It needs no provider key; the first run builds the container image. |

The six requests are Low reads (disk usage, processes, listening ports) and three
changes (install a package, open port 22, turn off ssh password login). The
operator approves the reads. The three changes stay previewed and unapproved, so
they sit in the chain as unapproved previews, and the daemon sweeps them to `canceled`
when they expire. The recording starts well after that, so the history shows `canceled`;
the sweep writes a signed status event, which is why `verify` still reports the statuses as matching.

### Regenerate the GIF

```bash
cargo build -p sysknife-cli -p sysknife-daemon

# Once, or whenever the planner prompt changes what the model proposes.
SYSKNIFE_LLM_PROVIDER=groq SYSKNIFE_LLM_MODEL=openai/gpt-oss-120b GROQ_API_KEY=... \
  assets/demo/audit-tamper.sh seed

vhs assets/demo/audit-tamper.tape

# Same frame budget as the other recordings: under 400 frames.
ffmpeg -y -i assets/demo/audit-tamper.gif \
  -vf "fps=10,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3" \
  assets/demo/audit-tamper.tmp.gif
mv assets/demo/audit-tamper.tmp.gif assets/demo/audit-tamper.gif
```

`seed` fails unless the saved chain holds at least two executed and two queued
rows, so a model that plans differently cannot silently change what the recording
means. The container holds only the seeded state: the daemon sees a clean host
and the daemon reports on that container, never on the machine that records it.

The tamper edits the signed `action_name` and `summary` of one row. `verify` then
reports the first row that no longer chains, and the same verdict comes from
`--pubkey audit-key.pub`, which needs no daemon and no private key.
