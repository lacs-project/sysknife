# Demo assets

Two demo recordings live here — one for the standalone CLI and one for the
Claude Code MCP flow.

---

## MCP flow demo (primary hero)

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

## Why mocks instead of live binaries?

Recording against the live CLI or MCP server would require a daemon socket,
an LLM provider key, and a network round-trip, and would produce a different
recording on every run. The mock scripts are deterministic: every regeneration
produces byte-identical frames.

If you ever need to record against a real daemon, point the tape at the live
binary, but commit the resulting GIF only — never a tape that depends on
external side conditions.
