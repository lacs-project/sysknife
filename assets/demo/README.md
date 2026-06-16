# Demo assets

Two demo recordings live here — one for the standalone CLI and one for the
Claude Code MCP flow.

---

## MCP flow demo (primary hero)

`mcp-flow.tape` + `mcp-flow-mock.sh` → `mcp-flow.gif`

Shows a Claude Code session where the user asks a sysadmin question, Claude
calls the `sysknife_plan` MCP tool, presents a bordered plan card with risk
badges, the user approves, Claude calls `sysknife_execute`, steps stream
back, and the audit hash is printed. This is the primary README hero — it
communicates "use SysKnife via your AI IDE."

### Regenerate MCP GIF

```bash
# Render raw GIF with VHS
vhs assets/demo/mcp-flow.tape

# Optimize to stay under the 3 MB ceiling
ffmpeg -y -i assets/demo/mcp-flow.gif \
  -vf "fps=10,scale=1200:720:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=64[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3" \
  -loop 0 assets/demo/mcp-flow.gif
```

---

## CLI demo (secondary / CLI-specific docs)

`demo.tape` + `demo-mock.sh` → `demo.gif`

Shows the standalone `sysknife` CLI: planning spinner, plan card, approval
prompt, streamed step execution, audit hash. Mirrors the render styling of
`apps/sysknife-cli/src/render.rs`.

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

- **Width × Height = 1200 × 720** for both recordings.
- **GIF must stay under 3 MB** (GitHub's mobile renderer hard ceiling).
- FontSize 18 for the MCP flow (more content fits on screen); 24 for the CLI demo.

## Why mocks instead of live binaries?

Recording against the live CLI or MCP server would require a daemon socket,
an LLM provider key, and a network round-trip, and would produce a different
recording on every run. The mock scripts are deterministic: every regeneration
produces byte-identical frames.

If you ever need to record against a real daemon, point the tape at the live
binary, but commit the resulting GIF only — never a tape that depends on
external side conditions.
