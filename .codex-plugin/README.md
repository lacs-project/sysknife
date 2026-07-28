# Codex plugin manifest

`plugin.json` is the manifest Codex plugin directories read to list SysKnife —
notably [`hashgraph-online/awesome-codex-plugins`](https://github.com/hashgraph-online/awesome-codex-plugins),
whose `scripts/validate-plugin-pr.py` fetches this repository and fails the
listing PR if `.codex-plugin/plugin.json` is absent or incomplete.

`mcp.json` declares how to launch the server. It deliberately carries **no
`env` block**: SysKnife reads its LLM credentials from the environment
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …), and a manifest with a placeholder
key invites someone to paste a real one into a tracked file. The root
`.mcp.json.example` shows the fuller shape for local development, and root
`.mcp.json` is gitignored for the same reason.

`command` is the bare `sysknife` name, so it resolves from `PATH` after any of
the supported installs (`npx sysknife-setup`, `cargo install sysknife-cli`, or a
release binary). Nothing here needs the daemon: `tools/list` answers from the
statically registered tool router, so a directory can introspect the server
without a privileged process running.

## Keeping it current

`version` must match the released version. `scripts/check_release_versions.sh`
includes this file, so a release that forgets to bump it fails CI rather than
publishing a manifest that misreports which version a directory is listing.

`interface.composerIcon` must resolve to a file in this repository under 50KB —
`assets/raster/sysknife-256.png` is ~16KB. See `assets/raster/README.md` for how
the PNGs are regenerated from the SVG sources.
