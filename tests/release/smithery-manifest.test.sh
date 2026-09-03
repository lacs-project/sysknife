#!/usr/bin/env bash
# Guards smithery.yaml -- the manifest Smithery reads to run SysKnife's MCP
# server on a user's own machine -- against the ways it can silently rot.
#
# Smithery has two deployment runtimes, and only one of them can work here:
#
#   runtime: typescript / container  ->  Smithery HOSTS the server in its cloud
#                                        and requires Streamable HTTP.
#   startCommand.type: stdio         ->  Smithery's CLI SPAWNS the server on the
#                                        user's machine over stdio.
#
# SysKnife must use the stdio form. The MCP server is the unprivileged half of
# the system; it has nothing to offer until it can reach sysknife-daemon over a
# local unix socket, which a hosted container cannot provide. Running locally is
# not a limitation of the listing, it is the only shape that produces a working
# server. See docs/mcp-registry.md.
#
# Three failure modes are asserted:
#
# 1. Wrong runtime. Someone "modernises" the file to runtime: container, and the
#    listing starts booting a daemonless sandbox that reports zero tools.
# 2. Command drift. The CLI subcommand is renamed and the manifest keeps naming
#    the old one, so every install fails at spawn.
# 3. A placeholder credential in configSchema. A tracked manifest carrying a
#    fake API key is how a real one eventually gets committed; SysKnife reads
#    provider credentials from the environment instead.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$repo_root/smithery.yaml"
cli_source="$repo_root/apps/sysknife-cli/src/cli.rs"

fail() {
    printf 'smithery-manifest: %s\n' "$1" >&2
    exit 1
}

[[ -f "$manifest" ]] || fail 'smithery.yaml is missing from the repository root'
[[ -f "$cli_source" ]] || fail "cannot read $cli_source to cross-check the subcommand"

# yq is not a repo dependency, so read the two scalars with grep rather than a
# YAML parser. Both live at a known depth and the guard below rejects anything
# that would make the shape ambiguous.
if grep -qE '^[[:space:]]*runtime:' "$manifest"; then
    fail 'smithery.yaml declares a runtime; hosted runtimes need Streamable HTTP and a daemonless container cannot serve SysKnife'
fi

start_type="$(grep -A2 '^startCommand:' "$manifest" | grep -oP '^\s*type:\s*"?\K[a-z]+' | head -1 || true)"
[[ "$start_type" == "stdio" ]] \
    || fail "startCommand.type is '${start_type:-<missing>}', expected stdio"

grep -q 'commandFunction:' "$manifest" \
    || fail 'startCommand.commandFunction is missing; Smithery has no way to spawn the server'

# The spawned command must be the real binary and the real subcommand.
grep -q "command: *'sysknife'" "$manifest" \
    || fail "commandFunction does not spawn the 'sysknife' binary"

subcommand="$(grep -oP "args: *\[ *'\K[a-z-]+" "$manifest" | head -1 || true)"
[[ -n "$subcommand" ]] || fail 'commandFunction passes no subcommand'

# Cross-check against the CLI itself: #[command(name = "mcp-server")] is the
# single source of truth for what the binary answers to.
grep -q "#\[command(name = \"${subcommand}\")\]" "$cli_source" \
    || fail "commandFunction runs 'sysknife ${subcommand}', which is not a subcommand declared in apps/sysknife-cli/src/cli.rs"

# No placeholder credentials. Provider keys come from the environment.
if grep -qiE '(api_?key|token|secret|password)' "$manifest"; then
    fail 'smithery.yaml mentions a credential field; SysKnife reads provider keys from the environment, and a placeholder key in a tracked file is how a real one gets committed'
fi

printf 'smithery-manifest: OK\n'
