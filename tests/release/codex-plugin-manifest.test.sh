#!/usr/bin/env bash
# Guards .codex-plugin/plugin.json against the metadata gaps that cost trust
# points in the HOL Registry listing, and a .codexignore that goes missing.
#
# The registry scores plugins with hashgraph-online/hol-guard, whose checks read
# this manifest with the repository root as the plugin directory. Two of its
# checks are all-or-nothing, so a single absent field zeroes the whole check:
#
#   Recommended metadata present (4 pts) wants author, homepage, repository,
#   license and keywords. Only `homepage` was ever missing here, and its absence
#   scored the same as a malformed manifest.
#
#   .codexignore found (3 pts) wants the file to exist at the repository root.
#
# Neither gap breaks a build, so no Rust test sees them. Both are asserted here.
#
# The interface URL check (websiteURL, privacyPolicyURL, termsOfServiceURL and
# screenshots, 3 pts) is deliberately NOT asserted. It is all-or-nothing too,
# and SysKnife publishes no privacy policy or terms of service because the
# daemon transmits nothing. Declaring `websiteURL` alone earns zero points, so
# the manifest states what is true instead of what scores.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest="$repo_root/.codex-plugin/plugin.json"

fail() {
    printf 'codex-plugin-manifest: %s\n' "$1" >&2
    exit 1
}

[[ -f "$manifest" ]] || fail '.codex-plugin/plugin.json is missing'

field() { node -p "JSON.parse(require('fs').readFileSync('$manifest','utf8'))$1"; }

# --- Recommended metadata: the scanner's RECOMMENDED_FIELDS, verbatim ---
for key in author homepage repository license keywords; do
    present="$(field ".$key !== undefined")"
    [[ "$present" == "true" ]] \
        || fail "recommended field \"$key\" is missing from the manifest"
done

# author and keywords carry a shape requirement beyond mere presence.
[[ "$(field ".author.name ? 'yes' : 'no'")" == "yes" ]] \
    || fail 'author.name must be a non-empty string'
[[ "$(field ".keywords.length > 0")" == "true" ]] \
    || fail 'keywords must be a non-empty array'

# homepage and repository are read as links by the registry listing, so an
# http:// or relative value would render as a broken destination.
for key in homepage repository; do
    value="$(field ".$key")"
    [[ "$value" == https://* ]] \
        || fail "$key is '$value', expected an https:// URL"
done

# --- Declared interface assets have to exist, or the listing renders a gap ---
for key in composerIcon logo; do
    value="$(field ".interface.$key")"
    [[ -n "$value" && "$value" != undefined ]] \
        || fail "interface.$key is not declared"
    # Paths are relative to the repository root, which is the plugin directory
    # the scanner passes in.
    resolved="$repo_root/${value#./}"
    [[ -f "$resolved" ]] \
        || fail "interface.$key points at '$value', which does not exist"
done

# The manifest names the file that declares the MCP servers; a stale path there
# publishes a plugin that installs and then exposes nothing.
mcp_servers="$(field ".mcpServers")"
[[ -f "$repo_root/${mcp_servers#./}" ]] \
    || fail "mcpServers points at '$mcp_servers', which does not exist"

# --- .codexignore ---
[[ -f "$repo_root/.codexignore" ]] \
    || fail '.codexignore is missing from the repository root'
[[ -s "$repo_root/.codexignore" ]] \
    || fail '.codexignore exists but is empty'

# A .codexignore that fails to cover the build directory ships the whole target
# tree to anything that walks the plugin, which is what the file exists to stop.
grep -qE '^/?target/?$' "$repo_root/.codexignore" \
    || fail '.codexignore does not exclude the Rust target directory'

printf 'codex-plugin-manifest: OK\n'
