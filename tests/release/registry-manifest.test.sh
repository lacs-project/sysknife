#!/usr/bin/env bash
# Guards server.json -- the manifest published to the official MCP Registry --
# against the two ways it can silently stop working.
#
# 1. Ownership. The cargo validator proves ownership by fetching the crate's
#    RENDERED README from crates.io and searching for a plain-text
#    `mcp-name: <server name>` token. crates.io strips HTML comments when
#    rendering, so a well-meaning edit that tucks the marker into a comment, or
#    a README rewrite that drops it, makes the next publish fail authorization.
# 2. Coupling. The marker only exists in a *published* crate version, so
#    server.json's version must name the crate version that carries it, and the
#    packaged crate must actually ship the README.
#
# Neither failure is visible to the Rust test suite, so it is asserted here.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
server_json="$repo_root/server.json"
crate_readme="$repo_root/apps/sysknife-cli/README.md"

fail() {
    printf 'registry-manifest: %s\n' "$1" >&2
    exit 1
}

[[ -f "$server_json" ]] || fail 'server.json is missing from the repository root'

field() { node -p "JSON.parse(require('fs').readFileSync('$server_json','utf8'))$1"; }

name="$(field ".name")"
version="$(field ".version")"
pkg_count="$(field ".packages.length")"
registry_type="$(field ".packages[0].registryType")"
registry_base="$(field ".packages[0].registryBaseUrl")"
identifier="$(field ".packages[0].identifier")"
pkg_version="$(field ".packages[0].version")"
transport="$(field ".packages[0].transport.type")"

[[ "$pkg_count" == "1" ]] \
    || fail "expected exactly one package entry, found $pkg_count"
[[ "$registry_type" == "cargo" ]] \
    || fail "packages[0].registryType is '$registry_type', expected cargo"
# The validator rejects any other base URL for a cargo package outright.
[[ "$registry_base" == "https://crates.io" ]] \
    || fail "packages[0].registryBaseUrl is '$registry_base', expected https://crates.io"
[[ "$transport" == "stdio" ]] \
    || fail "packages[0].transport.type is '$transport', expected stdio"
[[ "$pkg_version" == "$version" ]] \
    || fail "packages[0].version $pkg_version does not match server version $version"

# The listed crate has to be the one that installs the `sysknife` binary, and
# its version has to be this release's version -- the crate release is what
# publishes the README the validator reads.
crate_manifest="$repo_root/apps/sysknife-cli/Cargo.toml"
crate_name="$(sed -n 's/^name = "\([^"]*\)"/\1/p' "$crate_manifest" | head -n 1)"
crate_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$crate_manifest" | head -n 1)"
[[ "$identifier" == "$crate_name" ]] \
    || fail "packages[0].identifier is '$identifier', expected the CLI crate '$crate_name'"
[[ "$version" == "$crate_version" ]] \
    || fail "server.json version $version does not match $crate_name $crate_version"

# `sysknife`'s MCP server is a subcommand, so the listing has to carry it as a
# positional argument. Without it a client runs the bare CLI, which prints help
# and exits instead of speaking JSON-RPC.
subcommand="$(field ".packages[0].packageArguments?.filter(a => a.type === 'positional').map(a => a.value).join(',') ?? ''")"
[[ "$subcommand" == "mcp-server" ]] \
    || fail "packages[0].packageArguments positional values are '$subcommand', expected exactly mcp-server"

# ---------------------------------------------------------------------------
# The crates.io ownership marker
# ---------------------------------------------------------------------------

marker="mcp-name: $name"

grep -Fq "$marker" "$crate_readme" \
    || fail "apps/sysknife-cli/README.md does not contain '$marker'; the registry could not verify ownership"

# crates.io renders the README as Markdown, so anything inside an HTML comment
# disappears before the validator ever sees it.
if node -e "
const fs = require('fs');
const src = fs.readFileSync('$crate_readme', 'utf8');
const visible = src.replace(/<!--[\s\S]*?-->/g, '');
process.exit(visible.includes('$marker') ? 1 : 0);
"; then
    fail "'$marker' in apps/sysknife-cli/README.md survives only inside an HTML comment; crates.io strips those when rendering"
fi

# A marker in a README that the packaged crate does not ship is a marker the
# validator cannot fetch.
grep -Eq '^readme = ' "$crate_manifest" || grep -Fq 'README.md' "$crate_manifest" \
    || fail "apps/sysknife-cli/Cargo.toml does not reference README.md, so the packaged crate may omit it"

printf 'registry-manifest: server.json -> cargo %s@%s (%s) with a rendered ownership marker.\n' \
    "$identifier" "$version" "$subcommand"
