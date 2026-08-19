#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected="${1:-}"
expected="${expected#v}"

manifests=(
    apps/sysknife-cli/Cargo.toml
    apps/sysknife-shell/src-tauri/Cargo.toml
    crates/sysknife-brain/Cargo.toml
    crates/sysknife-core/Cargo.toml
    crates/sysknife-daemon-test/Cargo.toml
    crates/sysknife-daemon/Cargo.toml
    crates/sysknife-proto/Cargo.toml
    crates/sysknife-types/Cargo.toml
)

versions=()
for manifest in "${manifests[@]}"; do
    version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/$manifest" | head -n 1)"
    if [[ -z "$version" ]]; then
        printf 'No package version found in %s\n' "$manifest" >&2
        exit 1
    fi
    versions+=("$version")
done

versions+=("$(node -p "require('$repo_root/apps/sysknife-shell/package.json').version")")
versions+=("$(node -p "require('$repo_root/apps/sysknife-shell/package-lock.json').version")")
versions+=("$(node -p "require('$repo_root/apps/sysknife-shell/src-tauri/tauri.conf.json').version")")
versions+=("$(node -p "require('$repo_root/packages/setup/package.json').version")")
# The Codex plugin manifest reports the version to plugin directories, so a
# release that forgets it publishes a listing that misstates what is shipped.
versions+=("$(node -p "require('$repo_root/.codex-plugin/plugin.json').version")")
# server.json is the manifest published to the official MCP Registry. Its
# version names the crate version whose rendered README carries the ownership
# marker, so a stale value here fails authorization at publish time.
versions+=("$(node -p "require('$repo_root/server.json').version")")
versions+=("$(node -p "require('$repo_root/server.json').packages[0].version")")

baseline="${versions[0]}"
for version in "${versions[@]}"; do
    if [[ "$version" != "$baseline" ]]; then
        printf 'Release versions are inconsistent: expected %s, found %s\n' "$baseline" "$version" >&2
        exit 1
    fi
done

if [[ -n "$expected" && "$baseline" != "$expected" ]]; then
    printf 'Release tag version %s does not match package version %s\n' "$expected" "$baseline" >&2
    exit 1
fi

# Internal path dependencies carry an explicit `version` next to `path`, and that
# field is what crates.io resolves at publish time. A bump that misses one
# publishes sysknife-brain 0.9.0 depending on sysknife-core ^0.8.0, which resolves
# to the crate already on the registry instead of the tree that was just built,
# and the mistake is invisible until someone builds against the published crate.
# The package-version loop above reads only `[package] version`, so these need
# their own pass.
pins="$(grep -rn '^sysknife-[a-z-]* = {' \
    "$repo_root"/crates/*/Cargo.toml \
    "$repo_root"/apps/sysknife-cli/Cargo.toml \
    "$repo_root"/apps/sysknife-shell/src-tauri/Cargo.toml |
    grep 'version = ')"

# An empty result means the manifests moved, not that every pin agrees. Fail
# loudly rather than reporting success for a check that inspected nothing.
if [[ -z "$pins" ]]; then
    printf 'No internal dependency pins found; the manifest paths in %s are stale.\n' \
        "${BASH_SOURCE[0]}" >&2
    exit 1
fi

pin_count=0
while IFS= read -r pin; do
    pin_count=$((pin_count + 1))
    pinned="$(printf '%s' "$pin" | sed -n 's/.*version = "\([^"]*\)".*/\1/p')"
    if [[ "$pinned" != "$baseline" ]]; then
        printf 'Internal dependency pin does not match package version %s:\n  %s\n' \
            "$baseline" "$pin" >&2
        exit 1
    fi
done <<< "$pins"

printf 'All release versions match %s (%d internal dependency pins checked).\n' \
    "$baseline" "$pin_count"
