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

printf 'All release versions match %s.\n' "$baseline"
