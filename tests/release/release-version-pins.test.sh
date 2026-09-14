#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

paths=(
    scripts/check_release_versions.sh
    apps/sysknife-cli/Cargo.toml
    apps/sysknife-shell/package.json
    apps/sysknife-shell/package-lock.json
    apps/sysknife-shell/src-tauri/Cargo.toml
    apps/sysknife-shell/src-tauri/tauri.conf.json
    crates/sysknife-brain/Cargo.toml
    crates/sysknife-core/Cargo.toml
    crates/sysknife-daemon-test/Cargo.toml
    crates/sysknife-daemon/Cargo.toml
    crates/sysknife-proto/Cargo.toml
    crates/sysknife-types/Cargo.toml
    packages/setup/package.json
    .codex-plugin/plugin.json
    server.json
)

for path in "${paths[@]}"; do
    mkdir -p "$fixture/$(dirname "$path")"
    cp "$repo_root/$path" "$fixture/$path"
done

bash "$fixture/scripts/check_release_versions.sh" >/dev/null

python3 - "$fixture/crates/sysknife-brain/Cargo.toml" <<'PY'
from pathlib import Path
import re
import sys

manifest = Path(sys.argv[1])
contents = manifest.read_text()
mutated, replacements = re.subn(
    r'^(sysknife-core = \{ path = "[^"]*"), version = "[^"]*"( \})$',
    r'\1\2',
    contents,
    count=1,
    flags=re.MULTILINE,
)
if replacements != 1:
    raise SystemExit("fixture could not remove the sysknife-core version pin")
manifest.write_text(mutated)
PY

if output="$(bash "$fixture/scripts/check_release_versions.sh" 2>&1)"; then
    printf 'release-version-pins: missing inline version unexpectedly passed\n' >&2
    exit 1
fi

grep -Fq 'crates/sysknife-brain/Cargo.toml' <<<"$output" || {
    printf 'release-version-pins: failure omitted the manifest path: %s\n' "$output" >&2
    exit 1
}
grep -Fq 'missing an explicit version pin' <<<"$output" || {
    printf 'release-version-pins: failure did not explain the missing pin: %s\n' "$output" >&2
    exit 1
}

printf 'release-version-pins: missing inline versions fail explicitly.\n'
