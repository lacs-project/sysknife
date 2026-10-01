#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

# The fixture is built from release-versions.json, not from a list kept here.
# This file used to carry its own copy of every manifest, which made four
# places that had to agree about what a release touches: this test, the
# checker, the bump script and the registry. Deriving it means a new crate is
# registered once.
paths=(
    scripts/check_release_versions.sh
    scripts/release_versions.py
    release-versions.json
)
if ! registered="$(python3 "$repo_root/scripts/release_versions.py" sites)"; then
    echo "FAIL: could not read the version registry; the fixture would be empty" >&2
    exit 1
fi
while IFS= read -r site; do
    [ -n "$site" ] && paths+=("$site")
done <<<"$registered"

# A fixture built from an empty registry would make every assertion below pass
# over nothing, which is the shape this repository keeps catching.
if [ "${#paths[@]}" -le 3 ]; then
    echo "FAIL: the registry named no version sites; the fixture inspects nothing" >&2
    exit 1
fi

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
