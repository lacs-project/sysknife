#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

paths=(scripts/check_release_versions.sh scripts/release_versions.py release-versions.json)
while IFS= read -r site; do
    [ -n "$site" ] && paths+=("$site")
done < <(python3 "$repo_root/scripts/release_versions.py" sites)
for path in "${paths[@]}"; do
    mkdir -p "$fixture/$(dirname "$path")"
    cp "$repo_root/$path" "$fixture/$path"
done

current_version="$(python3 "$fixture/scripts/release_versions.py" values | sed -n '1p')"
stale_version="$(python3 - "$current_version" <<'PY'
import sys

major, minor, patch = map(int, sys.argv[1].split("."))
print(f"{major}.{minor}.{patch + 1}")
PY
)"
python3 "$fixture/scripts/release_versions.py" check "$current_version" >/dev/null
cp "$fixture/Cargo.lock" "$fixture/Cargo.lock.baseline"
python3 - "$fixture/Cargo.lock" "$current_version" "$stale_version" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
current, stale = sys.argv[2:]
pattern = rf'(^name = "sysknife-cli"\nversion = "){re.escape(current)}("$)'
replacement = rf'\g<1>{stale}\2'
text, replacements = re.subn(pattern, replacement,
                             path.read_text(), count=1, flags=re.M)
if replacements != 1:
    raise SystemExit(f"fixture could not find sysknife-cli {current} in Cargo.lock")
path.write_text(text)
PY
if output="$(python3 "$fixture/scripts/release_versions.py" check 2>&1)"; then
    printf 'release-version-check: stale Cargo.lock workspace version unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'Cargo.lock' <<<"$output" || {
    printf 'release-version-check: failure omitted Cargo.lock: %s\n' "$output" >&2
    exit 1
}
grep -Fq 'sysknife-cli' <<<"$output" || {
    printf 'release-version-check: failure omitted the workspace package: %s\n' "$output" >&2
    exit 1
}
mv "$fixture/Cargo.lock.baseline" "$fixture/Cargo.lock"

cp "$fixture/CHANGELOG.md" "$fixture/CHANGELOG.md.baseline"
python3 - "$fixture/CHANGELOG.md" "$current_version" "$stale_version" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
current, stale = sys.argv[2:]
pattern = rf'(^## \[){re.escape(current)}(\])'
replacement = rf'\g<1>{stale}\2'
text, replacements = re.subn(pattern, replacement, path.read_text(), count=1, flags=re.M)
if replacements != 1:
    raise SystemExit(f"fixture could not find the {current} release heading")
path.write_text(text)
PY
if output="$(python3 "$fixture/scripts/release_versions.py" check 2>&1)"; then
    printf 'release-version-check: stale changelog heading unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'CHANGELOG.md' <<<"$output" || {
    printf 'release-version-check: failure omitted CHANGELOG.md: %s\n' "$output" >&2
    exit 1
}
mv "$fixture/CHANGELOG.md.baseline" "$fixture/CHANGELOG.md"

printf 'release-version-check: Cargo.lock and changelog versions are checked.\n'
