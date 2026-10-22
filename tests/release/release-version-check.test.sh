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

python3 "$fixture/scripts/release_versions.py" check 0.26.0 >/dev/null
cp "$fixture/Cargo.lock" "$fixture/Cargo.lock.baseline"
python3 - "$fixture/Cargo.lock" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text, replacements = re.subn(r'(^name = "sysknife-cli"\nversion = ")0\.26\.0("$)', r'\g<1>0.25.0\2',
                             path.read_text(), count=1, flags=re.M)
if replacements != 1:
    raise SystemExit("fixture could not find sysknife-cli 0.26.0 in Cargo.lock")
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
python3 - "$fixture/CHANGELOG.md" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text, replacements = re.subn(r'(^## \[)0\.26\.0(\])', r'\g<1>0.25.0\2', path.read_text(), count=1, flags=re.M)
if replacements != 1:
    raise SystemExit("fixture could not find the latest release heading")
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
