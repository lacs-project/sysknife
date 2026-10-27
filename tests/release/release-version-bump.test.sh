#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

make_fixture() {
    local fixture="$1"
    local -a paths=(scripts/bump_version.sh scripts/check_release_versions.sh scripts/release_versions.py release-versions.json)
    mkdir -p "$fixture"
    while IFS= read -r site; do
        [ -n "$site" ] && paths+=("$site")
    done < <(python3 "$repo_root/scripts/release_versions.py" sites)
    for path in "${paths[@]}"; do
        mkdir -p "$fixture/$(dirname "$path")"
        cp "$repo_root/$path" "$fixture/$path"
    done
    git -C "$fixture" init -q
    git -C "$fixture" config user.name "Release version fixture"
    git -C "$fixture" config user.email "release-version-fixture@example.invalid"
    git -C "$fixture" add .
    git -C "$fixture" -c commit.gpgsign=false commit -qm "fixture baseline"
}

failed="$scratch/failed"
make_fixture "$failed"
current_version="$(python3 "$failed/scripts/release_versions.py" values | sed -n '1p')"
target_version="$(python3 - "$current_version" <<'PY'
import sys

major, minor, patch = map(int, sys.argv[1].split("."))
print(f"{major}.{minor}.{patch + 1}")
PY
)"
mkdir -p "$scratch/bin"
mkdir -p "$failed/scratch/untracked"
printf '%s\n' 'must not be copied into the staged tree' >"$failed/scratch/untracked/marker.txt"
cat >"$scratch/bin/cargo" <<'SH'
#!/usr/bin/env sh
if [ -e scratch/untracked/marker.txt ]; then
    printf 'untracked worktree files were copied into the staged tree\n' >&2
    exit 2
fi
printf 'simulated offline lockfile refresh failure\n' >&2
exit 1
SH
chmod +x "$scratch/bin/cargo"

failed_state="$(git -C "$failed" status --porcelain)"
if output="$(PATH="$scratch/bin:$PATH" bash "$failed/scripts/bump_version.sh" "$target_version" --date 2026-10-22 2>&1)"; then
    printf 'release-version-bump: failed lock refresh unexpectedly succeeded\n' >&2
    exit 1
fi
grep -Fq 'simulated offline lockfile refresh failure' <<<"$output" || {
    printf 'release-version-bump: injected Cargo failure was not reported: %s\n' "$output" >&2
    exit 1
}
if [ "$(git -C "$failed" status --porcelain)" != "$failed_state" ]; then
    printf 'release-version-bump: failed lock refresh changed the fixture:\n%s\n' \
        "$(git -C "$failed" status --short)" >&2
    exit 1
fi

success="$scratch/success"
make_fixture "$success"
python3 - "$success/CHANGELOG.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()
heading = "## [Unreleased]"
if text.count(heading) != 1:
    raise SystemExit("fixture could not find the Unreleased section")
path.write_text(text.replace(heading, heading + "\n\n- Fixture release note.", 1))
PY
mkdir -p "$scratch/bin-success"
cat >"$scratch/bin-success/cargo" <<'SH'
#!/usr/bin/env python3
import json
import re
from pathlib import Path

root = Path.cwd()
config = json.loads((root / "release-versions.json").read_text())
members = {}
for rel in config["cargo_manifests"]:
    manifest = (root / rel).read_text()
    name = re.search(r'^name = "([^"]+)"', manifest, re.M).group(1)
    version = re.search(r'^version = "([^"]+)"', manifest, re.M).group(1)
    members[name] = version

lock = root / "Cargo.lock"
text = lock.read_text()
changed = set()

def update(match):
    body = match.group(1)
    name = re.search(r'^name = "([^"]+)"$', body, re.M)
    version = re.search(r'^version = "([^"]+)"$', body, re.M)
    source = re.search(r'^source\s*=', body, re.M)
    if name and version and not source and name.group(1) in members:
        body = re.sub(r'^version = "[^"]+"$', f'version = "{members[name.group(1)]}"', body, count=1, flags=re.M)
        changed.add(name.group(1))
    return "[[package]]\n" + body

text = re.sub(r'^\[\[package\]\]\s*\n(.*?)(?=^\[\[package\]\]\s*$|\Z)', update, text, flags=re.M | re.S)
if changed != set(members):
    raise SystemExit(f"fake Cargo refreshed {sorted(changed)}, expected {sorted(members)}")
lock.write_text(text)
SH
chmod +x "$scratch/bin-success/cargo"
if output="$(PATH="$scratch/bin-success:$PATH" bash "$success/scripts/bump_version.sh" "$target_version" --date 2026-10-22 2>&1)"; then
    grep -Fq "All release versions match $target_version" <<<"$output" || {
        printf 'release-version-bump: successful bump did not verify all sites: %s\n' "$output" >&2
        exit 1
    }
else
    printf 'release-version-bump: staged bump failed unexpectedly: %s\n' "$output" >&2
    exit 1
fi
success_state="$(git -C "$success" status --porcelain)"
if [ -z "$success_state" ]; then
    printf 'release-version-bump: successful bump did not install version files\n' >&2
    exit 1
fi
if output="$(PATH="$scratch/bin-success:$PATH" bash "$success/scripts/bump_version.sh" "$target_version" --date 2026-10-22 2>&1)"; then
    grep -Fq "already at $target_version" <<<"$output" || {
        printf 'release-version-bump: consistent rerun was not recognized: %s\n' "$output" >&2
        exit 1
    }
else
    printf 'release-version-bump: consistent rerun failed: %s\n' "$output" >&2
    exit 1
fi
if [ "$(git -C "$success" status --porcelain)" != "$success_state" ]; then
    printf 'release-version-bump: consistent rerun changed the fixture\n' >&2
    exit 1
fi

partial="$scratch/partial"
make_fixture "$partial"
python3 - "$partial" "$target_version" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
target = sys.argv[2]
config = json.loads((root / "release-versions.json").read_text())
first = (root / config["cargo_manifests"][0]).read_text()
current = re.search(r'^version = "([^"]+)"', first, re.M).group(1)
prefix = re.escape(config["internal_dep_prefix"])

for rel in config["cargo_manifests"]:
    path = root / rel
    text, packages = re.subn(rf'^version = "{re.escape(current)}"', f'version = "{target}"', path.read_text(), count=1, flags=re.M)
    if packages != 1:
        raise SystemExit(f"could not update package version in {rel}")
    text = re.sub(rf'({prefix}[a-z-]+\s*=\s*\{{[^}}\n]*version\s*=\s*)"{re.escape(current)}"',
                  rf'\g<1>"{target}"', text)
    path.write_text(text)

for site in config["json_sites"]:
    path = root / site["file"]
    document = json.loads(path.read_text())
    for keys in site["paths"]:
        node = document
        for key in keys[:-1]:
            node = node[key]
        if node[keys[-1]] != current:
            raise SystemExit(f"unexpected version in {site['file']} at {keys}")
        node[keys[-1]] = target
    path.write_text(json.dumps(document, indent=2) + "\n")
PY

before="$(git -C "$partial" status --porcelain)"
if output="$(PATH="$scratch/bin:$PATH" bash "$partial/scripts/bump_version.sh" "$target_version" --date 2026-10-22 2>&1)"; then
    printf 'release-version-bump: rerun accepted stale generated files\n' >&2
    exit 1
fi
grep -Fq 'Cargo.lock' <<<"$output" || {
    printf 'release-version-bump: stale lockfile was not identified: %s\n' "$output" >&2
    exit 1
}
grep -Fq 'CHANGELOG.md' <<<"$output" || {
    printf 'release-version-bump: stale changelog was not identified: %s\n' "$output" >&2
    exit 1
}
after="$(git -C "$partial" status --porcelain)"
if [ "$after" != "$before" ]; then
    printf 'release-version-bump: failed rerun changed the fixture:\n%s\n' "$after" >&2
    exit 1
fi

printf 'release-version-bump: failures are atomic and stale reruns are refused.\n'
