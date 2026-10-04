#!/usr/bin/env bash
# Guards the hand-maintained release crate lists against Cargo workspace drift.
set -euo pipefail

ROOT="${SYSKNIFE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

ROOT="$ROOT" python3 - <<'PY'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
failures = []

try:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    metadata = json.loads(result.stdout)
except (subprocess.CalledProcessError, json.JSONDecodeError, OSError) as exc:
    print(f"FAIL: cargo metadata could not be read: {exc}")
    sys.exit(1)

packages = metadata.get("packages", [])
publishable_packages = [p for p in packages if p.get("publish") != []]
publishable = {p["name"] for p in publishable_packages}

if not publishable:
    print("FAIL: cargo metadata reported no publishable workspace crates; refusing an empty comparison")
    sys.exit(1)

dependencies = {}
for package in publishable_packages:
    dependencies[package["name"]] = {
        dep["name"]
        for dep in package.get("dependencies", [])
        if dep["name"] in publishable
    }

def read(rel):
    path = root / rel
    try:
        return path.read_text()
    except OSError as exc:
        failures.append(f"{rel}: cannot read file: {exc}")
        return ""

def extract_lists(text, pattern):
    # Every list, not the first one: a second loop that drops a crate must not
    # hide behind an earlier complete one.
    lists = []
    for body in re.findall(pattern, text, re.S):
        crates = re.findall(r"\bsysknife-[a-z0-9-]+\b", body)
        if crates:
            lists.append(crates)
    return lists

FOR_CRATE_LOOP = r"for\s+crate\s+in\s+(.+?);\s*do"
CRATES_ARRAY = r"crates=\(\s*(.*?)\s*\)"

sources = {
    ".github/workflows/release.yml": FOR_CRATE_LOOP,
    "scripts/check_registry_versions.sh": FOR_CRATE_LOOP,
    "scripts/release_rehearsal.sh": CRATES_ARRAY,
}

lists = {}
for rel, pattern in sources.items():
    found = extract_lists(read(rel), pattern)
    if not found:
        failures.append(f"{rel}: no release crate list found")
    for index, crates in enumerate(found, 1):
        label = rel if len(found) == 1 else f"{rel} (list {index} of {len(found)})"
        lists[label] = crates

for rel, crates in lists.items():
    seen = set(crates)

    for crate in sorted(publishable - seen):
        failures.append(f"{rel}: missing publishable crate {crate}")

    for crate in sorted(seen - publishable):
        failures.append(f"{rel}: unexpected release crate {crate}")

    if len(crates) != len(seen):
        duplicates = sorted({crate for crate in crates if crates.count(crate) > 1})
        failures.append(f"{rel}: duplicate release crate(s): {', '.join(duplicates)}")

    positions = {crate: i for i, crate in enumerate(crates)}
    for crate in crates:
        if crate not in publishable:
            continue
        for dependency in sorted(dependencies.get(crate, ())):
            if dependency not in positions:
                continue
            if positions[dependency] > positions[crate]:
                failures.append(
                    f"{rel}: invalid release order: {crate} appears before "
                    f"dependency {dependency}"
                )

if failures:
    for failure in failures:
        print("FAIL:", failure)
    sys.exit(1)

print(
    "ok: release crate lists cover all "
    f"{len(publishable)} publishable workspace crates in dependency order"
)
PY
