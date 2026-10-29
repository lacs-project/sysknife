#!/usr/bin/env bash
#
# package-license.test.sh — every package we publish must carry the licence
# text, not only a `license = "MIT"` field.
#
# crates.io and npm build each tarball from the package's own directory. The
# LICENSE file sits at the repository root, outside all of them, so
# sysknife-cli-0.28.0.crate and sysknife-setup@0.28.0 shipped without a
# licence file. MIT asks for the notice in every copy, and OpenSSF Baseline
# OSPS-LE-03.02 asks for it alongside the released assets.
#
# Reads `cargo metadata` for the publishable crates and packages/setup for npm;
# each must hold a LICENSE identical to the root one, and no include/exclude
# rule may drop it. No network.
set -euo pipefail

ROOT="${SYSKNIFE_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

ROOT="$ROOT" python3 - <<'PY'
import json
import os
import subprocess
import sys
import tomllib
from fnmatch import fnmatch
from pathlib import Path

root = Path(os.environ["ROOT"])
failures = []

license_text = (root / "LICENSE").read_bytes() if (root / "LICENSE").is_file() else b""
if not license_text.strip():
    print("FAIL: the root LICENSE is missing or empty; nothing to compare against")
    sys.exit(1)

try:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root, capture_output=True, text=True, check=True,
    )
    packages = json.loads(result.stdout)["packages"]
except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError, OSError) as exc:
    print(f"FAIL: cargo metadata could not be read: {exc}")
    sys.exit(1)

crates = [p for p in packages if p.get("publish") != []]
if not crates:
    print("FAIL: cargo metadata reported no publishable crates; refusing an empty check")
    sys.exit(1)

def check_copy(label, directory):
    copy = directory / "LICENSE"
    if not copy.is_file():
        failures.append(f"{label}: no LICENSE in {directory.relative_to(root)}/, so the published package carries none")
    elif copy.read_bytes() != license_text:
        failures.append(f"{label}: {copy.relative_to(root)} differs from the root LICENSE")

for crate in crates:
    manifest = Path(crate["manifest_path"])
    check_copy(crate["name"], manifest.parent)
    package = tomllib.loads(manifest.read_text()).get("package", {})
    include = package.get("include")
    if include is not None and not any(fnmatch("LICENSE", pattern) for pattern in include):
        failures.append(f"{crate['name']}: package.include does not list LICENSE")
    if any(fnmatch("LICENSE", pattern) for pattern in package.get("exclude", [])):
        failures.append(f"{crate['name']}: package.exclude drops LICENSE")

# npm always packs a top-level LICENSE, whatever `files` says.
npm_dir = root / "packages" / "setup"
manifest = json.loads((npm_dir / "package.json").read_text())
if manifest.get("private"):
    failures.append("packages/setup is marked private; this check expected the published npm package")
check_copy(manifest.get("name", "packages/setup"), npm_dir)

if failures:
    for failure in failures:
        print(f"FAIL: {failure}")
    sys.exit(1)

print(f"package-license: {len(crates)} crates and the npm package each ship the root LICENSE")
PY
