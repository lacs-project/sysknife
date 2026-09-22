#!/usr/bin/env bash
# Guards release-versions.json against being incomplete or stale.
#
# The registry is only worth having if it is exhaustive. A manifest added
# without registering it here is invisible to scripts/bump_version.sh, and the
# release then publishes one crate at the new version depending on another at
# the old one, which is invisible until somebody builds against the published
# crate. So this derives the expected set from the tree rather than trusting
# the list, and fails on anything the registry does not account for.
#
# Pure-function test: no network, no cargo, no writes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CONFIG="$ROOT/release-versions.json"

[ -f "$CONFIG" ] || { echo "FAIL: $CONFIG not found"; exit 1; }

ROOT="$ROOT" CONFIG="$CONFIG" python3 - <<'PY'
import json, os, re, subprocess, sys
from pathlib import Path

root = Path(os.environ["ROOT"])
cfg = json.loads(Path(os.environ["CONFIG"]).read_text())
failures = []

# The version every site must currently agree on, read from the first manifest.
first = root / cfg["cargo_manifests"][0]
m = re.search(r'^version = "([^"]+)"', first.read_text(), re.M)
if not m:
    print(f"FAIL: no [package] version in {cfg['cargo_manifests'][0]}")
    sys.exit(1)
release = m.group(1)

registered = set(cfg["cargo_manifests"]) | {s["file"] for s in cfg["json_sites"]}
registered |= set(cfg["generated_lockfiles"])

# 1. Every registered file exists and holds the release version. A stale entry
#    is as bad as a missing one: it makes the count look right.
for rel in sorted(registered):
    p = root / rel
    if not p.exists():
        failures.append(f"{rel} is registered and does not exist")
    elif release not in p.read_text():
        failures.append(f"{rel} is registered and does not contain {release}")

# 2. Every declared JSON PATH resolves and holds the release version. Paths,
#    not a count of "version" matches: package-lock.json has 178 version
#    fields and two of them are ours, so counting matches would compare the
#    release against every npm dependency.
def resolve(doc, path):
    cur = doc
    for step in path:
        cur = cur[step]
    return cur

for site in cfg["json_sites"]:
    doc = json.loads((root / site["file"]).read_text())
    if not site["paths"]:
        failures.append(f'{site["file"]}: registered with no paths, so it is never checked')
    for path in site["paths"]:
        try:
            got = resolve(doc, path)
        except (KeyError, IndexError, TypeError):
            failures.append(f'{site["file"]}: declared path {path} does not resolve')
            continue
        if got != release:
            failures.append(f'{site["file"]}: path {path} holds {got!r}, not {release!r}')

# 3. COMPLETENESS. Any tracked manifest carrying the release version in a
#    version field must be registered. This is the assertion that catches a
#    new crate, and the one the other two cannot make.
tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                         capture_output=True, check=True).stdout.decode().split("\0")
tracked = [t for t in tracked if t]
if not tracked:
    failures.append("git ls-files returned nothing; this check inspected no files")

ignore = set(cfg.get("not_a_version_site", []))
found = []
for rel in tracked:
    if not rel.endswith((".toml", ".json")):
        continue
    try:
        text = (root / rel).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        continue
    hit = (re.search(rf'^version\s*=\s*"{re.escape(release)}"', text, re.M)
           or re.search(rf'"version"\s*:\s*"{re.escape(release)}"', text))
    if hit:
        found.append(rel)

if not found:
    failures.append(
        f"no file in the tree carries version {release}; this check would pass "
        "over an empty set, so it fails instead")

for rel in sorted(set(found) - registered - ignore):
    failures.append(
        f"{rel} carries version {release} and is not in release-versions.json. "
        "Register it, or add it to not_a_version_site with a reason.")

# 4. The writer and the checker must read the SAME registry, or the whole
#    point of having one is lost.
for script in ("scripts/bump_version.sh", "scripts/check_release_versions.sh"):
    body = (root / script).read_text()
    if "release-versions.json" not in body:
        failures.append(f"{script} does not read release-versions.json")

if failures:
    for f in failures:
        print("FAIL:", f)
    sys.exit(1)
print(f"ok: release-versions.json accounts for every version site at {release} "
      f"({len(registered)} file(s), {sum(len(s['paths']) for s in cfg['json_sites'])} JSON path(s))")
print("ok: bump_version.sh and check_release_versions.sh read the same registry")
PY
