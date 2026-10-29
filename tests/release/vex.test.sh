#!/usr/bin/env bash
#
# vex.test.sh — every OpenVEX statement under vex/ must be well formed, and a
# `component_not_present` claim must stay true.
#
# vex/ publishes, in OpenVEX v0.2.0, the vulnerabilities that do not affect
# what SysKnife releases (OSPS Baseline VM-04.02). A statement that a crate is
# absent from sysknife-cli is a claim about the dependency graph, and the graph
# moves with every Cargo.lock change. This test recomputes it.
#
# The closure comes from Cargo.lock: every package a product can reach through
# the lock's dependency lists, across all targets and dev-dependencies. That
# over-approximates what the binary links, which is the safe direction: a crate
# missing from the over-approximation is missing from the binary. No network,
# no cargo.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail_count=0
note() { printf 'vex: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

# check VEX_DIR LOCKFILE
check() {
    python3 - "$1" "$2" <<'PY'
import json
import re
import sys
import tomllib
from datetime import datetime
from pathlib import Path

vex_dir, lock_path = Path(sys.argv[1]), Path(sys.argv[2])
CONTEXT = "https://openvex.dev/ns/v0.2.0"
STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
CARGO_PURL = re.compile(r"^pkg:cargo/([A-Za-z0-9_-]+)(?:@[^?#]+)?$")

packages = {}
for package in tomllib.loads(lock_path.read_text())["package"]:
    packages.setdefault(package["name"], []).append(package)
workspace = {name for name, entries in packages.items() if any("source" not in e for e in entries)}

def closure(root):
    seen, stack = set(), [e for e in packages[root] if "source" not in e]
    while stack:
        package = stack.pop()
        key = (package["name"], package["version"])
        if key in seen:
            continue
        seen.add(key)
        for dep in package.get("dependencies", []):
            name, _, version = dep.partition(" ")
            version = version.split(" ")[0]
            stack.extend(c for c in packages[name] if not version or c["version"] == version)
    return {name for name, _ in seen}

failures, checked = [], 0
files = sorted(vex_dir.glob("*.openvex.json"))
for path in files:
    label = path.name
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        failures.append(f"{label}: not JSON ({exc})")
        continue
    if doc.get("@context") != CONTEXT:
        failures.append(f"{label}: @context must be {CONTEXT}")
    for field in ("@id", "author"):
        if not isinstance(doc.get(field), str) or not doc[field].strip():
            failures.append(f"{label}: missing {field}")
    try:
        datetime.fromisoformat(str(doc.get("timestamp")).replace("Z", "+00:00"))
    except ValueError:
        failures.append(f"{label}: timestamp is not ISO 8601")
    if not isinstance(doc.get("version"), int) or doc["version"] < 1:
        failures.append(f"{label}: version must be an integer from 1")
    statements = doc.get("statements") or []
    if not statements:
        failures.append(f"{label}: no statements")
    for index, st in enumerate(statements, 1):
        where = f"{label} statement {index}"
        vuln = (st.get("vulnerability") or {}).get("name")
        if not vuln:
            failures.append(f"{where}: no vulnerability.name")
        where = f"{label} {vuln or f'statement {index}'}"
        status = st.get("status")
        if status not in STATUSES:
            failures.append(f"{where}: status {status!r} is not an OpenVEX status")
        products = st.get("products") or []
        if not products:
            failures.append(f"{where}: no products")
        if status == "not_affected":
            justification = st.get("justification")
            if justification is not None and justification not in JUSTIFICATIONS:
                failures.append(f"{where}: unknown justification {justification!r}")
            if justification is None and not st.get("impact_statement"):
                failures.append(f"{where}: not_affected needs a justification or an impact_statement")
        if status == "affected" and not st.get("action_statement"):
            failures.append(f"{where}: affected needs an action_statement")
        if not (status == "not_affected" and st.get("justification") == "component_not_present"):
            continue
        for product in products:
            match = CARGO_PURL.match(product.get("@id", ""))
            if not match or match.group(1) not in workspace:
                failures.append(f"{where}: product {product.get('@id')!r} is not a pkg:cargo purl for a workspace crate")
                continue
            reach = closure(match.group(1))
            subcomponents = product.get("subcomponents") or []
            if not subcomponents:
                failures.append(f"{where}: component_not_present names no subcomponent for {match.group(1)}")
            for sub in subcomponents:
                sub_match = CARGO_PURL.match(sub.get("@id", ""))
                if not sub_match:
                    failures.append(f"{where}: subcomponent {sub.get('@id')!r} is not a pkg:cargo purl")
                elif sub_match.group(1) in reach:
                    failures.append(f"{where}: claims {sub_match.group(1)} is not present in {match.group(1)}, but Cargo.lock reaches it")
                else:
                    checked += 1

for failure in failures:
    print(f"FAIL: {failure}")
if failures:
    sys.exit(1)
if not files or checked == 0:
    print(f"no component_not_present claim under {vex_dir} was checked")
    sys.exit(2)
print(f"{len(files)} VEX file(s); {checked} component_not_present claim(s) hold against Cargo.lock")
PY
}

# ── 1. The repository's own statements ───────────────────────────────────────

if out="$(check "$repo_root/vex" "$repo_root/Cargo.lock" 2>&1)"; then
    summary="$out"
else
    note "vex/ does not hold:"$'\n'"$out"
fi

# ── 2. The checker must refuse what it should ────────────────────────────────

# fixture NAME: a VEX directory holding stdin as one document.
fixture() {
    mkdir -p "$work/$1"
    cat >"$work/$1/f.openvex.json"
    printf '%s\n' "$work/$1"
}

# expect_check DIR WANT_RC PATTERN LABEL
expect_check() {
    local out rc=0
    out="$(check "$1" "$repo_root/Cargo.lock" 2>&1)" || rc=$?
    if [ "$rc" -ne "$2" ]; then
        note "$4: checker exited $rc, want $2: $out"
    elif ! grep -qE -- "$3" <<<"$out"; then
        note "$4: checker output lacks /$3/: $out"
    fi
}

statement() {
    printf '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.org/v","author":"a","timestamp":"2026-10-29T00:00:00Z","version":1,"statements":[%s]}\n' "$1"
}

# serde is in sysknife-cli's graph, so claiming it absent must fail.
dir="$(statement '{"vulnerability":{"name":"GHSA-test"},"products":[{"@id":"pkg:cargo/sysknife-cli","subcomponents":[{"@id":"pkg:cargo/serde"}]}],"status":"not_affected","justification":"component_not_present"}' | fixture present)"
expect_check "$dir" 1 'claims serde is not present in sysknife-cli' 'a crate the product reaches'

dir="$(statement '{"vulnerability":{"name":"GHSA-test"},"products":[{"@id":"pkg:cargo/not-a-member","subcomponents":[{"@id":"pkg:cargo/glib"}]}],"status":"not_affected","justification":"component_not_present"}' | fixture foreign)"
expect_check "$dir" 1 'not a pkg:cargo purl for a workspace crate' 'a product outside the workspace'

dir="$(statement '{"vulnerability":{"name":"GHSA-test"},"products":[{"@id":"pkg:cargo/sysknife-cli"}],"status":"not_affected","justification":"component_not_present"}' | fixture nosub)"
expect_check "$dir" 1 'names no subcomponent' 'component_not_present without a subcomponent'

dir="$(statement '{"vulnerability":{"name":"GHSA-test"},"products":[{"@id":"pkg:cargo/sysknife-cli"}],"status":"not_affected"}' | fixture nojust)"
expect_check "$dir" 1 'needs a justification' 'not_affected with no reason'

dir="$(statement '{"vulnerability":{"name":"GHSA-test"},"products":[],"status":"maybe"}' | fixture status)"
expect_check "$dir" 1 'not an OpenVEX status' 'an invented status'

dir="$(statement '' | fixture empty)"
expect_check "$dir" 1 'no statements' 'a document with no statements'

mkdir -p "$work/none"
expect_check "$work/none" 2 'was checked' 'a directory with no VEX files'

dir="$(statement '{"vulnerability":{"name":"GHSA-test"},"products":[{"@id":"pkg:cargo/sysknife-cli","subcomponents":[{"@id":"pkg:cargo/glib"}]}],"status":"not_affected","justification":"component_not_present"}' | fixture holds)"
expect_check "$dir" 0 '1 component_not_present claim' 'a true claim'

if [ "$fail_count" -ne 0 ]; then
    printf '\nvex: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'vex: %s\n' "$summary"
