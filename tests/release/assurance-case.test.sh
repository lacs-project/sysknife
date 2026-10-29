#!/usr/bin/env bash
#
# assurance-case.test.sh — every file and symbol docs/assurance-case.md cites
# must exist.
#
# The assurance case argues that SysKnife meets its security requirements by
# pointing at the code and the test behind each claim. A pointer to a function
# that was renamed, or a test that was deleted, leaves the claim standing with
# nothing under it. The document cites `path::symbol` rather than line numbers
# so ordinary edits do not trip this; a rename or a removal does.
#
# Host-side only: reads the document and the files it names. No build.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail_count=0
note() { printf 'assurance-case: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

# check ROOT DOC
check() {
    python3 - "$1" "$2" <<'PY'
import re
import sys
from pathlib import Path

root, doc = Path(sys.argv[1]), Path(sys.argv[2])
PREFIXES = ("crates/", "apps/", "packaging/", "tests/", "scripts/", "fuzz/", ".github/", "docs/", "tools/")
DEFINITION = r"\b(?:fn|const|static|struct|enum|type|mod)\s+{}\b"

failures, paths, symbols = [], 0, 0
for token in sorted(set(re.findall(r"`([^`\s]+)`", doc.read_text()))):
    if not token.startswith(PREFIXES) or "*" in token:
        continue
    path, _, symbol = token.partition("::")
    target = root / path
    if not target.exists():
        failures.append(f"cites {path}, which does not exist")
        continue
    paths += 1
    if not symbol:
        continue
    if not target.is_file() or not re.search(DEFINITION.format(re.escape(symbol)), target.read_text()):
        failures.append(f"cites {path}::{symbol}, and {path} defines no {symbol}")
        continue
    symbols += 1

for failure in failures:
    print(f"FAIL: {failure}")
if failures:
    sys.exit(1)
if symbols == 0:
    print("found no path::symbol citation; nothing was checked")
    sys.exit(2)
print(f"{paths} cited paths exist, {symbols} of them with a symbol each defines")
PY
}

# ── 1. The document itself ───────────────────────────────────────────────────

if out="$(check "$repo_root" "$repo_root/docs/assurance-case.md" 2>&1)"; then
    summary="$out"
else
    note "docs/assurance-case.md cites what is not there:"$'\n'"$out"
fi

# ── 2. The checker must catch a missing file, a missing symbol, and nothing ──

mkdir -p "$work/crates/x/src"
printf 'pub fn present() {}\n// mentions gone() in a comment only\n' >"$work/crates/x/src/lib.rs"

expect() {
    local rc=0 out
    printf '%s\n' "$1" >"$work/doc.md"
    out="$(check "$work" "$work/doc.md" 2>&1)" || rc=$?
    if [ "$rc" -ne "$2" ]; then
        note "$4: checker exited $rc, want $2: $out"
    elif ! grep -qE -- "$3" <<<"$out"; then
        note "$4: checker output lacks /$3/: $out"
    fi
}

expect 'See `crates/x/src/lib.rs::present`.' 0 '1 of them' 'a symbol the file defines'
expect 'See `crates/x/src/missing.rs::present`.' 1 'does not exist' 'a file that is gone'
expect 'See `crates/x/src/lib.rs::gone`.' 1 'defines no gone' 'a symbol named only in a comment'
expect 'Nothing cited here.' 2 'nothing was checked' 'a document with no citations'

if [ "$fail_count" -ne 0 ]; then
    printf '\nassurance-case: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'assurance-case: %s\n' "$summary"
