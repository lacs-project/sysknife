#!/usr/bin/env bash
#
# dependabot-coverage.test.sh — every lockfile, pinned requirements file and
# container file in the repository must have a Dependabot version-update entry.
#
# Dependabot security alerts reach any manifest GitHub's dependency graph
# understands, but version updates reach only the directories that
# .github/dependabot.yml names. tools/ci-node, tools/ci-python, fuzz/ and
# .clusterfuzzlite/ were each added without an entry, so their pins aged
# silently until an advisory arrived. docs/dependencies.md says every pinned
# dependency is watched; this keeps that sentence true.
#
# Reads `git ls-files` and the Dependabot config. No network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail_count=0
note() { printf 'dependabot-coverage: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

# check CONFIG PATHS: PATHS is a file of tracked paths, one per line. The
# heredoc below is Python's stdin, so the paths cannot come that way.
check() {
    python3 - "$1" "$2" <<'PY'
import re
import sys
from pathlib import PurePosixPath

import yaml

config = yaml.safe_load(open(sys.argv[1])) or {}
covered = {(u.get("package-ecosystem"), "/" + str(u.get("directory", "")).strip("/"))
           for u in config.get("updates") or []}
covered = {(eco, "/" if d == "/" else d) for eco, d in covered}

RULES = [
    (re.compile(r"(^|/)Cargo\.lock$"), "cargo"),
    (re.compile(r"(^|/)package-lock\.json$"), "npm"),
    (re.compile(r"(^|/)requirements[^/]*\.txt$"), "pip"),
    (re.compile(r"(^|/)(Docker|Container)file[^/]*$"), "docker"),
    (re.compile(r"^\.github/workflows/[^/]+\.ya?ml$"), "github-actions"),
]

needed = set()
for path in open(sys.argv[2]).read().splitlines():
    for pattern, ecosystem in RULES:
        if pattern.search(path):
            parent = str(PurePosixPath(path).parent)
            directory = "/" if ecosystem == "github-actions" or parent == "." else "/" + parent
            needed.add((ecosystem, directory))

if not needed:
    print("found no lockfiles; nothing was checked")
    sys.exit(2)
missing = sorted(needed - covered)
for ecosystem, directory in missing:
    print(f"FAIL: no {ecosystem} entry for {directory}")
if missing:
    sys.exit(1)
print(f"{len(needed)} ecosystem directories, each with a Dependabot entry")
PY
}

# ── 1. The repository ────────────────────────────────────────────────────────

if ! tracked="$(git -C "$repo_root" ls-files)"; then
    printf 'dependabot-coverage: git ls-files failed; nothing was checked\n' >&2
    exit 1
fi
printf '%s\n' "$tracked" >"$work/tracked"
if out="$(check "$repo_root/.github/dependabot.yml" "$work/tracked" 2>&1)"; then
    summary="$out"
else
    note "$out"
fi

# ── 2. The checker must notice a missing entry and an empty tree ────────────

cat >"$work/config.yml" <<'YAML'
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
YAML
printf 'Cargo.lock\nfuzz/Cargo.lock\n' >"$work/two-locks"
out="$(check "$work/config.yml" "$work/two-locks" 2>&1)" \
    && note "a second Cargo.lock with no entry passed: $out"
grep -q 'no cargo entry for /fuzz' <<<"$out" || note "missing fuzz/ entry not named: $out"

printf '.github/workflows/ci.yml\n' >"$work/workflow"
out="$(check "$work/config.yml" "$work/workflow" 2>&1)" \
    && note "workflows with no github-actions entry passed: $out"
grep -q 'no github-actions entry for /$' <<<"$out" || note "missing github-actions entry not named: $out"

printf 'Cargo.lock\n' >"$work/one-lock"
out="$(check "$work/config.yml" "$work/one-lock" 2>&1)" || note "a covered Cargo.lock failed: $out"

# One file per rule, against a config that covers nothing else: each of the
# five ecosystems must be named, so dropping a rule fails here.
printf '%s\n' Cargo.lock web/package-lock.json py/requirements.txt img/Containerfile \
    .github/workflows/x.yml >"$work/each-rule"
printf 'version: 2\nupdates: []\n' >"$work/empty.yml"
out="$(check "$work/empty.yml" "$work/each-rule" 2>&1)" && note "an empty config passed: $out"
for want in 'cargo entry for /$' 'npm entry for /web' 'pip entry for /py' 'docker entry for /img' \
    'github-actions entry for /$'; do
    grep -q "no $want" <<<"$out" || note "the rule behind 'no $want' did not fire: $out"
done

rc=0
printf 'README.md\n' >"$work/no-locks"
out="$(check "$work/config.yml" "$work/no-locks" 2>&1)" || rc=$?
[ "$rc" -eq 2 ] || note "a tree with no lockfiles exited $rc, want 2: $out"

if [ "$fail_count" -ne 0 ]; then
    printf '\ndependabot-coverage: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'dependabot-coverage: %s\n' "$summary"
