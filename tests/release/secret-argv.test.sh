#!/usr/bin/env bash
#
# secret-argv.test.sh — no workflow may put a secret on a command line.
#
# Every process on a runner can read every other process's argv through /proc,
# and a command line also lands in `ps`, in crash reports and in `set -x`
# traces. release.yml passed CARGO_REGISTRY_TOKEN to `cargo publish --token`,
# although cargo reads that variable from the environment by itself.
#
# For each workflow, collects the env variables whose value names `secrets.`
# (workflow, job and step level) and fails when a `run:` script expands one
# anywhere other than a presence check, `test -n "${NAME:-}"` or
# `[ -n "${NAME:-}" ]`. A `${{ secrets.* }}` written straight into a `run:`
# script fails too, because it pastes the value into the script file.
#
# Host-side only: reads .github/workflows. No network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail_count=0
note() { printf 'secret-argv: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

scan() {
    python3 - "$1" <<'PY'
import re
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
files = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))

def secret_vars(env):
    if not isinstance(env, dict):
        return set()
    return {name for name, value in env.items() if "secrets." in str(value)}

def presence_check(name):
    braced = r'"\$\{' + name + r':-\}"'
    return re.compile(r'(?:\btest\s+-n\s+' + braced + r'|\[\s+-n\s+' + braced + r'\s+\])')

findings = []
secret_names = 0
for path in files:
    workflow = yaml.safe_load(path.read_text()) or {}
    top = secret_vars(workflow.get("env"))
    for job_id, job in (workflow.get("jobs") or {}).items():
        job_vars = top | secret_vars(job.get("env"))
        for index, step in enumerate(job.get("steps") or []):
            names = job_vars | secret_vars(step.get("env"))
            secret_names += len(names)
            script = step.get("run")
            if not isinstance(script, str):
                continue
            label = f"{path.name} job {job_id} step {step.get('name', index + 1)}"
            if re.search(r"\$\{\{\s*secrets\.", script):
                findings.append(f"{label}: writes ${{{{ secrets.* }}}} into the script itself")
            for name in sorted(names):
                stripped = presence_check(name).sub("", script)
                if re.search(r"\$(?:\{" + name + r"\b|" + name + r"\b)", stripped):
                    findings.append(f"{label}: expands ${name} outside a presence check")

for finding in findings:
    print(f"FAIL: {finding}")
if findings:
    sys.exit(1)
if secret_names == 0:
    print("found no secret-bearing env variables; nothing was checked")
    sys.exit(2)
PY
}

# ── 1. The repository's own workflows ────────────────────────────────────────

if ! out="$(scan "$repo_root/.github/workflows" 2>&1)"; then
    note "the workflows put a secret on a command line:"$'\n'"$out"
fi

# ── 2. The scanner itself: it must catch each shape and spare the check ─────

fixture() {
    local dir="$work/$1"
    mkdir -p "$dir"
    cat >"$dir/w.yml"
    printf '%s\n' "$dir"
}

# expect_scan DIR WANT_RC PATTERN LABEL
expect_scan() {
    local out rc=0
    out="$(scan "$1" 2>&1)" || rc=$?
    if [ "$rc" -ne "$2" ]; then
        note "$4: scanner exited $rc, want $2: $out"
    elif ! grep -qE -- "$3" <<<"$out"; then
        note "$4: scanner output lacks /$3/: $out"
    fi
}

dir="$(fixture argv <<'YAML'
jobs:
  publish:
    steps:
      - name: Publish
        env:
          TOKEN: ${{ secrets.TOKEN }}
        run: |
          test -n "${TOKEN:-}" || exit 1
          cargo publish --token "$TOKEN"
YAML
)"
expect_scan "$dir" 1 'expands \$TOKEN' 'a token passed as an argument'

dir="$(fixture braced <<'YAML'
env:
  TOKEN: ${{ secrets.TOKEN }}
jobs:
  publish:
    steps:
      - run: |
          curl -H "Authorization: Bearer ${TOKEN}" https://example.org
YAML
)"
expect_scan "$dir" 1 'expands \$TOKEN' 'a workflow-level token in a braced expansion'

dir="$(fixture inline <<'YAML'
jobs:
  publish:
    steps:
      - run: echo "${{ secrets.TOKEN }}" | tool login
YAML
)"
expect_scan "$dir" 1 'into the script itself' 'a secret written into the script'

dir="$(fixture presence <<'YAML'
jobs:
  publish:
    env:
      TOKEN: ${{ secrets.TOKEN }}
    steps:
      - run: |
          test -n "${TOKEN:-}" || exit 1
          [ -n "${TOKEN:-}" ] || exit 1
          cargo publish
YAML
)"
expect_scan "$dir" 0 '^$' 'presence checks and an environment-only consumer'

dir="$(fixture none <<'YAML'
jobs:
  build:
    steps:
      - run: make
YAML
)"
expect_scan "$dir" 2 'nothing was checked' 'workflows holding no secret at all'

mkdir -p "$work/empty"
expect_scan "$work/empty" 2 'nothing was checked' 'a directory with no workflows'

if [ "$fail_count" -ne 0 ]; then
    printf '\nsecret-argv: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'secret-argv: no workflow expands a secret outside a presence check\n'
