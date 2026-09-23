#!/usr/bin/env bash
# npm-audit-off-pr-path.test.sh — npm audit must not gate a pull request, and
# must still run somewhere.
#
# `npm audit` POSTs to registry.npmjs.org. As an enforced step of the required
# `frontend` job it failed every open pull request whenever that endpoint
# returned 503 or timed out, and `gh pr checks` printed the same `frontend fail`
# for an outage as for a real advisory (#367). It now runs against main in
# .github/workflows/npm-audit.yml, and dependency-review covers what a pull
# request introduces.
#
# Two ways back to the old state, both checked:
#
#   * An enforced `npm audit` step reappears in a workflow a pull request can
#     trigger. A step (or its job) with `continue-on-error: true` reports
#     without blocking and is allowed; any other form fails.
#   * The scheduled audit disappears, or quietly stops enforcing. Moving the
#     check off the pull-request path must not become deleting it.
#
# Workflows are parsed as YAML and every step's `run` is read, so a renamed job
# or step cannot hide one. A read that finds no `npm audit` at all fails rather
# than reporting a clean pass over nothing, and the fixtures below prove each
# failure can actually be produced.
#
# Host-side only: needs python3 with PyYAML, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# check_workflows ROOT — exit 0 and print a summary when ROOT's workflows keep
# npm audit off the pull-request path and still run it on a schedule.
check_workflows() {
    local root="$1" manifest status=0
    manifest="$(mktemp)"
    python3 "$repo_root/scripts/github_yaml.py" "$root/.github/workflows" "$root/.github/actions" \
        > "$manifest" || { rm -f "$manifest"; return 1; }
    python3 - "$root" "$manifest" <<'PYTHON' || status=$?
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("npm-audit guard: PyYAML is required; install yamllint with python3 -m pip install yamllint==1.38.0")

root = Path(sys.argv[1])
paths = [Path(p.decode()) for p in Path(sys.argv[2]).read_bytes().split(b"\0") if p]

# Triggers that put a workflow on a pull request's path. `workflow_call` is
# included because a reusable workflow runs under whatever called it.
PR_EVENTS = {"pull_request", "pull_request_target", "merge_group", "workflow_call"}
AUDIT = re.compile(r"\bnpm\s+audit\b")

failures = []
invocations = 0
scheduled_enforced = 0


def triggers(workflow):
    # PyYAML reads a bare `on:` key as the boolean True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, (list, dict)):
        return set(on)
    return set()


def is_true(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


for path in paths:
    name = path.relative_to(root).as_posix()
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as error:
        failures.append(f"{name}: cannot parse: {error}")
        continue

    if path.name in ("action.yml", "action.yaml"):
        # A composite action runs under any workflow that uses it, so its
        # trigger cannot be read from here. Refuse rather than guess.
        for step in (doc.get("runs") or {}).get("steps") or []:
            if isinstance(step, dict) and AUDIT.search(str(step.get("run", ""))):
                invocations += 1
                failures.append(f"{name}: runs npm audit inside a composite action; keep it in npm-audit.yml")
        continue

    events = triggers(doc)
    on_pr = bool(events & PR_EVENTS)
    for job_id, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps") or [], 1):
            if not isinstance(step, dict) or not AUDIT.search(str(step.get("run", ""))):
                continue
            invocations += 1
            label = f"{name} job '{job_id}' step {index} ('{step.get('name', 'unnamed')}')"
            enforced = not (is_true(step.get("continue-on-error")) or is_true(job.get("continue-on-error")))
            if on_pr and enforced:
                failures.append(
                    f"{label} enforces npm audit on the pull-request path; a registry outage fails every PR (#367)"
                )
            if "schedule" in events and not on_pr and enforced:
                if "--audit-level=high" in str(step["run"]):
                    scheduled_enforced += 1
                else:
                    failures.append(f"{label} runs the scheduled npm audit without --audit-level=high")

if invocations == 0:
    failures.append("no npm audit found in any workflow; the read is broken or the audit was deleted")
elif scheduled_enforced == 0:
    failures.append("no scheduled, pull-request-free workflow enforces npm audit --audit-level=high; "
                    "moving it off the PR path must not delete it")

for failure in failures:
    print(f"FAIL  {failure}", file=sys.stderr)
if failures:
    sys.exit(1)
print(f"npm audit guard passed: {invocations} invocation(s) across {len(paths)} file(s), "
      f"{scheduled_enforced} enforced on a schedule, none enforced on the pull-request path.")
PYTHON
    rm -f "$manifest"
    return "$status"
}

# ---------------------------------------------------------------------------
# The repository as it stands.
# ---------------------------------------------------------------------------
check_workflows "$repo_root"

# ---------------------------------------------------------------------------
# Fixtures: each must go red, with the expected diagnostic.
# ---------------------------------------------------------------------------
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

reset_fixture() {
    rm -rf "$fixture/.github"
    mkdir -p "$fixture/.github"
    cp -R "$repo_root/.github/workflows" "$fixture/.github/workflows"
    if [ -d "$repo_root/.github/actions" ]; then
        cp -R "$repo_root/.github/actions" "$fixture/.github/actions"
    fi
}

expect_failure() {
    local case_name="$1" expected="$2" output
    if output="$(check_workflows "$fixture" 2>&1)"; then
        printf 'npm-audit guard test: %s unexpectedly passed\n' "$case_name" >&2
        exit 1
    fi
    if ! grep -Fq -- "$expected" <<<"$output"; then
        printf 'npm-audit guard test: %s failed without "%s":\n%s\n' "$case_name" "$expected" "$output" >&2
        exit 1
    fi
}

# Put the pre-#367 step back into `frontend`, under the same checkout step
# every job starts with, so the fixture tracks ci.yml rather than a copy of it.
add_frontend_step() {
    python3 - "$fixture/.github/workflows/ci.yml" "$1" <<'PYTHON'
import sys
from pathlib import Path

path, step = Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8")
head, sep, tail = text.partition("\n  frontend:\n")
assert sep, "ci.yml has no frontend job"
anchor = "      - name: Set up Node\n"
assert anchor in tail, "frontend job has no Set up Node step"
path.write_text(head + sep + tail.replace(anchor, step + "\n" + anchor, 1), encoding="utf-8")
PYTHON
}

reset_fixture
add_frontend_step '      - name: Audit production dependencies
        run: npm audit --omit=dev --audit-level=high
'
expect_failure "enforced audit in ci.yml frontend" \
    "ci.yml job 'frontend' step 2 ('Audit production dependencies') enforces npm audit on the pull-request path"

# Renaming the step and splitting the command across a block scalar must not hide it.
reset_fixture
add_frontend_step '      - name: Dependencies
        run: |
          echo checking
          npm   audit --omit=dev
'
expect_failure "renamed multi-line audit" "ci.yml job 'frontend' step 2 ('Dependencies') enforces npm audit"

# Reporting without blocking is the other shape #367 allows.
reset_fixture
add_frontend_step '      - name: Audit production dependencies
        continue-on-error: true
        run: npm audit --omit=dev --audit-level=high
'
check_workflows "$fixture" >/dev/null

reset_fixture
rm "$fixture/.github/workflows/npm-audit.yml"
expect_failure "scheduled audit deleted" "no npm audit found in any workflow"

reset_fixture
sed -i 's/^  workflow_dispatch:$/  workflow_dispatch:\n  pull_request:/' "$fixture/.github/workflows/npm-audit.yml"
expect_failure "scheduled workflow also on pull_request" \
    "npm-audit.yml job 'npm-audit' step 3 ('Audit production dependencies') enforces npm audit on the pull-request path"

reset_fixture
sed -i 's/ --audit-level=high$//' "$fixture/.github/workflows/npm-audit.yml"
expect_failure "scheduled audit without a level" "runs the scheduled npm audit without --audit-level=high"

reset_fixture
sed -i 's/^    runs-on: ubuntu-latest$/    runs-on: ubuntu-latest\n    continue-on-error: true/' \
    "$fixture/.github/workflows/npm-audit.yml"
expect_failure "scheduled audit made non-blocking" "no scheduled, pull-request-free workflow enforces npm audit"

reset_fixture
mkdir -p "$fixture/.github/actions/audit"
cat > "$fixture/.github/actions/audit/action.yml" <<'EOF'
name: audit
runs:
  using: composite
  steps:
    - run: npm audit
      shell: bash
EOF
expect_failure "audit hidden in a composite action" "runs npm audit inside a composite action"

printf 'npm-audit guard test: 7 fixtures went red or green as expected.\n'
