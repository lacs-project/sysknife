#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
import re
import sys
from pathlib import Path

import yaml

workflow_path = Path(".github/workflows/cargo-audit.yml")
ci_path = Path(".github/workflows/ci.yml")

if not workflow_path.is_file():
    sys.exit("FAIL: scheduled cargo audit workflow is missing")

if not ci_path.is_file():
    sys.exit("FAIL: existing CI workflow is missing")

workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
ci_workflow = yaml.safe_load(ci_path.read_text(encoding="utf-8"))

if not isinstance(workflow, dict) or not isinstance(ci_workflow, dict):
    sys.exit("FAIL: invalid workflow configuration")

# PyYAML may interpret the YAML key "on" as Boolean True.
triggers = workflow.get("on", workflow.get(True, {}))

if not isinstance(triggers, dict):
    sys.exit("FAIL: invalid cargo audit triggers")

if "workflow_dispatch" not in triggers:
    sys.exit("FAIL: cargo audit cannot be triggered manually")

if not triggers.get("schedule"):
    sys.exit("FAIL: scheduled cargo audit has no schedule trigger")

if triggers["schedule"] != [{"cron": "17 6 * * *"}]:
    sys.exit("FAIL: cargo audit must run daily at 06:17 UTC")

permissions = workflow.get("permissions", {})

jobs = workflow.get("jobs", {})
ci_jobs = ci_workflow.get("jobs", {})

if not isinstance(jobs, dict) or not isinstance(ci_jobs, dict):
    sys.exit("FAIL: invalid workflow jobs")

cargo_job = jobs.get("cargo-audit", {})
security_job = ci_jobs.get("security-audit", {})

if not isinstance(cargo_job, dict) or not isinstance(security_job, dict):
    sys.exit("FAIL: cargo audit or security-audit job is missing")

steps = cargo_job.get("steps", [])
security_steps = security_job.get("steps", [])

if not isinstance(steps, list) or not isinstance(security_steps, list):
    sys.exit("FAIL: invalid workflow steps")

if not all(isinstance(step, dict) for step in steps + security_steps):
    sys.exit("FAIL: workflow steps must be mappings")

actions = [step["uses"] for step in steps if "uses" in step]

expected_actions = [
    step["uses"] for step in security_steps if "uses" in step
]

if len(expected_actions) != 2:
    sys.exit("FAIL: security-audit must contain exactly two actions")

if len(actions) != 2:
    sys.exit("FAIL: scheduled cargo audit must contain exactly two actions")

# Both jobs must use full, immutable 40-character SHA pins.
for action in actions + expected_actions:
    if not isinstance(action, str) or not re.fullmatch(
        r"[^@\s]+@[0-9a-fA-F]{40}", action
    ):
        sys.exit(f"FAIL: action is not pinned to a full SHA: {action}")

# Verify the expected actions, not just their SHA format.
expected_names = [
    "actions/checkout",
    "taiki-e/install-action",
]

actual_names = [action.split("@", 1)[0] for action in expected_actions]

if actual_names != expected_names:
    sys.exit("FAIL: security-audit contains unexpected actions")

if actions != expected_actions:
    sys.exit("FAIL: cargo audit actions must match the approved CI pins")

# Ensure the installation step installs cargo-audit.
install_steps = [
    step for step in steps
    if step.get("uses", "").startswith("taiki-e/install-action@")
]

if len(install_steps) != 1:
    sys.exit("FAIL: expected exactly one cargo-audit installation action")

if install_steps[0].get("with", {}).get("tool") != "cargo-audit":
    sys.exit("FAIL: install action must install cargo-audit")

# The scheduled audit must run without advisory ignores.
commands = [step.get("run", "") for step in steps if "run" in step]

if commands.count("cargo audit") != 1:
    sys.exit("FAIL: workflow must run plain cargo audit exactly once")

# Preserve least-privilege permissions.
if permissions != {"contents": "read"}:
    sys.exit("FAIL: cargo audit workflow must have read-only permissions")

print("Scheduled cargo audit schedule contract passed.")
PY
