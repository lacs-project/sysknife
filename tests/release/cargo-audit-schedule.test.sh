#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
import sys
from pathlib import Path

workflow_path = Path(".github/workflows/cargo-audit.yml")

if not workflow_path.is_file():
    sys.exit("FAIL: scheduled cargo audit workflow is missing")

import yaml

workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

# PyYAML may interpret the YAML key "on" as the Boolean True.
triggers = workflow.get("on", workflow.get(True, {}))

if "workflow_dispatch" not in triggers:
    sys.exit("FAIL: cargo audit cannot be triggered manually")

if not isinstance(triggers, dict) or not triggers.get("schedule"):
    sys.exit("FAIL: scheduled cargo audit has no schedule trigger")

if triggers["schedule"] != [{"cron": "17 6 * * *"}]:
    sys.exit("FAIL: cargo audit must run daily at 06:17 UTC")

permissions = workflow.get("permissions", {})

import re

steps = workflow.get("jobs", {}).get("cargo-audit", {}).get("steps", [])

actions = [step["uses"] for step in steps if "uses" in step]

if not actions:
    sys.exit("FAIL: cargo audit workflow has no GitHub Actions")

for action in actions:
    if not re.fullmatch(r"[^@\s]+@[0-9a-fA-F]{40}", action):
        sys.exit(f"FAIL: action is not pinned to a full SHA: {action}")

expected_actions = [
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "taiki-e/install-action@1168f6810a3cb30a3514bf5756a3b7f0422c6df8",
]

if actions != expected_actions:
    sys.exit("FAIL: cargo audit actions must match the approved CI pins")

install_step = steps[1]

if install_step.get("with", {}).get("tool") != "cargo-audit":
    sys.exit("FAIL: install action must install cargo-audit")

commands = [step.get("run", "") for step in steps if "run" in step]

if commands.count("cargo audit") != 1:
    sys.exit("FAIL: workflow must run plain cargo audit exactly once")

if permissions != {"contents": "read"}:
    sys.exit("FAIL: cargo audit workflow must have read-only permissions")

print("Scheduled cargo audit schedule contract passed.")
PY
