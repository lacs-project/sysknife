#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python3 - <<'PY'
import sys
from pathlib import Path
import yaml

workflow = yaml.safe_load(
    Path(".github/workflows/release.yml").read_text()
)
jobs = workflow["jobs"]

for job in ("publish-crates", "publish-npm"):
    if job not in jobs:
        sys.exit(f"FAIL: missing job {job}")

needs = jobs["publish-npm"].get("needs", [])
if isinstance(needs, str):
    needs = [needs]

if "publish-crates" not in needs:
    sys.exit(
        "FAIL: npm must depend on successful crates.io publication"
    )

print("PASS: npm depends on crates.io publication")
PY
