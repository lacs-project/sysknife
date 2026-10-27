#!/usr/bin/env python3
# Fails when any run: block in release.yml passes --token on the command line.
# cargo reads CARGO_REGISTRY_TOKEN from the environment; a --token flag copies
# the secret into the process argv, where /proc/<pid>/cmdline exposes it.
import re
import sys
from pathlib import Path

import yaml

repo_root = Path(__file__).resolve().parents[2]
workflow = yaml.safe_load(
    (repo_root / ".github/workflows/release.yml").read_text()
)

token_flag = re.compile(r"(?<![\w-])--token(?![\w-])")
offenders = []
for job_name, job in workflow["jobs"].items():
    for step in job.get("steps", []):
        if token_flag.search(step.get("run", "")):
            step_name = step.get("name", "<unnamed>")
            offenders.append(f"job {job_name!r} step {step_name!r}")

if offenders:
    sys.exit(
        "FAIL: --token passed on the command line in " + "; ".join(offenders)
    )

print("PASS: no release.yml run block passes --token on the command line")
