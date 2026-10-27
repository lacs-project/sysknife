#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "$repo_root" <<'PYTHON'
from pathlib import Path
import sys
import tempfile

try:
    import yaml
except ImportError:
    sys.exit("workflow-timeouts: PyYAML is required")


def invalid_timeouts(paths):
    invalid = []
    for path in paths:
        try:
            workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise RuntimeError(f"cannot read {path}: {error}") from error
        if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
            raise RuntimeError(f"{path} has no jobs mapping")
        for name, job in workflow["jobs"].items():
            if not isinstance(job, dict):
                raise RuntimeError(f"{path} job {name} is not a mapping")
            if "uses" in job:
                continue
            timeout = job.get("timeout-minutes")
            if type(timeout) is not int or timeout <= 0:
                invalid.append(f"{path.name}/{name}")
    return invalid


with tempfile.TemporaryDirectory(prefix="workflow-timeouts-") as directory:
    fixture = Path(directory) / "fixture.yml"
    fixture.write_text(
        "jobs:\n"
        "  fast:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: []\n"
        "  bounded:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n"
        "    steps: []\n"
        "  empty:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes:\n"
        "    steps: []\n"
        "  string:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: '5'\n"
        "    steps: []\n"
        "  zero:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 0\n"
        "    steps: []\n"
        "  boolean:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: true\n"
        "    steps: []\n"
        "  reusable:\n"
        "    uses: ./.github/workflows/publish-mcp.yml\n",
        encoding="utf-8",
    )
    expected = [
        "fixture.yml/fast",
        "fixture.yml/empty",
        "fixture.yml/string",
        "fixture.yml/zero",
        "fixture.yml/boolean",
    ]
    actual = invalid_timeouts([fixture])
    if actual != expected:
        raise RuntimeError(f"fixture expected {expected}, got {actual}")

workflows = Path(sys.argv[1]) / ".github" / "workflows"
paths = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
if not paths:
    raise RuntimeError(f"no workflow files found under {workflows}")

invalid = invalid_timeouts(paths)
if invalid:
    print("FAIL: workflow jobs missing positive integer timeout-minutes:", file=sys.stderr)
    for job in invalid:
        print(f"  {job}", file=sys.stderr)
    sys.exit(1)

print(f"workflow-timeouts: checked all jobs in {len(paths)} workflow files")
PYTHON
