#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate_files=(
    "$repo_root/.github/workflows/ci.yml"
    "$repo_root/.github/workflows/e2e.yml"
    "$repo_root/.github/workflows/release.yml"
)

# PyYAML is installed by the existing yamllint prerequisite. Parse actual run
# fields so strings in action inputs, comments, and heredocs cannot count.
invoked_tests="$(python3 - "${gate_files[@]}" <<'PYTHON'
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("test-reachability: PyYAML is required; install yamllint with python3 -m pip install yamllint==1.38.0")

command = re.compile(r"bash[ \t]+(tests/(?:release|e2e)/[A-Za-z0-9_.-]+\.test\.sh)(?:[ \t]+#.*)?[ \t]*")
for path in sys.argv[1:]:
    try:
        with open(path, encoding="utf-8") as stream:
            workflow = yaml.safe_load(stream)
        for job in (workflow or {}).get("jobs", {}).values():
            for step in job.get("steps", []):
                if not isinstance(step, dict):
                    continue
                run = step.get("run")
                if isinstance(run, str):
                    match = command.fullmatch(run.strip())
                    if match:
                        print(match.group(1))
    except (OSError, yaml.YAMLError, AttributeError, TypeError) as error:
        sys.exit(f"test-reachability: cannot read workflow {path}: {error}")
PYTHON
)"

check_suite() {
    local suite="$1"
    local test_file relative_path
    local tests=()

    while IFS= read -r -d '' test_file; do
        tests+=("$test_file")
    done < <(find "$repo_root/tests/$suite" -maxdepth 1 -type f -name '*.test.sh' -print0)

    if (( ${#tests[@]} == 0 )); then
        printf 'test-reachability: no tests discovered in tests/%s/*.test.sh\n' "$suite" >&2
        return 1
    fi

    for test_file in "${tests[@]}"; do
        relative_path="${test_file#"$repo_root/"}"
        if ! grep -Fxq -- "$relative_path" <<< "$invoked_tests"; then
            printf 'test-reachability: test is not invoked by a gate: %s\n' \
                "$relative_path" >&2
            return 1
        fi
    done

    return 0
}

check_suite release
check_suite e2e

printf 'test-reachability: every release and E2E test is invoked by a gate.\n'
