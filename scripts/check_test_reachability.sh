#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
gate_files=(
    "$repo_root/.github/workflows/ci.yml"
    "$repo_root/.github/workflows/e2e.yml"
    "$repo_root/.github/workflows/release.yml"
)

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
        if ! grep -Fq -- "$relative_path" "${gate_files[@]}"; then
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
