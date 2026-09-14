#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/.github/workflows" "$fixture/scripts" \
    "$fixture/tests/release" "$fixture/tests/e2e"
cp "$repo_root/scripts/check_test_reachability.sh" "$fixture/scripts/"
touch "$fixture/tests/release/reachable.test.sh" "$fixture/tests/e2e/reachable.test.sh"
cat > "$fixture/.github/workflows/ci.yml" <<'EOF'
run: bash tests/release/reachable.test.sh
run: bash tests/e2e/reachable.test.sh
EOF
touch "$fixture/.github/workflows/e2e.yml" "$fixture/.github/workflows/release.yml" \
    "$fixture/scripts/ci-local.sh"

bash "$fixture/scripts/check_test_reachability.sh" >/dev/null

touch "$fixture/tests/release/orphan.test.sh"
if output="$(bash "$fixture/scripts/check_test_reachability.sh" 2>&1)"; then
    printf 'test-reachability test: orphan test unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'test is not invoked by a gate: tests/release/orphan.test.sh' <<< "$output" || {
    printf 'test-reachability test: orphan diagnostic omitted its path: %s\n' "$output" >&2
    exit 1
}

rm "$fixture/tests/release/orphan.test.sh" "$fixture/tests/e2e/reachable.test.sh"
if output="$(bash "$fixture/scripts/check_test_reachability.sh" 2>&1)"; then
    printf 'test-reachability test: empty suite unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'no tests discovered in tests/e2e/*.test.sh' <<< "$output" || {
    printf 'test-reachability test: empty-suite diagnostic missing: %s\n' "$output" >&2
    exit 1
}

touch "$fixture/tests/e2e/reachable.test.sh" "$fixture/tests/release/local-only.test.sh"
printf '%s\n' 'run: bash tests/release/local-only.test.sh' >> "$fixture/scripts/ci-local.sh"
if output="$(bash "$fixture/scripts/check_test_reachability.sh" 2>&1)"; then
    printf 'test-reachability test: local-only test unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'test is not invoked by a gate: tests/release/local-only.test.sh' <<< "$output" || {
    printf 'test-reachability test: local-only diagnostic omitted its path: %s\n' "$output" >&2
    exit 1
}

rm "$fixture/tests/release/local-only.test.sh"
touch "$fixture/tests/release/not-executed.test.sh"
cp "$fixture/.github/workflows/ci.yml" "$fixture/base-ci.yml"
for mention in \
    '# run: bash tests/release/not-executed.test.sh' \
    'path: tests/release/not-executed.test.sh' \
    'path: tests/release/not-executed.test.sh*' \
    'run: echo bash tests/release/not-executed.test.sh' \
    'run: bash tests/release/not-executed.test.sh.backup' \
    'run: bash prefix/tests/release/not-executed.test.sh' \
    'run: bash tests/release/not-executedXtestXsh' \
    'run: bash tests/release/not-executed.test.sh || true'; do
    cp "$fixture/base-ci.yml" "$fixture/.github/workflows/ci.yml"
    printf '%s\n' "$mention" >> "$fixture/.github/workflows/ci.yml"
    if output="$(bash "$fixture/scripts/check_test_reachability.sh" 2>&1)"; then
        printf 'test-reachability test: non-invocation unexpectedly passed: %s\n' "$mention" >&2
        exit 1
    fi
    grep -Fq 'test is not invoked by a gate: tests/release/not-executed.test.sh' <<< "$output"
done

# Each supported workflow can satisfy the gate with a standalone invocation.
for workflow in ci e2e release; do
    cp "$fixture/base-ci.yml" "$fixture/.github/workflows/ci.yml"
    printf '%s\n' '  - run: bash tests/release/not-executed.test.sh  # run the test' \
        >> "$fixture/.github/workflows/$workflow.yml"
    bash "$fixture/scripts/check_test_reachability.sh" >/dev/null
    if [[ "$workflow" != ci ]]; then
        : > "$fixture/.github/workflows/$workflow.yml"
    fi
done

# A missing workflow must fail even when an earlier file contains every match.
cp "$fixture/base-ci.yml" "$fixture/.github/workflows/ci.yml"
printf '%s\n' 'run: bash tests/release/not-executed.test.sh' >> "$fixture/.github/workflows/ci.yml"
rm "$fixture/.github/workflows/release.yml"
if bash "$fixture/scripts/check_test_reachability.sh" >/dev/null 2>&1; then
    printf 'test-reachability test: missing workflow unexpectedly passed\n' >&2
    exit 1
fi

printf 'test-reachability test: orphan, empty-suite, local-only, and invocation matching validated.\n'
