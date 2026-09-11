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

bash "$fixture/scripts/check_test_reachability.sh" "$fixture" >/dev/null

touch "$fixture/tests/release/orphan.test.sh"
if output="$(bash "$fixture/scripts/check_test_reachability.sh" "$fixture" 2>&1)"; then
    printf 'test-reachability test: orphan test unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'test is not invoked by a gate: tests/release/orphan.test.sh' <<< "$output" || {
    printf 'test-reachability test: orphan diagnostic omitted its path: %s\n' "$output" >&2
    exit 1
}

rm "$fixture/tests/release/orphan.test.sh" "$fixture/tests/e2e/reachable.test.sh"
if output="$(bash "$fixture/scripts/check_test_reachability.sh" "$fixture" 2>&1)"; then
    printf 'test-reachability test: empty suite unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'no tests discovered in tests/e2e/*.test.sh' <<< "$output" || {
    printf 'test-reachability test: empty-suite diagnostic missing: %s\n' "$output" >&2
    exit 1
}

touch "$fixture/tests/e2e/reachable.test.sh" "$fixture/tests/release/local-only.test.sh"
printf '%s\n' 'run: bash tests/release/local-only.test.sh' >> "$fixture/scripts/ci-local.sh"
if output="$(bash "$fixture/scripts/check_test_reachability.sh" "$fixture" 2>&1)"; then
    printf 'test-reachability test: local-only test unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'test is not invoked by a gate: tests/release/local-only.test.sh' <<< "$output" || {
    printf 'test-reachability test: local-only diagnostic omitted its path: %s\n' "$output" >&2
    exit 1
}

printf 'test-reachability test: orphan, empty-suite, and local-only failures validated.\n'
