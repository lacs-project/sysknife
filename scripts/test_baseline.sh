#!/usr/bin/env bash
#
# test_baseline.sh — run a test suite and hold the published test count to what
# it actually reports.
#
# Three docs quoted "1,561 Rust tests" and check_public_claims.sh *required* that
# exact string, so the figure was pinned by hand in four places at once. The suite
# had meanwhile grown to 1,681. Nothing was lying on purpose; there was simply no
# path from the measurement to the claim, so the claim could only decay.
#
# This is that path. The count comes from the test runner's own output, lands in
# tests/evidence/workspace-tests.json, and scripts/check_public_claims.sh reads
# the figure from there instead of carrying a literal. Regenerate deliberately:
#
#   UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh              # Rust workspace
#   UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh --frontend   # vitest
#
# Without UPDATE_TEST_BASELINE the run verifies instead: a suite whose size no
# longer matches the recorded baseline fails, because a published claim derives
# from that baseline. Remaining arguments are forwarded to the runner, so this is
# a drop-in for the plain `cargo nextest run --workspace --locked` step.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact="$repo_root/tests/evidence/workspace-tests.json"
recorder="$repo_root/scripts/record_test_baseline.py"

# Which suite to measure. The two live in different CI jobs, so each verifies its
# own field against the shared artifact rather than one job measuring both.
suite="rust"
field="tests"
if [[ "${1:-}" == "--frontend" ]]; then
    suite="frontend"
    field="frontend_tests"
    shift
fi

output="$(mktemp)"
trap 'rm -f "$output"' EXIT

# Both runners colourise their summaries when CI=true, even with output piped, so
# the count is read from de-colourised text. Skipping this cost a CI run: vitest
# passed 72/72 and the parse then reported no count at all, because the line
# arrives as `ESC[2m      Tests ESC[22m ... (72)ESC[39m`.
strip_ansi() {
    sed -E "s/$(printf '\033')\[[0-9;]*[a-zA-Z]//g" "$1"
}

if [[ "$suite" == "frontend" ]]; then
    shell_dir="$repo_root/apps/sysknife-shell"
    if [[ ! -x "$shell_dir/node_modules/.bin/vitest" ]]; then
        printf 'test_baseline: vitest is not installed; run npm ci in %s first.\n' \
            "${shell_dir#"$repo_root"/}" >&2
        exit 1
    fi
    set +e
    (cd "$shell_dir" && ./node_modules/.bin/vitest run "$@") 2>&1 | tee "$output"
    status="${PIPESTATUS[0]}"
    set -e
    # "      Tests  72 passed (72)" — the parenthesised figure is the total, which
    # counts skipped and failed tests too, so it is the suite size rather than a
    # pass count.
    count="$(strip_ansi "$output" | sed -nE 's/^[[:space:]]*Tests[[:space:]]+.*\(([0-9]+)\)[[:space:]]*$/\1/p' | tail -1)"
else
    set +e
    cargo nextest run --workspace --locked "$@" 2>&1 | tee "$output"
    status="${PIPESTATUS[0]}"
    set -e
    # "Starting 1681 tests across 37 binaries" — present whether the run passes or
    # fails, unlike the Summary line, whose shape changes on failure
    # ("1503/1675 tests run" vs "1681 tests run").
    count="$(strip_ansi "$output" | sed -nE 's/^[[:space:]]*Starting ([0-9]+) tests? across .*/\1/p' | tail -1)"
fi

if [[ -z "$count" ]]; then
    printf '\ntest_baseline: could not read a %s test count from the run output.\n' "$suite" >&2
    printf 'The count is what the published claim rests on, so a run that does not\n' >&2
    printf 'report one is a failure rather than something to skip quietly.\n' >&2
    exit 1
fi

regenerate_hint() {
    if [[ "$suite" == "frontend" ]]; then
        printf '  UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh --frontend\n' >&2
    else
        printf '  UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh\n' >&2
    fi
}

if [[ "$status" -ne 0 ]]; then
    printf '\ntest_baseline: %s suite failed; baseline left untouched (%s tests started).\n' \
        "$suite" "$count" >&2
    exit "$status"
fi

if [[ "${UPDATE_TEST_BASELINE:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$artifact")"
    # Only this suite's field is rewritten. The other was measured by a different
    # command — in CI, a different job — so overwriting it from here would
    # replace a measurement with a guess.
    python3 "$recorder" \
        --artifact "$artifact" \
        --field "$field" \
        --count "$count" \
        --commit "$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf 'unknown')"
    printf '\ntest_baseline: recorded %s %s tests in %s\n' \
        "$count" "$suite" "${artifact#"$repo_root"/}"
    exit 0
fi

if [[ ! -f "$artifact" ]]; then
    printf '\ntest_baseline: no baseline at %s. Record one:\n' "${artifact#"$repo_root"/}" >&2
    regenerate_hint
    exit 1
fi

recorded="$(python3 "$recorder" --artifact "$artifact" --field "$field" --read || true)"
if [[ -z "$recorded" ]]; then
    printf '\ntest_baseline: %s has no readable "%s" field. Record one:\n' \
        "${artifact#"$repo_root"/}" "$field" >&2
    regenerate_hint
    exit 1
fi

if [[ "$recorded" != "$count" ]]; then
    printf '\ntest_baseline: %s suite has %s tests, baseline says %s.\n' \
        "$suite" "$count" "$recorded" >&2
    printf 'Published claims derive from the baseline, so it has to move with the\n' >&2
    printf 'suite. Regenerate and commit it:\n' >&2
    regenerate_hint
    exit 1
fi

printf '\ntest_baseline: %s %s tests, matching the recorded baseline.\n' "$count" "$suite"
