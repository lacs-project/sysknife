#!/usr/bin/env bash
#
# postgres-contract-guard.test.sh — both halves of the live Postgres contract
# must stay on the job that claims to run it.
#
# #313 closed the case where postgres-contract reported success with no
# database configured. The job now sets SYSKNIFE_REQUIRE_POSTGRES and runs
# with --include-ignored. Both are load-bearing; only the variable fails
# loudly from inside the test file. Drop the flag and cargo reports
# "6 passed; 5 ignored" and exits 0 — #294's shape with a different cause.
# See issue #315.
#
# This check reads the job and fails when either token is missing. It does
# not assert a test count: that would break the next time anyone adds a
# store test and teach whoever hit it to edit the number rather than read
# the check.
#
# Two design rules, both from tests/e2e/provider-parity.test.sh:
#
#   * The tokens are derived from postgres_store.rs, never restated as a
#     count, so renaming the env var or dropping #[ignore] fails here
#     until the job catches up.
#   * It covers every entry point, not just CI. ci-local.sh carries the
#     pair in two branches (URL already exported, and the path that starts
#     a container first). A guard that watches CI and ignores the local
#     mirror leaves half the surface open.
#
# A pattern that matched nothing would make every assertion below vacuously
# true, which is the exact failure this suite exists to stop. Missing files
# and an empty job extract fail rather than pass over nothing to read.
#
# Host-side only: greps files, needs no VM, no daemon, no network.
# Wired into docs-and-hygiene and scripts/ci-local.sh; a test nothing
# invokes is the same defect in a different costume.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ci_yml="$repo_root/.github/workflows/ci.yml"
ci_local="$repo_root/scripts/ci-local.sh"
store="$repo_root/crates/sysknife-daemon/tests/postgres_store.rs"

for f in "$ci_yml" "$ci_local" "$store"; do
    [ -f "$f" ] || { printf 'FAIL: missing file: %s\n' "$f" >&2; exit 1; }
done

# Fail-closed env var, taken from the store test the job runs.
# sort -u consumes every grep hit so a later head cannot SIGPIPE the pipeline
# under `set -o pipefail`.
require_token="$(grep -o 'SYSKNIFE_REQUIRE_POSTGRES' "$store" | sort -u || true)"
if [ -z "$require_token" ]; then
    printf 'FAIL: %s no longer names SYSKNIFE_REQUIRE_POSTGRES; the job token cannot be derived\n' \
        "$store" >&2
    exit 1
fi

# Live tests carry #[ignore]; without --include-ignored cargo never runs them
# and still exits 0. Demand the attribute rather than trusting a count.
if ! grep -Eq '#\[ignore' "$store"; then
    printf 'FAIL: %s has no #[ignore] tests; --include-ignored would not run the live contract\n' \
        "$store" >&2
    exit 1
fi
# cargo's flag for #[ignore] tests. Named here once; the rust file proves
# those tests are ignored, the job must still pass the flag.
ignore_token='--include-ignored'

tokens=("$require_token" "$ignore_token")

failures=0
report() {
    printf 'FAIL  %s\n' "$1" >&2
    failures=$((failures + 1))
}

# Top-level GitHub Actions job. Empty extract is a failure: grepping nothing
# would report every token present.
extract_job() {
    local file="$1"
    local job="$2"
    awk -v job="$job" '
        $0 ~ ("^  " job ":[[:space:]]*$") { inside = 1 }
        inside && /^  [A-Za-z0-9_-]+:/ && $0 !~ ("^  " job ":") { exit }
        inside { print }
    ' "$file"
}

job="$(extract_job "$ci_yml" "postgres-contract")"
if [ -z "$job" ]; then
    report "$ci_yml has no postgres-contract job to read"
else
    for token in "${tokens[@]}"; do
        grep -Fq -- "$token" <<<"$job" \
            || report "$ci_yml postgres-contract job is missing $token"
    done
fi

# Each cargo invocation of postgres_store, including the env lines that
# continue onto it. The label string also names the command, so only
# statements that actually call run_step count as a branch.
extract_invocations() {
    awk '
        {
            if (buf != "") buf = buf "\n" $0
            else buf = $0
            if ($0 ~ /\\$/) next
            if (buf ~ /run_step/ && buf ~ /postgres_store/) printf "%s\x1e", buf
            buf = ""
        }
    ' "$1"
}

branch_count=0
while IFS= read -r -d $'\x1e' stmt; do
    [ -z "$stmt" ] && continue
    branch_count=$((branch_count + 1))
    for token in "${tokens[@]}"; do
        grep -Fq -- "$token" <<<"$stmt" \
            || report "$ci_local postgres-contract branch $branch_count is missing $token"
    done
done < <(extract_invocations "$ci_local")

if [ "$branch_count" -lt 2 ]; then
    report "$ci_local has $branch_count postgres-contract run_step branch(es); both the exported-URL path and the container-start path must carry the pair"
fi

if [ "$failures" -ne 0 ]; then
    printf '\n%d postgres-contract guard failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'postgres-contract guard passed: %s and %s present on the CI job and %d ci-local.sh branches.\n' \
    "$require_token" "$ignore_token" "$branch_count"
