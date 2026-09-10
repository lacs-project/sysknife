#!/usr/bin/env bash
#
# postgres-contract-guard.test.sh — every live Postgres contract must stay on
# the job that claims to run it, and on the local mirror of that job.
#
# #313 closed the case where postgres-contract reported success with no
# database configured. The job now sets SYSKNIFE_REQUIRE_POSTGRES and runs
# with --include-ignored. Both are load-bearing; only the variable fails
# loudly from inside the test file. Drop the flag and cargo reports
# "6 passed; 5 ignored" and exits 0 — #294's shape with a different cause.
# See issue #315.
#
# The job later grew a second live step (#340, the CLI anchor exit-code
# contract) and this check did not see it, because it looked for its two
# tokens anywhere in the job rather than on each command. Three mutations of
# that step left the guard green: dropping --ignored (cargo reports
# "1 ignored", exit 0), misspelling the test name by one character (cargo
# reports "running 0 tests", exit 0), and deleting the step outright. So the
# check now reads each cargo invocation separately.
#
# Design rules, all three inherited from tests/e2e/provider-parity.test.sh:
#
#   * Everything is derived from the Rust sources, never restated as a
#     count or a list. A test file that names SYSKNIFE_REQUIRE_POSTGRES is
#     a live-Postgres contract file, so some step has to run it; renaming
#     the env var or dropping #[ignore] fails here until the job catches up.
#   * It covers every entry point, not just CI. ci-local.sh carries the
#     contract in two branches (URL already exported, and the path that
#     starts a container first). A guard that watches CI and ignores the
#     local mirror leaves half the surface open.
#   * No test count is asserted. That would break the next time anyone adds
#     a store test and would teach whoever hit it to edit the number rather
#     than read the check.
#
# A pattern that matched nothing would make every assertion below vacuously
# true, which is the exact failure this suite exists to stop. Missing files,
# an empty job extract and an empty marker set all fail rather than pass over
# nothing to read.
#
# Host-side only: greps files, needs no VM, no daemon, no network.
# Wired into docs-and-hygiene and scripts/ci-local.sh; a test nothing
# invokes is the same defect in a different costume.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ci_yml="$repo_root/.github/workflows/ci.yml"
ci_local="$repo_root/scripts/ci-local.sh"

for f in "$ci_yml" "$ci_local"; do
    [ -f "$f" ] || { printf 'FAIL: missing file: %s\n' "$f" >&2; exit 1; }
done

failures=0
report() {
    printf 'FAIL  %s\n' "$1" >&2
    failures=$((failures + 1))
}

# --------------------------------------------------------------------------
# The marker set: which test files are live Postgres contracts.
# --------------------------------------------------------------------------
# The fail-closed env var is the marker. A file that reads it refuses to pass
# quietly without a database (#313), which is precisely what makes it a
# contract someone has to run. Deriving the set means a new live test file is
# covered the day it lands, with no list here to forget to update.
#
# `|| true` keeps an empty result reachable: grep exiting 1 on no match would
# otherwise kill the script at the assignment under `set -o pipefail`, and the
# diagnostic below would never print. That shape cost five guards their error
# messages (#347).
require_token='SYSKNIFE_REQUIRE_POSTGRES'
marker_files="$(
    grep -rl --include='*.rs' -F "$require_token" \
        "$repo_root/crates" "$repo_root/apps" 2>/dev/null \
        | grep '/tests/' | sort || true
)"
if [ -z "$marker_files" ]; then
    printf 'FAIL: no test file under crates/ or apps/ names %s; the contract set cannot be derived\n' \
        "$require_token" >&2
    exit 1
fi

# stem -> path, and the ordered list of stems.
declare -A marker_path=()
marker_stems=()
while IFS= read -r path; do
    [ -n "$path" ] || continue
    stem="$(basename "$path" .rs)"
    if [ -n "${marker_path[$stem]:-}" ]; then
        report "duplicate live test target $stem; qualify the guard by package before adding this target"
    fi
    marker_path["$stem"]="$path"
    marker_stems+=("$stem")
    # Live tests carry #[ignore]; without an ignore flag cargo never runs them
    # and still exits 0. Demand the attribute rather than trusting a count.
    if ! grep -Eq '#\[ignore' "$path"; then
        report "${path#"$repo_root"/} names $require_token but has no #[ignore] test; no ignore flag would run its contract"
    fi
done <<<"$marker_files"

# cargo's two flags for #[ignore] tests. `--ignored` runs only them,
# `--include-ignored` runs them alongside the rest; either is acceptable, and
# neither is optional.
ignore_flag_re='(^|[[:space:]])(--include-ignored|--ignored)([[:space:]]|$)'

# --------------------------------------------------------------------------
# Shared assertions for one cargo invocation.
# --------------------------------------------------------------------------
# `where` is a human-readable location for the diagnostic; `cmd` is the whole
# invocation on one line with runs of whitespace squashed.
check_invocation() {
    local where="$1" cmd="$2"

    local harness_args="${cmd#* -- }"
    if [[ "$harness_args" == "$cmd" ]] || ! [[ "$harness_args" =~ $ignore_flag_re ]]; then
        report "$where runs cargo test without --ignored or --include-ignored, so its #[ignore] contract would be skipped and still exit 0"
    fi

    local target=""
    if [[ "$cmd" =~ --test[[:space:]]+([A-Za-z0-9_]+) ]]; then
        target="${BASH_REMATCH[1]}"
    else
        report "$where runs cargo test with no --test target, so which contract it covers cannot be derived"
        return
    fi

    # Any bare word left after the options and before the `--` separator is a
    # test-name filter. `cargo test NAME -- --exact` matching nothing prints
    # "running 0 tests" and exits 0, so a filter that no longer resolves is a
    # green step that tests nothing.
    local head="${cmd%% -- *}"
    local skip=0 tok filters=()
    for tok in $head; do
        if [ "$skip" = 1 ]; then skip=0; continue; fi
        case "$tok" in
            cargo | test) ;;
            # A shell line continuation survives the whitespace squash.
            '\') ;;
            -p | --package | --test | --features | --manifest-path) skip=1 ;;
            -* | *=*) ;;
            *) filters+=("$tok") ;;
        esac
    done

    local file="${marker_path[$target]:-}"
    if [ -z "$file" ]; then
        # Every target invoked by the live job must retain its fail-closed
        # marker. Checking only marker -> invocation lets a renamed marker
        # silently shrink the contract set while CI still runs that target.
        if ! compgen -G "$repo_root/*/*/tests/$target.rs" >/dev/null; then
            report "$where targets --test $target, and no crates/*/tests/$target.rs or apps/*/tests/$target.rs exists to run"
        else
            report "$where targets --test $target, whose file no longer names $require_token; the contract set narrowed under the job"
        fi
        return
    fi

    for tok in ${filters+"${filters[@]}"}; do
        # The filter has to name an #[ignore]d test in the file this step
        # targets. Walk up from the fn to the nearest attribute block so a
        # non-ignored test cannot satisfy an --ignored run.
        if ! awk -v name="$tok" '
            /^[[:space:]]*#\[ignore/ { ignored = 1 }
            /^[[:space:]]*#\[(tokio::)?test\]/ { test = 1 }
            /^[[:space:]]*(async[[:space:]]+)?fn[[:space:]]/ {
                if ($0 ~ ("fn[[:space:]]+" name "[[:space:]]*\\(") && ignored && test) {
                    found = 1
                    exit
                }
                ignored = 0
                test = 0
            }
            END { exit found ? 0 : 1 }
        ' "$file"; then
            report "$where filters on '$tok', which is not an #[ignore] test in ${file#"$repo_root"/}; the step would run 0 tests and exit 0"
        fi
    done
}

# --------------------------------------------------------------------------
# .github/workflows/ci.yml
# --------------------------------------------------------------------------
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

# One record per `- name:` step, folded scalars joined, whitespace squashed, so
# a flag on one step cannot satisfy an assertion about another. That blindness
# is what let #340's step regress unnoticed.
extract_steps() {
    awk '
        /^      - name:/ {
            if (buf != "") printf "%s\x1e", buf
            buf = $0
            next
        }
        buf != "" { buf = buf " " $0 }
        END { if (buf != "") printf "%s\x1e", buf }
    ' <<<"$1" | tr -s '[:space:]' ' ' | tr '\036' '\n'
}

job="$(extract_job "$ci_yml" "postgres-contract")"
if [ -z "$job" ]; then
    report "$ci_yml has no postgres-contract job to read"
else
    grep -Eq "^[[:space:]]+$require_token: [\"']?1[\"']?([[:space:]]|$)" <<<"$job" \
        || report "$ci_yml postgres-contract job is missing $require_token"

    ci_targets=""
    while IFS= read -r step; do
        [ -n "$step" ] || continue
        case "$step" in
            *"cargo test"*) ;;
            *) continue ;;
        esac
        step_name="$(sed -E 's/^ *- name: *//; s/ run:.*//' <<<"$step")"
        # Drop the step's name and the `run: >-` preamble; the words in a step
        # title are not arguments, and reading them as such reports a filter
        # per word.
        step="${step#* run: }"
        step="${step#>- }"
        step="${step#> }"
        step="${step#| }"
        if [[ "$step" != cargo\ test\ * ]]; then
            report "$ci_yml step '$step_name' must directly run its cargo test command"
            continue
        fi
        check_invocation "$ci_yml postgres-contract step '$step_name'" "$step"
        if [[ "$step" =~ --test[[:space:]]+([A-Za-z0-9_]+) ]]; then
            ci_targets="$ci_targets ${BASH_REMATCH[1]}"
        fi
    done < <(extract_steps "$job")

    # Every live-contract file needs a step. Deleting #340's step, which this
    # check used to allow, fails here.
    for stem in "${marker_stems[@]}"; do
        case " $ci_targets " in
            *" $stem "*) ;;
            *) report "$ci_yml postgres-contract job runs no step against --test $stem, whose ${marker_path[$stem]##*/} is a live $require_token contract" ;;
        esac
    done
fi

# --------------------------------------------------------------------------
# scripts/ci-local.sh
# --------------------------------------------------------------------------
# Each cargo invocation reached through run_step, including the env lines that
# continue onto it. The label string also names the command, so only
# statements that actually call run_step count.
extract_invocations() {
    awk '
        {
            if (buf != "") buf = buf "\n" $0
            else buf = $0
            if ($0 ~ /\\$/) next
            if (buf ~ /run_step/ && buf ~ /cargo test/) printf "%s\x1e", buf
            buf = ""
        }
    ' "$1"
}

declare -A local_target_count=()
invocation=0
while IFS= read -r -d $'\x1e' stmt; do
    [ -n "$stmt" ] || continue
    invocation=$((invocation + 1))
    squashed="$(tr -s '[:space:]' ' ' <<<"$stmt")"
    # The label repeats the command verbatim, so strip it before parsing or the
    # quoted copy is read as a second invocation.
    parsed="${squashed#*run_step }"
    # Remove exactly one quoted label. Searching for the first 'cargo test'
    # instead reads the label, allowing the actual command to silently drift.
    label_re='^"[^"]*"[[:space:]]+(.*)$'
    if [[ "$parsed" =~ $label_re ]]; then
        parsed="${BASH_REMATCH[1]}"
        parsed="${parsed#\\ }"
    else
        report "$ci_local invocation $invocation must have one quoted run_step label"
        continue
    fi
    if [[ "$parsed" != cargo\ test\ * ]]; then
        report "$ci_local invocation $invocation does not run cargo test"
        continue
    fi
    environment="${squashed%%run_step*}"
    if ! [[ "$environment" =~ (^|[[:space:]])SYSKNIFE_REQUIRE_POSTGRES=1([[:space:]]|$) ]]; then
        report "$ci_local invocation $invocation must set SYSKNIFE_REQUIRE_POSTGRES=1"
    fi
    check_invocation "$ci_local invocation $invocation" "$parsed"
    if [[ "$parsed" =~ --test[[:space:]]+([A-Za-z0-9_]+) ]]; then
        target="${BASH_REMATCH[1]}"
        local_target_count["$target"]=$(( ${local_target_count["$target"]:-0} + 1 ))
    fi
done < <(extract_invocations "$ci_local")

# Both entry paths, for every contract. ci-local.sh reaches the database two
# ways (URL already exported, container started here) and a contributor who
# takes either one has to run the same set CI does.
# The lower bound reflects those two current paths; adding another entry path
# also requires revisiting this coverage check.
for stem in "${marker_stems[@]}"; do
    count="${local_target_count[$stem]:-0}"
    if [ "$count" -lt 2 ]; then
        report "$ci_local runs --test $stem in $count branch(es); both the exported-URL path and the container-start path must run it"
    fi
done

if [ "$failures" -ne 0 ]; then
    printf '\n%d postgres-contract guard failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'postgres-contract guard passed: %d live contract file(s) (%s), each run with an ignore flag by ci.yml and by both ci-local.sh branches.\n' \
    "${#marker_stems[@]}" "${marker_stems[*]}"
