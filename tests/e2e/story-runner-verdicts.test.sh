#!/usr/bin/env bash
# Verify the result contract by executing staged copies of the production
# runners. Only their VM/build prerequisites and story scripts are replaced;
# classification, summaries, and exit decisions are the real runner paths.
#
# Host-side only: no VM, daemon, LLM, or network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

fake_bin="$fixture/bin"
mkdir -p "$fake_bin"

write_fake_command() {
    local name="$1"
    if [[ "$name" == "timeout" ]]; then
        printf '%s\n' '#!/usr/bin/env bash' 'shift' 'exec "$@"' >"$fake_bin/$name"
    else
        printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$fake_bin/$name"
    fi
    chmod +x "$fake_bin/$name"
}

for command in cargo jq sysknife systemctl timeout; do
    write_fake_command "$command"
done

write_story() {
    local directory="$1" prefix="$2" story_id="$3" outcome="$4"
    local path="$directory/${prefix}${story_id}.sh"

    case "$outcome" in
        pass)
            printf '%s\n' '#!/usr/bin/env bash' "# Story $story_id: fixture" \
                'echo "PASS: fixture story"' >"$path"
            ;;
        skip)
            printf '%s\n' '#!/usr/bin/env bash' "# Story $story_id: fixture" \
                'echo "SKIP: fixture story"' >"$path"
            ;;
        rate)
            printf '%s\n' '#!/usr/bin/env bash' "# Story $story_id: fixture" \
                'echo "rate limit exceeded"' 'exit 1' >"$path"
            ;;
        silent)
            printf '%s\n' '#!/usr/bin/env bash' "# Story $story_id: fixture" \
                'exit 0' >"$path"
            ;;
        *)
            printf 'unknown fixture outcome: %s\n' "$outcome" >&2
            exit 1
            ;;
    esac
    chmod +x "$path"
}

CASE_OUTPUT=""
CASE_STATUS=0
run_case() {
    local label="$1" expected_status="$2" runner="$3"
    shift 3

    if CASE_OUTPUT="$(
        PATH="$fake_bin:$PATH" \
        SYSKNIFE_LLM_MODEL=fixture \
        SYSKNIFE_LLM_PROVIDER=ollama \
        SYSKNIFE_ALLOW_DESTRUCTIVE=0 \
        SYSKNIFE_STORY_DELAY=0 \
        SYSKNIFE_STORY_DELAY_SECS=0 \
        SYSKNIFE_STORY_TIMEOUT=30 \
            bash "$runner" "$@" 2>&1
    )"; then
        CASE_STATUS=0
    else
        CASE_STATUS=$?
    fi

    if [[ "$CASE_STATUS" -ne "$expected_status" ]]; then
        printf 'FAIL: %s (expected exit %s, got %s)\n' \
            "$label" "$expected_status" "$CASE_STATUS" >&2
        printf '%s\n' "$CASE_OUTPUT" >&2
        failures=$((failures + 1))
    fi
}

assert_output_contains() {
    local label="$1" needle="$2"
    if ! grep -Fq -- "$needle" <<<"$CASE_OUTPUT"; then
        printf 'FAIL: %s (output did not contain %s)\n' "$label" "$needle" >&2
        printf '%s\n' "$CASE_OUTPUT" >&2
        failures=$((failures + 1))
    fi
}

assert_output_not_contains() {
    local label="$1" needle="$2"
    if grep -Fq -- "$needle" <<<"$CASE_OUTPUT"; then
        printf 'FAIL: %s (output contained %s)\n' "$label" "$needle" >&2
        printf '%s\n' "$CASE_OUTPUT" >&2
        failures=$((failures + 1))
    fi
}

failures=0

# run-stories.sh has the rate-limit diagnostic in addition to SKIP. Replace only
# the fixed host paths needed to run its real story loop without root.
run_root="$fixture/run-stories"
mkdir -p "$run_root/stories"
run_runner="$run_root/run-stories.sh"
cp "$repo_root/tests/e2e/run-stories.sh" "$run_runner"
sed -i 's/\r$//' "$run_runner"
ready_marker="$run_root/ready"
touch "$ready_marker"
sed -i "s|/var/lib/sysknife-e2e/ready|$ready_marker|g" "$run_runner"
sed -i "s|/tmp/sysknife-story-|$fixture/sysknife-story-|g" "$run_runner"
write_story "$run_root/stories" story- 1 pass
write_story "$run_root/stories" story- 2 skip
write_story "$run_root/stories" story- 3 rate
write_story "$run_root/stories" story- 4 silent

run_case 'run-stories rejects SKIP' 1 "$run_runner" 1 2
assert_output_contains 'run-stories reports SKIP' 'SKIP'
run_case 'run-stories rejects RATELIMIT' 1 "$run_runner" 1 3
assert_output_contains 'run-stories keeps RATELIMIT diagnostic' 'RATELIMIT'
assert_output_not_contains 'run-stories does not relabel RATELIMIT as FAIL' 'FAIL'
run_case 'run-stories rejects an unmarked zero exit' 1 "$run_runner" 4
assert_output_contains 'run-stories explains an unmarked zero exit' \
    'exited 0 without a PASS marker'
run_case 'run-stories accepts an explicit PASS' 0 "$run_runner" 1

# Mutation check: removing the aggregate guard from a staged production copy
# must make the SKIP fixture green. This proves the assertions above are
# sensitive to the production decision, not merely to a parallel expectation.
run_mutant="$run_root/run-stories-no-unproven-gate.sh"
cp "$run_runner" "$run_mutant"
python3 - "$run_mutant" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = """if [[ $fail_count -gt 0 || $skip_count -gt 0 || $ratelimit_count -gt 0 ||
  $pass_count -eq 0 || $cassette_failed -gt 0 ]]; then"""
new = """if [[ $fail_count -gt 0 || $cassette_failed -gt 0 ]]; then"""
if text.count(old) != 1:
    raise SystemExit("story-runner gate mutation did not find one production guard")
path.write_text(text.replace(old, new))
PY
if ! grep -Fq -- 'if [[ $fail_count -gt 0 || $cassette_failed -gt 0 ]]; then' "$run_mutant"; then
    printf 'FAIL: story-runner gate mutation did not apply\n' >&2
    failures=$((failures + 1))
else
    run_case 'mutated run-stories accepts SKIP' 0 "$run_mutant" 1 2
fi

# Exercise the production runner's no-argument default selection without
# restating its curated list. Derive one passing fixture per checked-in story,
# then make the Fedora-only story fail the aggregate contract if selected.
for story_file in "$repo_root"/tests/e2e/stories/story-*.sh; do
    story_name="${story_file##*/}"
    story_id="${story_name#story-}"
    story_id="${story_id%.sh}"
    write_story "$run_root/stories" story- "$story_id" pass
done
write_story "$run_root/stories" story- 28 skip

run_case 'run-stories default set accepts portable stories' 0 "$run_runner"
assert_output_not_contains 'run-stories default set omits Fedora-only story 28' 'Story 28'

# The exec runner has the same result contract but its own production loop.
exec_root="$fixture/exec"
mkdir -p "$exec_root"
exec_runner="$exec_root/run-exec-stories.sh"
cp "$repo_root/tests/e2e/exec/run-exec-stories.sh" "$exec_runner"
sed -i 's/\r$//' "$exec_runner"
exec_ready="$exec_root/ready"
touch "$exec_ready"
sed -i "s|/var/lib/sysknife-e2e/ready|$exec_ready|g" "$exec_runner"
write_story "$exec_root" exec- 1 pass
write_story "$exec_root" exec- 2 skip
write_story "$exec_root" exec- 3 silent

run_case 'run-exec-stories rejects SKIP' 1 "$exec_runner" 1 2
run_case 'run-exec-stories rejects an unmarked zero exit' 1 "$exec_runner" 3
run_case 'run-exec-stories accepts an explicit PASS' 0 "$exec_runner" 1

# dev-stories.sh builds and starts a daemon before entering its production story
# loop. A fake successful build plus a pre-existing staged socket avoids both
# external operations while leaving the verdict path untouched.
dev_root="$fixture/dev"
dev_e2e="$dev_root/tests/e2e"
mkdir -p "$dev_e2e/stories"
dev_runner="$dev_e2e/dev-stories.sh"
cp "$repo_root/tests/e2e/dev-stories.sh" "$dev_runner"
sed -i 's/\r$//' "$dev_runner"
dev_socket="$dev_root/daemon.sock"
touch "$dev_socket"
sed -i "s|SOCKET_PATH=\"/tmp/sysknife-daemon.sock\"|SOCKET_PATH=\"$dev_socket\"|" \
    "$dev_runner"
for story_file in "$repo_root"/tests/e2e/stories/story-*.sh; do
    story_name="${story_file##*/}"
    story_id="${story_name#story-}"
    story_id="${story_id%.sh}"
    write_story "$dev_e2e/stories" story- "$story_id" pass
done
write_story "$dev_e2e/stories" story- 2 skip
write_story "$dev_e2e/stories" story- 3 silent

run_case 'dev-stories rejects SKIP' 1 "$dev_runner" 1 2
run_case 'dev-stories rejects an unmarked zero exit' 1 "$dev_runner" 3
run_case 'dev-stories accepts an explicit PASS' 0 "$dev_runner" 1

write_story "$dev_e2e/stories" story- 2 pass
write_story "$dev_e2e/stories" story- 3 pass
write_story "$dev_e2e/stories" story- 28 skip
run_case 'dev-stories default set accepts portable stories' 0 "$dev_runner"
assert_output_not_contains 'dev-stories default set omits Fedora-only story 28' 'Story 28'

if [[ "$failures" -ne 0 ]]; then
    printf '\n%d story-runner verdict failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'Story-runner verdict contract passed across all three production runners.\n'
