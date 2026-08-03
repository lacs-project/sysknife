#!/usr/bin/env bash
#
# provider-parity.test.sh — every LLM provider the product supports must be
# reachable from every E2E entry point.
#
# The daemon grew providers (groq, deepseek, mistral, xai) that the harness
# scripts never learned about. A key for one of those was exported on the host,
# the harness dropped it on the floor, and every story failed against a
# fallback provider that was not installed. The error surfaced as fifty broken
# stories rather than one missing variable, and the message named the wrong
# provider while it did so.
#
# Two design rules this test follows, both learned the hard way in review:
#
#   * The provider list is derived from the Rust source, never restated here,
#     so adding a ninth provider fails this test until the harness forwards it.
#   * It covers every entry point, not just the Ubuntu ones. The first version
#     checked three scripts and passed while atomic-vm.sh and
#     run-exec-stories.sh still carried the original bug. A partial check that
#     reads like a full one is worse than no check.
#
# Host-side only: greps scripts, needs no VM, no daemon and no network.
# Wired into scripts/ci-local.sh so it actually runs; a test nothing invokes is
# the same defect in a different costume.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config_rs="$repo_root/crates/sysknife-brain/src/config.rs"

# Scripts that forward host environment into a guest.
forwarding_scripts=(
    "tests/e2e/ubuntu-vm.sh"
    "tests/e2e/atomic-vm.sh"
)
# Scripts that choose the provider for a run.
selecting_scripts=(
    "tests/e2e/run-stories.sh"
    "tests/e2e/exec/run-exec-stories.sh"
    "tests/e2e/dev-stories.sh"
)

for rel in "${forwarding_scripts[@]}" "${selecting_scripts[@]}"; do
    [ -f "$repo_root/$rel" ] || { printf 'missing file: %s\n' "$rel" >&2; exit 1; }
done
[ -f "$config_rs" ] || { printf 'missing file: %s\n' "$config_rs" >&2; exit 1; }

# Key-based providers, straight from the config that reads them. Ollama is
# excluded by construction: it takes no API key. Today this yields 7.
mapfile -t keys < <(grep -oE '[A-Z0-9]+_API_KEY' "$config_rs" | sort -u)

# A pattern that matched nothing would make every assertion below vacuously
# true, which is the exact failure this suite exists to stop. Demand a floor
# rather than trusting the extraction.
if [ "${#keys[@]}" -lt 7 ]; then
    printf 'provider extraction found only %d keys in %s; the pattern has drifted\n' \
        "${#keys[@]}" "$config_rs" >&2
    exit 1
fi

failures=0
report() {
    printf 'FAIL  %s\n' "$1" >&2
    failures=$((failures + 1))
}

for key in "${keys[@]}"; do
    # PROVIDER_API_KEY -> provider
    provider="$(printf '%s' "${key%_API_KEY}" | tr '[:upper:]' '[:lower:]')"

    for rel in "${forwarding_scripts[@]}"; do
        grep -Fq -- "$key" "$repo_root/$rel" \
            || report "$rel does not forward $key into the guest"
    done

    for rel in "${selecting_scripts[@]}"; do
        grep -Fq -- "$key" "$repo_root/$rel" \
            || report "$rel does not detect $key"
        grep -Fq -- "\"$provider\"" "$repo_root/$rel" \
            || report "$rel never selects provider $provider"
    done
done

# An empty SYSKNIFE_LLM_MODEL is not "unset": BrainConfig reads it with
# env::var().ok(), so "" wins over the per-provider default and the request
# goes out naming no model. Every selecting script must leave it unset instead.
for rel in "${selecting_scripts[@]}"; do
    if grep -qE '^export SYSKNIFE_LLM_MODEL="\$\{SYSKNIFE_LLM_MODEL:-\$\{SYSKNIFE_TEST_MODEL:-\}\}"' \
            "$repo_root/$rel"; then
        report "$rel exports SYSKNIFE_LLM_MODEL even when empty, overriding the product default with \"\""
    fi
done

# The planner's own rate limit (DEFAULT_MAX_RPM) is lower than the rate a
# full story suite generates, so a run that cannot raise it silently reports
# throttled stories as failures. The knob has to reach the guest.
for rel in "${forwarding_scripts[@]}"; do
    grep -Fq -- 'SYSKNIFE_MAX_RPM' "$repo_root/$rel" \
        || report "$rel does not forward SYSKNIFE_MAX_RPM, so a full suite cannot raise the planner rate limit"
done

if [ "$failures" -ne 0 ]; then
    printf '\n%d provider-parity failure(s) across %d providers.\n' "$failures" "${#keys[@]}" >&2
    exit 1
fi

printf 'Provider parity passed: %d providers reachable from %d entry points.\n' \
    "${#keys[@]}" "$(( ${#forwarding_scripts[@]} + ${#selecting_scripts[@]} ))"
