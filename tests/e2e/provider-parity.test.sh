#!/usr/bin/env bash
#
# provider-parity.test.sh — every LLM provider the product supports must be
# reachable from the E2E harness.
#
# The daemon grew providers (groq, deepseek, mistral, xai) that the harness
# scripts never learned about. A key for one of those was exported on the host,
# the harness dropped it on the floor, and every story failed against a
# fallback provider that was not installed. The error surfaced as fifty broken
# stories rather than one missing variable.
#
# The provider list is derived from the Rust source rather than restated here,
# so adding a ninth provider fails this test until the harness forwards it.
#
# Host-side only: greps scripts, needs no VM, no daemon and no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config_rs="$repo_root/crates/sysknife-brain/src/config.rs"

# Scripts that must know every provider, and why:
#   ubuntu-vm.sh   forwards host env into the guest for provision and run
#   run-stories.sh selects the provider inside the VM
#   dev-stories.sh selects the provider for the no-VM host path
vm_script="$repo_root/tests/e2e/ubuntu-vm.sh"
run_script="$repo_root/tests/e2e/run-stories.sh"
dev_script="$repo_root/tests/e2e/dev-stories.sh"

for f in "$config_rs" "$vm_script" "$run_script" "$dev_script"; do
    [ -f "$f" ] || { printf 'missing file: %s\n' "$f" >&2; exit 1; }
done

# Key-based providers, straight from the config that reads them. Ollama is
# excluded by construction: it takes no API key.
mapfile -t keys < <(grep -oE '[A-Z0-9]+_API_KEY' "$config_rs" | sort -u)

# A grep that matches nothing would make every assertion below vacuously true,
# which is the exact failure this suite is meant to stop. Demand a plausible
# floor instead of trusting the extraction.
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

    grep -Fq -- "$key" "$vm_script" \
        || report "ubuntu-vm.sh does not forward $key into the guest"

    grep -Fq -- "$key" "$run_script" \
        || report "run-stories.sh does not detect $key"
    grep -Fq -- "\"$provider\"" "$run_script" \
        || report "run-stories.sh never selects provider $provider"

    grep -Fq -- "$key" "$dev_script" \
        || report "dev-stories.sh does not detect $key"
    grep -Fq -- "\"$provider\"" "$dev_script" \
        || report "dev-stories.sh never selects provider $provider"
done

# An empty SYSKNIFE_LLM_MODEL is not "unset": BrainConfig reads it with
# env::var().ok(), so "" wins over the per-provider default and the request
# goes out with no model at all. The harness must leave it unset instead.
if grep -qE '^export SYSKNIFE_LLM_MODEL="\$\{SYSKNIFE_LLM_MODEL:-\$\{SYSKNIFE_TEST_MODEL:-\}\}"' "$run_script"; then
    report "run-stories.sh exports SYSKNIFE_LLM_MODEL even when empty, overriding the product default with \"\""
fi

if [ "$failures" -ne 0 ]; then
    printf '\n%d provider-parity failure(s) across %d providers.\n' "$failures" "${#keys[@]}" >&2
    exit 1
fi

printf 'Provider parity passed: %d providers reachable from the harness.\n' "${#keys[@]}"
