#!/usr/bin/env bash
# Ensure VM harnesses send provider secrets over stdin, never in process argv.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config_rs="$repo_root/crates/sysknife-brain/src/config.rs"
harnesses=(
    "tests/e2e/atomic-vm.sh"
    "tests/e2e/ubuntu-vm.sh"
)

keys=()
while IFS= read -r key; do
    keys+=("$key")
done < <(grep -oE '[A-Z0-9]+_API_KEY' "$config_rs" | sort -u)
if [ "${#keys[@]}" -lt 7 ]; then
    printf 'provider extraction found only %d keys\n' "${#keys[@]}" >&2
    exit 1
fi

failures=0
report() {
    printf 'FAIL  %s\n' "$1" >&2
    failures=$((failures + 1))
}

for rel in "${harnesses[@]}"; do
    harness="$repo_root/$rel"

    [ "$(grep -c '^[[:space:]]*write_guest_env_file \\' "$harness")" -eq 2 ] \
        || report "$rel must stage environment for both provision and run"
    grep -Fq "| cmd_ssh \"sudo sh -c 'rm -f \${GUEST_ENV_FILE} && umask 077 && cat > \${GUEST_ENV_FILE}'\"" "$harness" \
        || report "$rel does not transfer the environment over SSH stdin into a fresh 0600 file"
    [ "$(grep -c 'rm -f \${GUEST_ENV_FILE}.*exec bash tests/e2e/' "$harness")" -eq 2 ] \
        || report "$rel must remove the guest environment before both scripts execute"

    # The regression to catch is a secret value reaching argv, not one
    # particular way of spelling it. The previous form matched the old
    # accumulator by name (`prov_env`, `sudo_env`), so reintroducing the same
    # bug under any other variable name passed silently.
    #
    # Structural instead: no line that invokes cmd_ssh may interpolate a
    # shell variable straight after `sudo`, which is the shape that puts a
    # value on the guest command line. The stdin transfer and the `sudo bash
    # -c` consumer both name a literal command after sudo, so neither matches.
    if grep -nE 'cmd_ssh[^#]*sudo *[$"]?\$\{?[A-Za-z_]' "$harness" \
        | grep -vE 'sudo (sh|bash) -c' >/dev/null; then
        report "$rel interpolates a variable into an argv command after sudo"
    fi

    # And the specific values must never appear on a cmd_ssh line at all.
    for key in "${keys[@]}"; do
        if grep -n 'cmd_ssh' "$harness" | grep -Fq "$key"; then
            report "$rel names $key on a cmd_ssh line, which puts it in argv"
        fi
    done

    # Anchored to the call sites. `grep -Fq "$key" "$harness"` asked only
    # whether the name appears anywhere, so a key deleted from cmd_run and
    # left in a comment still passed. Extract the arguments of each
    # write_guest_env_file call and require the key in the run one.
    run_block="$(awk '/^cmd_run\(\)/,/^}/' "$harness")"
    prov_block="$(awk '/^cmd_provision\(\)/,/^}/' "$harness")"
    if [ -z "$run_block" ] || [ -z "$prov_block" ]; then
        report "$rel: could not read cmd_run/cmd_provision; the extraction is broken"
        continue
    fi
    for key in "${keys[@]}"; do
        printf '%s' "$run_block" | grep -Fq "$key" \
            || report "$rel does not forward $key from cmd_run"
    done
done

if [ "$failures" -ne 0 ]; then
    printf '\n%d VM environment secret handling failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'VM environment secrets are stdin-only across %d harnesses.\n' "${#harnesses[@]}"
