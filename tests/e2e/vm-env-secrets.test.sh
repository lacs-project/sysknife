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
    grep -Fq "| cmd_ssh \"sudo sh -c 'umask 077 && cat > \${GUEST_ENV_FILE}'\"" "$harness" \
        || report "$rel does not transfer the environment over SSH stdin"
    [ "$(grep -c 'rm -f \${GUEST_ENV_FILE}.*exec bash tests/e2e/' "$harness")" -eq 2 ] \
        || report "$rel must remove the guest environment before both scripts execute"

    if grep -Eq '[a-z_]+_env\+="? \$var=|sudo\$\{[a-z_]+_env\}' "$harness"; then
        report "$rel still interpolates forwarded variables into an argv command"
    fi

    for key in "${keys[@]}"; do
        grep -Fq "$key" "$harness" \
            || report "$rel does not forward $key"
    done
done

if [ "$failures" -ne 0 ]; then
    printf '\n%d VM environment secret handling failure(s).\n' "$failures" >&2
    exit 1
fi

printf 'VM environment secrets are stdin-only across %d harnesses.\n' "${#harnesses[@]}"
