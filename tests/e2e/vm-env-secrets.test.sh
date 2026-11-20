#!/usr/bin/env bash
# Ensure VM harnesses send provider secrets over stdin, never in process argv.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config_rs="$repo_root/crates/sysknife-brain/src/config.rs"
harnesses=()
while IFS= read -r harness; do
    harnesses+=("$harness")
done < <(grep -l '^cmd_ssh()' "$repo_root"/tests/e2e/*.sh)
if [ "${#harnesses[@]}" -lt 2 ]; then
    printf 'expected at least two VM harnesses defining cmd_ssh, found %d\n' "${#harnesses[@]}" >&2
    exit 1
fi

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

for harness in "${harnesses[@]}"; do
    rel="${harness#"$repo_root"/}"

    [ "$(grep -c '^[[:space:]]*write_guest_env_file \\' "$harness")" -eq 2 ] \
        || report "$rel must stage environment for both provision and run"
    [ "$(grep -c 'rm -f \${GUEST_ENV_FILE}.*exec bash tests/e2e/' "$harness")" -eq 2 ] \
        || report "$rel must remove the guest environment before both scripts execute"

    # Inspect the remote command, including continuation lines, independently
    # of which guest account runs it. Values piped into stdin precede cmd_ssh.
    calls="$(awk '
        /^[[:space:]]*#/ { next }
        { while (sub(/\\$/, "") && (getline more) > 0) $0 = $0 more }
        match($0, /(^|[[:space:]|])cmd_ssh[[:space:]]+/) {
            print substr($0, RSTART + RLENGTH)
        }
    ' "$harness")"
    if [ -z "$calls" ]; then
        report "$rel has no SSH command to check"
        continue
    fi
    grep -Fq '| cmd_ssh "sudo sh -c' "$harness" \
        || report "$rel must pipe the privileged file transfer into SSH"
    transfers="$(grep -E 'sudo sh -c|cat[[:space:]]*>' <<<"$calls" || true)"
    while IFS= read -r transfer; do
        [[ "$transfer" == *"sudo sh -c 'rm -f \${GUEST_ENV_FILE} && umask 077 && cat > \${GUEST_ENV_FILE}'"* ]] \
            || report "$rel must transfer stdin into a fresh 0600 file"
    done <<<"$transfers"
    while IFS= read -r var; do
        case "$var" in
            VM_USER|GUEST_ENV_FILE|story_args) ;;
            *) report "$rel interpolates \$$var into an SSH command" ;;
        esac
    done < <(grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*' <<<"$calls" | tr -d '${' | sort -u)
    for key in "${keys[@]}"; do
        if grep -Fq "$key" <<<"$calls"; then
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
        grep -Fq "$key" <<<"$run_block" \
            || report "$rel does not forward $key from cmd_run"
    done
done

if [ "$failures" -ne 0 ]; then
    printf '\n%d VM environment secret handling failure(s).\n' "$failures" >&2
    exit 1
fi

# Exercise the test-exec entry point with separate host and guest environments.
# The transport accepts only the fixed guest command. The story checks what
# arrived on stdin after Bash has decoded and exported the assignments.
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/sysknife/tests/e2e/exec"
touch "$scratch/vm-key"
cat > "$scratch/bin/ssh" <<'SH'
#!/usr/bin/env bash
set -eu
[[ "${!#}" == 'cd ~/sysknife && exec bash -s' ]]
for arg in "$@"; do
    [[ "$arg" != *fixture-value* ]]
done
exec env -i PATH="$PATH" HOME="$HOME" bash -c "${!#}"
SH
chmod +x "$scratch/bin/ssh"
cat > "$scratch/sysknife/tests/e2e/exec/run-exec-stories.sh" <<'SH'
set -eu
while IFS= read -r name; do
    [[ "${!name}" == "fixture-value-$name" ]]
done < "$HOME/providers"
[[ "$SYSKNIFE_LLM_MODEL" == $'reader\x27s model\nsecond line' ]]
[[ -z "${SYSKNIFE_TEST_MODEL+x}" ]]
[[ "$#" == 3 && "$1" == 1 && "$2" == 'two words' && -z "$3" ]]
touch "$HOME/story-ran"
SH
printf '%s\n' "${keys[@]}" > "$scratch/providers"
providers=()
for key in "${keys[@]}"; do
    providers+=("$key=fixture-value-$key")
done
env -i PATH="$scratch/bin:$PATH" HOME="$scratch" SYSKNIFE_VM_SSH_KEY="$scratch/vm-key" \
    SYSKNIFE_LLM_MODEL=$'reader\x27s model\nsecond line' SYSKNIFE_TEST_MODEL='' "${providers[@]}" \
    bash "$repo_root/tests/e2e/atomic-vm.sh" test-exec 1 'two words' ''
[[ -f "$scratch/story-ran" ]]

printf 'VM environment secrets are stdin-only across %d harnesses.\n' "${#harnesses[@]}"
