#!/usr/bin/env bash
# Single-quoted test programs are expanded by the child bash, not this shell.
# shellcheck disable=SC2016
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script="$repo_root/tests/e2e/ubuntu-vm.sh"

bash -n "$script"

require_text() {
    local pattern="$1"
    if ! grep -Fq -- "$pattern" "$script"; then
        printf 'missing Ubuntu VM bootstrap contract: %s\n' "$pattern" >&2
        exit 1
    fi
}

require_text 'set -Eeuo pipefail'
require_text 'cloud-init-failed'
require_text 'Acquire::Retries=3'
require_text 'DPkg::Lock::Timeout=120'
require_text 'die "cloud-init bootstrap failed"'
require_text 'die "cloud-init did not complete within ${max_wait}s"'
require_text 'cloud-init completed without all required tools'

printf 'Ubuntu VM bootstrap contract passed.\n'

tmp="$(mktemp -d)"
vm_pid=""
cleanup() {
    if [ -n "$vm_pid" ]; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
mkdir -p "$tmp/bin" "$tmp/vm"
export VM_SCRIPT="$script" UBUNTU_VM_DIR="$tmp/vm" UBUNTU_RELEASE=noble
export SSH_LOG="$tmp/ssh.log" SHADOW_RECORD='ubuntu:SECRET_FIELD_MUST_NOT_LEAK:20656:1:90:7:::'
export SSH_MODE=aging
cat > "$tmp/bin/ssh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SSH_LOG"
case "$SSH_MODE" in
    expired)
        printf '%s\n' 'WARNING: Your password has expired.' 'Password change required but no TTY available.' >&2
        exit 255 ;;
    denied) echo 'Permission denied (publickey).' >&2; exit 255 ;;
    success) exit 0 ;;
esac
case "$*" in
    *'sudo getent shadow'*)
        [ "$SSH_MODE" != lookup-failed ] || exit 1
        printf '%s\n' "$SHADOW_RECORD" ;;
    *'sudo chage '*) [ "$SSH_MODE" != reset-failed ] ;;
    *'sudo systemctl poweroff'*) exit 0 ;;
    *) echo 'unexpected SSH command' >&2; exit 2 ;;
esac
STUB
printf '#!/usr/bin/env bash\nexit 1\n' > "$tmp/bin/nc"
chmod +x "$tmp/bin/ssh" "$tmp/bin/nc"
export PATH="$tmp/bin:$PATH"

failures=0
run_case() {
    local name="$1" code="$2"
    : > "$SSH_LOG"
    if bash -c "set -euo pipefail; $code" > "$tmp/output" 2>&1; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s\n' "$name" >&2
        cat "$tmp/output" >&2
        failures=$((failures + 1))
    fi
    if grep -q SECRET_FIELD_MUST_NOT_LEAK "$tmp/output"; then
        printf 'FAIL %s: shadow password field leaked\n' "$name" >&2
        failures=$((failures + 1))
    fi
}

run_case source_without_dispatch '
    set -- sentinel remaining
    source "$VM_SCRIPT"
    [ "$#" -eq 2 ] && [ "$1" = sentinel ]
'
run_case expired_password_diagnostic '
    source "$VM_SCRIPT"
    export SSH_MODE=expired
    if output=$(wait_for_ssh_auth 2223 0 2>&1); then exit 1; fi
    [[ "$output" == *"password aging"* && "$output" == *ubuntu* ]]
    for command in destroy download install; do [[ "$output" == *"$command"* ]]; done
'
run_case unrelated_auth_failure_keeps_timeout '
    source "$VM_SCRIPT"
    export SSH_MODE=denied
    if output=$(wait_for_ssh_auth 2223 0 2>&1); then exit 1; fi
    [[ "$output" == *"SSH key auth did not succeed on port 2223 within 0s."* ]]
    [[ "$output" != *"password aging"* ]]
'
run_case successful_auth '
    source "$VM_SCRIPT"
    export SSH_MODE=success
    wait_for_ssh_auth 2223 0
'
run_case finite_max_is_reset '
    source "$VM_SCRIPT"
    output=$(reset_login_password_aging 2>&1)
    printf "%s\n" "$output"
    [[ "$output" == *WARNING* && "$output" == *last_change=20656* && "$output" == *max_days=90* && "$output" == *account_expiry=unset* ]]
    grep -Fq "sudo chage -d $(date -u +%F) -m 0 -M 99999 -I -1 -E -1 ubuntu" "$SSH_LOG"
'
run_case safe_aging_is_unchanged '
    source "$VM_SCRIPT"
    export SHADOW_RECORD="ubuntu:SECRET_FIELD_MUST_NOT_LEAK:20656:0:99999:7:::"
    reset_login_password_aging
    ! grep -q "sudo chage" "$SSH_LOG"
'
run_case forced_change_is_reset '
    source "$VM_SCRIPT"
    export SHADOW_RECORD="ubuntu:SECRET_FIELD_MUST_NOT_LEAK:0:0:99999:7:::"
    reset_login_password_aging
    grep -q "sudo chage" "$SSH_LOG"
'
run_case account_expiry_is_reset '
    source "$VM_SCRIPT"
    export SHADOW_RECORD="ubuntu:SECRET_FIELD_MUST_NOT_LEAK:20656:0:99999:7::21000:"
    reset_login_password_aging
    grep -q "sudo chage" "$SSH_LOG"
'
run_case disabled_aging_is_unchanged '
    source "$VM_SCRIPT"
    export SHADOW_RECORD="ubuntu:SECRET_FIELD_MUST_NOT_LEAK::0::7::-1:"
    reset_login_password_aging
    ! grep -q "sudo chage" "$SSH_LOG"
'
sleep 120 &
vm_pid=$!
printf '%s\n' "$vm_pid" > "$tmp/vm/vm.pid"
run_case reset_precedes_poweroff '
    source "$VM_SCRIPT"
    cmd_stop
    reset=$(grep -n "sudo chage" "$SSH_LOG" | cut -d: -f1)
    poweroff=$(grep -n "sudo systemctl poweroff" "$SSH_LOG" | cut -d: -f1)
    [ "$reset" -lt "$poweroff" ]
'
run_case lookup_failure_prevents_poweroff '
    source "$VM_SCRIPT"
    export SSH_MODE=lookup-failed
    if (cmd_stop); then exit 1; fi
    ! grep -q "sudo systemctl poweroff" "$SSH_LOG"
'
run_case reset_failure_prevents_poweroff '
    source "$VM_SCRIPT"
    export SSH_MODE=reset-failed
    if (cmd_stop); then exit 1; fi
    ! grep -q "sudo systemctl poweroff" "$SSH_LOG"
'
run_case malformed_aging_prevents_poweroff '
    source "$VM_SCRIPT"
    export SHADOW_RECORD="ubuntu:SECRET_FIELD_MUST_NOT_LEAK:20656:0:broken:7:::"
    if (cmd_stop); then exit 1; fi
    ! grep -q "sudo systemctl poweroff" "$SSH_LOG"
'
run_case custom_login_user '
    export UBUNTU_VM_USER=testoperator
    source "$VM_SCRIPT"
    reset_login_password_aging
    grep -Fq "sudo getent shadow testoperator" "$SSH_LOG"
    grep -Fq -- "-E -1 testoperator" "$SSH_LOG"
'
[ "$failures" -eq 0 ] || exit 1
printf 'Ubuntu VM password-aging behaviour passed.\n'
