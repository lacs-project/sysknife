#!/usr/bin/env bash
# systemd-directory-modes.test.sh — systemd must preserve the private modes
# declared by tmpfiles when it recreates SysKnife runtime/state directories.
#
# Host-side only: no VM, no daemon, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpfiles="$repo_root/packaging/sysknife-tmpfiles.conf"
unit="$repo_root/packaging/sysknife-daemon.service"
ubuntu_provision="$repo_root/tests/e2e/ubuntu-provision.sh"

for file in "$tmpfiles" "$unit" "$ubuntu_provision"; do
    [ -f "$file" ] || { printf 'missing %s\n' "$file" >&2; exit 1; }
done

tmpfiles_mode() {
    local path="$1"
    awk -v wanted="$path" '$1 == "d" && $2 == wanted { print $3 }' "$tmpfiles"
}

unit_mode() {
    local file="$1"
    local key="$2"
    awk -F= -v wanted="$key" '$1 == wanted { print $2 }' "$file"
}

runtime_mode="$(tmpfiles_mode /run/sysknife)"
state_mode="$(tmpfiles_mode /var/lib/sysknife)"

if [ -z "$runtime_mode" ] || [ -z "$state_mode" ]; then
    printf 'FAIL: could not derive both directory modes from %s\n' "$tmpfiles" >&2
    exit 1
fi

check_modes() {
    local label="$1"
    local file="$2"
    local runtime_actual state_actual
    runtime_actual="$(unit_mode "$file" RuntimeDirectoryMode)"
    state_actual="$(unit_mode "$file" StateDirectoryMode)"

    if [ -z "$runtime_actual" ] || [ -z "$state_actual" ]; then
        printf 'FAIL: %s does not declare both systemd directory modes\n' "$label" >&2
        exit 1
    fi
    if [ "$runtime_actual" != "$runtime_mode" ]; then
        printf 'FAIL: %s RuntimeDirectoryMode=%s, tmpfiles requires %s\n' \
            "$label" "$runtime_actual" "$runtime_mode" >&2
        exit 1
    fi
    if [ "$state_actual" != "$state_mode" ]; then
        printf 'FAIL: %s StateDirectoryMode=%s, tmpfiles requires %s\n' \
            "$label" "$state_actual" "$state_mode" >&2
        exit 1
    fi
}

check_modes 'packaging/sysknife-daemon.service' "$unit"
check_modes 'tests/e2e/ubuntu-provision.sh' "$ubuntu_provision"

printf 'systemd directory modes match tmpfiles: runtime %s, state %s.\n' \
    "$runtime_mode" "$state_mode"
