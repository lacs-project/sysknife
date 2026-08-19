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

normalise_mode() {
    local mode="$1"
    case "$mode" in
        [0-7][0-7][0-7] | [0-7][0-7][0-7][0-7]) ;;
        *)
            printf 'FAIL: invalid directory mode %s\n' "$mode" >&2
            return 1
            ;;
    esac
    printf '%04o' "$((8#$mode))"
}

tmpfiles_mode() {
    local path="$1"
    awk -v wanted="$path" '$1 == "d" && $2 == wanted { print $3 }' "$tmpfiles"
}

unit_mode() {
    local file="$1"
    local key="$2"
    awk -F= -v wanted="$key" '
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            section = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", section)
            next
        }
        section == "[Service]" {
            name = $1
            value = $2
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (name == wanted) print value
        }
    ' "$file"
}

runtime_mode="$(tmpfiles_mode /run/sysknife)"
state_mode="$(tmpfiles_mode /var/lib/sysknife)"

if [ -z "$runtime_mode" ] || [ -z "$state_mode" ]; then
    printf 'FAIL: could not derive both directory modes from %s\n' "$tmpfiles" >&2
    exit 1
fi

runtime_mode="$(normalise_mode "$runtime_mode")"
state_mode="$(normalise_mode "$state_mode")"

check_modes() {
    local label="$1"
    local file="$2"
    local runtime_actual state_actual
    runtime_actual="$(unit_mode "$file" RuntimeDirectoryMode)"
    state_actual="$(unit_mode "$file" StateDirectoryMode)"

    if [ -z "$runtime_actual" ] || [ -z "$state_actual" ]; then
        printf 'FAIL: %s does not declare both systemd directory modes in [Service]\n' "$label" >&2
        exit 1
    fi

    runtime_actual="$(normalise_mode "$runtime_actual")"
    state_actual="$(normalise_mode "$state_actual")"

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

verify_systemd_unit() {
    command -v systemd-analyze >/dev/null 2>&1 || return 0

    local verify_dir verify_unit verify_log
    verify_dir="$(mktemp -d)"
    verify_unit="$verify_dir/sysknife-daemon.service"
    verify_log="$verify_dir/systemd-analyze.log"

    # Keep verification independent of whether the development host has the
    # packaged daemon installed at /usr/local/bin yet.
    sed 's#^ExecStart=.*#ExecStart=/bin/true#' "$unit" > "$verify_unit"

    if ! systemd-analyze verify "$verify_unit" >"$verify_log" 2>&1; then
        printf 'FAIL: systemd-analyze rejected packaging/sysknife-daemon.service:\n' >&2
        cat "$verify_log" >&2
        rm -rf "$verify_dir"
        exit 1
    fi
    if [ -s "$verify_log" ]; then
        printf 'FAIL: systemd-analyze reported problems in packaging/sysknife-daemon.service:\n' >&2
        cat "$verify_log" >&2
        rm -rf "$verify_dir"
        exit 1
    fi
    rm -rf "$verify_dir"
}

check_modes 'packaging/sysknife-daemon.service' "$unit"
check_modes 'tests/e2e/ubuntu-provision.sh' "$ubuntu_provision"
verify_systemd_unit

printf 'systemd directory modes match tmpfiles: runtime %s, state %s.\n' \
    "$runtime_mode" "$state_mode"
