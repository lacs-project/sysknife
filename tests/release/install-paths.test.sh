#!/usr/bin/env bash
#
# install-paths.test.sh — the install must know, before it writes anything,
# every directory it is going to write into; and a path under a read-only
# prefix must be redirected on hosts where that prefix is read-only.
#
# `make install` on Fedora Atomic wrote the daemon binary, the systemd unit,
# the polkit rules and twelve sudo grants, then hit $(HELPERS) at
# /usr/lib/sysknife, discovered /usr was read-only, and stopped. That left
# live grants naming helper scripts that did not exist. The rpm-ostree branch
# in tests/e2e/provision.sh redirects four path variables and was written when
# there were two helpers and no $(HELPERS) variable; it has not changed since
# f1d9806 while the helper count went to twelve. See issue #301.
#
# Two checks, both derived rather than restated:
#
#   1. $(INSTALL_DIRS), which the preflight iterates, must cover every $(VAR)
#      the daemon-install recipe actually writes into. A preflight that has
#      fallen behind the recipe is worse than none, because it reports a clean
#      bill for a path it never looked at.
#   2. Every path variable whose default sits under a prefix that rpm-ostree
#      mounts read-only must be redirected by that branch, or be listed here
#      as a known gap with the issue that tracks it.
#
# Host-side only: reads the Makefile and one shell script. No make, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
makefile="$repo_root/Makefile"
provision="$repo_root/tests/e2e/provision.sh"
for f in "$makefile" "$provision"; do
    [ -f "$f" ] || { printf 'missing file: %s\n' "$f" >&2; exit 1; }
done

fail_count=0
note() { printf 'install-paths: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

# ── 1. INSTALL_DIRS must cover what daemon-install writes into ───────────────

# The recipe runs from `daemon-install:` to the next line that starts a new
# target or a comment block at column 0.
recipe="$(awk '
    /^daemon-install:/ { inside = 1; next }
    inside && /^[^\t#]/ && NF { exit }
    inside { print }
' "$makefile")"
[ -n "$recipe" ] || { printf 'could not extract the daemon-install recipe\n' >&2; exit 1; }

# Variables the recipe writes into: the $(VAR) that appear as a destination.
recipe_vars="$(printf '%s\n' "$recipe" \
    | grep -oE '\$\([A-Z_]+\)' | tr -d '$()' | sort -u)"
[ -n "$recipe_vars" ] || { printf 'derived no variables from the recipe\n' >&2; exit 1; }

declared="$(sed -nE 's/^INSTALL_DIRS[[:space:]]*=[[:space:]]*(.*)$/\1/p' "$makefile")"
# The assignment is line-continued, so pull the whole logical line.
declared="$(awk '/^INSTALL_DIRS[[:space:]]*=/{ found=1 } found { print; if ($0 !~ /\\$/) exit }' "$makefile" \
    | grep -oE '\$\([A-Z_]+\)' | tr -d '$()' | sort -u)"
[ -n "$declared" ] || { printf 'Makefile declares no INSTALL_DIRS\n' >&2; exit 1; }

missing="$(comm -23 <(printf '%s\n' "$recipe_vars") <(printf '%s\n' "$declared") || true)"
for v in $missing; do
    note "daemon-install writes into \$($v) but INSTALL_DIRS omits it, so the preflight never checks it"
done

# ── 2. read-only prefixes must be redirected on rpm-ostree ───────────────────

# rpm-ostree mounts /usr read-only. /usr/local is a symlink to /var/usrlocal
# and stays writable, so it does not count.
readonly_on_ostree() {
    case "$1" in
        /usr/local/*) return 1 ;;
        /usr/*) return 0 ;;
        *) return 1 ;;
    esac
}

# Known gaps: variable name, then the issue that tracks it. Keep this empty.
declare -A known_gap=(
    [HELPERS]="#301"
)

# The rpm-ostree branch's overrides, read from the script rather than restated.
overrides="$(awk '
    /rpm-ostree status --booted/ { inside = 1 }
    inside && /^else/ { exit }
    inside { print }
' "$provision" | grep -oE '^[[:space:]]+[A-Z_]+=' | tr -d ' =' | sort -u)"
[ -n "$overrides" ] || { printf 'derived no overrides from the rpm-ostree branch\n' >&2; exit 1; }

checked=0
for v in $declared; do
    default="$(sed -nE "s/^${v}[[:space:]]*\\?=[[:space:]]*(.*)$/\\1/p" "$makefile" | head -1)"
    # Resolve one level of $(PREFIX), the only indirection in use.
    prefix_default="$(sed -nE 's/^PREFIX[[:space:]]*\?=[[:space:]]*(.*)$/\1/p' "$makefile" | head -1)"
    default="${default//\$(PREFIX)/$prefix_default}"
    [ -n "$default" ] || continue
    checked=$((checked + 1))
    readonly_on_ostree "$default" || continue
    printf '%s\n' "$overrides" | grep -qx "$v" && continue
    if [ -n "${known_gap[$v]:-}" ]; then
        printf 'install-paths: KNOWN GAP %s defaults to %s and is not redirected on rpm-ostree (%s)\n' \
            "$v" "$default" "${known_gap[$v]}"
        continue
    fi
    note "$v defaults to $default, which rpm-ostree mounts read-only, and the ostree branch does not redirect it"
done
[ "$checked" -gt 0 ] || { printf 'resolved no variable defaults; the rule checked nothing\n' >&2; exit 1; }

if [ "$fail_count" -ne 0 ]; then
    printf '\ninstall-paths: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'install-paths: INSTALL_DIRS covers all %s recipe destinations; %s defaults checked against the ostree overrides\n' \
    "$(printf '%s\n' "$recipe_vars" | grep -c .)" "$checked"
