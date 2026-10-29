#!/usr/bin/env bash
#
# destdir-install.test.sh — `make install DESTDIR=<stage>` must lay every file
# out under <stage> and leave the running system alone.
#
# A packager builds a staged tree and installs it later, so every destination
# has to carry the $(DESTDIR) prefix, and the steps that activate an install on
# the running host (systemd-sysusers, systemd-tmpfiles, systemctl) must not run.
# Without DESTDIR the install has to keep doing both. OpenSSF's
# installation_standard_variables criterion asks for exactly this.
#
# Runs the real Makefile against a copy of packaging/ and two placeholder
# binaries. Every install directory is redirected into a scratch tree, and the
# activation commands and cargo are stubs that log their calls, so a recipe line
# that forgets $(DESTDIR) lands in the scratch tree instead of on this host.
# No root, no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

fail_count=0
note() { printf 'destdir-install: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

src="$work/src"
stubs="$work/stubs"
log="$work/calls.log"
mkdir -p "$src/target/release" "$stubs"
cp "$repo_root/Makefile" "$src/"
cp -R "$repo_root/packaging" "$src/"
printf '#!/bin/sh\n' >"$src/target/release/sysknife"
printf '#!/bin/sh\n' >"$src/target/release/sysknife-daemon"

cat >"$stubs/stub" <<'STUB'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"$STUB_LOG"
STUB
chmod +x "$stubs/stub"
for cmd in cargo systemctl systemd-sysusers systemd-tmpfiles visudo; do
    ln -s stub "$stubs/$cmd"
done
export STUB_LOG="$log"

# Point every directory the install writes into at a scratch root. The list of
# variables comes from the Makefile's own INSTALL_DIRS, so a new install
# directory that this test does not redirect fails here instead of writing to
# the real host.
redirected=(BINDIR SYSUSERS TMPFILES SYSTEMD POLKIT SUDOERS HELPERS)
declared="$(awk '/^INSTALL_DIRS[[:space:]]*=/{ found=1 } found { print; if ($0 !~ /\\$/) exit }' \
    "$src/Makefile" | grep -oE '\$\([A-Z_]+\)' | tr -d '$()' | sort -u)"
[ -n "$declared" ] || { printf 'destdir-install: read no INSTALL_DIRS from the Makefile\n' >&2; exit 1; }
for v in $declared; do
    if ! printf '%s\n' "${redirected[@]}" | grep -qx "$v"; then
        printf 'destdir-install: INSTALL_DIRS names $(%s), which this test does not redirect; refusing to run\n' \
            "$v" >&2
        exit 1
    fi
done

paths_under() {
    local root="$1"
    printf 'BINDIR=%s SYSUSERS=%s TMPFILES=%s SYSTEMD=%s POLKIT=%s SUDOERS=%s HELPERS=%s' \
        "$root/usr/local/bin" "$root/usr/lib/sysusers.d" "$root/usr/lib/tmpfiles.d" \
        "$root/usr/lib/systemd/system" "$root/usr/share/polkit-1/rules.d" \
        "$root/etc/sudoers.d" "$root/usr/lib/sysknife"
}

run_make() {
    # shellcheck disable=SC2046  # paths_under emits VAR=value words on purpose
    PATH="$stubs:$PATH" make --no-print-directory -C "$src" "$@" $(paths_under "$sys")
}

sys="$work/sys"
stage="$work/stage"
mkdir -p "$sys" "$stage"

# The files a live install writes, read from a dry run of the recipe itself.
dry="$(run_make -n install)"
mapfile -t expected < <(printf '%s\n' "$dry" | awk '$1 == "install" && $2 ~ /^-D/ { print $NF }')
[ "${#expected[@]}" -gt 0 ] || { printf 'destdir-install: the dry run listed no install destinations\n' >&2; exit 1; }

# ── 1. A staged install writes only under DESTDIR and activates nothing ─────

# A read-only scratch root makes a preflight or install line that ignores
# DESTDIR fail. root ignores the mode bits, so that half only bites as non-root;
# the "nothing outside the stage" check below holds either way.
chmod 0555 "$sys"
: >"$log"
if ! out="$(run_make install DESTDIR="$stage" 2>&1)"; then
    note "make install DESTDIR=<stage> failed: $out"
fi
chmod 0755 "$sys"

for dest in "${expected[@]}"; do
    [ -f "$stage$dest" ] || note "staged install did not write ${dest#"$sys"} under DESTDIR"
done
outside="$(find "$sys" -mindepth 1 -not -type d)"
[ -z "$outside" ] || note "staged install wrote outside DESTDIR: ${outside//"$sys"/}"
if grep -E '^(systemctl|systemd-sysusers|systemd-tmpfiles) ' "$log" >/dev/null; then
    note "staged install touched the running system: $(grep -E '^(systemctl|systemd-sysusers|systemd-tmpfiles) ' "$log" | tr '\n' ';')"
fi
if [ -f "$stage$sys/etc/sudoers.d/sysknife" ]; then
    mode="$(stat -c '%a' "$stage$sys/etc/sudoers.d/sysknife")"
    [ "$mode" = 440 ] || note "staged sudoers fragment has mode $mode, want 440"
fi

# ── 2. A staged uninstall removes what the staged install wrote ─────────────

: >"$log"
if ! out="$(run_make uninstall DESTDIR="$stage" 2>&1)"; then
    note "make uninstall DESTDIR=<stage> failed: $out"
fi
left="$(find "$stage" -mindepth 1 -not -type d)"
[ -z "$left" ] || note "staged uninstall left files behind: ${left//"$stage$sys"/}"
if grep -E '^systemctl ' "$log" >/dev/null; then
    note "staged uninstall called systemctl: $(grep -E '^systemctl ' "$log" | tr '\n' ';')"
fi

# ── 3. Without DESTDIR the install still activates what it wrote ────────────

: >"$log"
if ! out="$(run_make install 2>&1)"; then
    note "make install without DESTDIR failed: $out"
fi
for dest in "${expected[@]}"; do
    [ -f "$dest" ] || note "live install did not write ${dest#"$sys"}"
done
for cmd in systemd-sysusers systemd-tmpfiles 'systemctl daemon-reload'; do
    grep -q "^$cmd" "$log" || note "live install no longer runs $cmd"
done

if [ "$fail_count" -ne 0 ]; then
    printf '\ndestdir-install: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'destdir-install: %s destinations staged under DESTDIR, none outside it, no activation; live install still activates\n' \
    "${#expected[@]}"
