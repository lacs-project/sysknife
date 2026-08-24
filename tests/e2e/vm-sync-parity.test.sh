#!/usr/bin/env bash
#
# vm-sync-parity.test.sh — no harness may copy another harness's VM disk into
# its own guest.
#
# tests/e2e/ubuntu-vm.sh has excluded both tests/e2e/vm and
# tests/e2e/ubuntu-vm from its repo-to-guest rsync since it was written.
# tests/e2e/atomic-vm.sh excluded only its own. So a worktree that had run the
# Ubuntu harness carried three qcow2 overlays totalling 24G, and provisioning
# the Fedora guest pushed them across the wire until its 38G disk filled:
#
#   rsync: [receiver] write failed on ".../tests/e2e/ubuntu-vm/noble/overlay.qcow2":
#   No space left on device (28)
#
# The overlays are gitignored, so nothing in review or CI ever saw them, and a
# clean checkout provisions fine. The failure needs a contributor who ran both
# harnesses, which is the contributor most likely to be trusted.
#
# Two design rules, following provider-parity.test.sh:
#
#   * The excluded directories are derived from .gitignore, never restated
#     here, so a third harness with a gitignored VM directory joins the rule
#     on its own.
#   * Every repo-to-guest rsync is checked, not one per script. A script with
#     a correct `sync` and a stale `provision` is the bug this test exists for.
#
# Host-side only: greps scripts, needs no VM, no daemon and no network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gitignore="$repo_root/.gitignore"
[ -f "$gitignore" ] || { printf 'missing file: %s\n' "$gitignore" >&2; exit 1; }

# Scripts that rsync the worktree into a guest.
harnesses=(
    "tests/e2e/ubuntu-vm.sh"
    "tests/e2e/atomic-vm.sh"
)
for rel in "${harnesses[@]}"; do
    [ -f "$repo_root/$rel" ] || { printf 'missing file: %s\n' "$rel" >&2; exit 1; }
done

# Derive the directories that hold VM state: gitignored directory entries under
# tests/e2e/, reduced to their first component. A trailing slash is what marks
# an entry as a directory, which is what separates tests/e2e/vm/ from the log
# globs beside it.
mapfile -t vm_dirs < <(
    grep -E '^tests/e2e/[^/]+/([^/*]+/)*$' "$gitignore" \
        | sed -E 's#^(tests/e2e/[^/]+)/.*#\1#' \
        | sort -u
)
if [ "${#vm_dirs[@]}" -eq 0 ]; then
    printf 'derived no VM directories from .gitignore; the rule cannot be checked\n' >&2
    exit 1
fi

failures=0
for rel in "${harnesses[@]}"; do
    script="$repo_root/$rel"

    # Every rsync that targets the guest's repo path. Counting them is the
    # point: a script whose `sync` is right and whose `provision` is stale
    # passes any check that only looks at the first one.
    rsync_lines="$(grep -n 'rsync -az' "$script" || true)"
    rsync_count="$(printf '%s' "$rsync_lines" | grep -c . || true)"
    if [ "$rsync_count" -eq 0 ]; then
        printf '%s: no `rsync -az` invocation found; this test no longer covers it\n' "$rel" >&2
        failures=$((failures + 1))
        continue
    fi

    for dir in "${vm_dirs[@]}"; do
        # The exclude may be written literally or reached through a variable
        # holding that default, so accept either spelling.
        if grep -q -- "--exclude=$dir" "$script" \
            || grep -qE "(VM_DIR|vm_dir)=\"?\\\$\{[A-Z_]+:-$dir\}" "$script"; then
            continue
        fi
        printf '%s does not exclude %s from its guest sync (%s rsync invocation(s))\n' \
            "$rel" "$dir" "$rsync_count" >&2
        failures=$((failures + 1))
    done

    # A single shared exclude list is what keeps the invocations from drifting.
    # Not mandatory, but if the excludes are inline they must be inline in all
    # of them, so check each invocation carries the same exclude count.
    counts="$(grep -o 'rsync -az[^\\]*' "$script" | grep -c 'exclude' || true)"
    if [ "$counts" -ne 0 ] && [ "$counts" -ne "$rsync_count" ]; then
        printf '%s: %s of %s rsync invocations carry inline excludes; the rest may be stale\n' \
            "$rel" "$counts" "$rsync_count" >&2
        failures=$((failures + 1))
    fi
done

if [ "$failures" -ne 0 ]; then
    printf '\nvm-sync-parity: %s failure(s)\n' "$failures" >&2
    exit 1
fi

printf 'vm-sync-parity: %s harness(es) exclude all %s VM directory(ies): %s\n' \
    "${#harnesses[@]}" "${#vm_dirs[@]}" "${vm_dirs[*]}"
