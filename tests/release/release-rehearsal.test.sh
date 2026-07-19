#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rehearsal="${repo_root}/scripts/release_rehearsal.sh"

if [[ ! -x "$rehearsal" ]]; then
    printf 'FAIL: release rehearsal is missing or not executable: %s\n' "$rehearsal" >&2
    exit 1
fi

help="$($rehearsal --help)"
grep -Fq -- '--check' <<<"$help"
grep -Fq -- '--full' <<<"$help"
grep -Fq 'never publishes' <<<"$help"

if "$rehearsal" --publish >/tmp/sysknife-rehearsal-publish.out 2>&1; then
    printf 'FAIL: rehearsal accepted a publishing mode\n' >&2
    exit 1
fi
grep -Fq 'never publishes' /tmp/sysknife-rehearsal-publish.out

check_output="$($rehearsal --check)"
grep -Eq 'sysknife-v[0-9]+\.[0-9]+\.[0-9]+-linux-(x86_64|aarch64)' <<<"$check_output"
grep -Eq 'sysknife-daemon-v[0-9]+\.[0-9]+\.[0-9]+-linux-(x86_64|aarch64)' <<<"$check_output"
grep -Fq 'Rehearsal preflight passed' <<<"$check_output"

for crate in sysknife-proto sysknife-core sysknife-types sysknife-brain \
             sysknife-daemon; do
    grep -Fq "patch.crates-io.${crate}.path" "$rehearsal"
done
grep -Fq 'npm pack ./packages/setup' "$rehearsal"

if grep -Eiq '(^|[[:space:]])(cargo|npm)[[:space:]]+publish|gh[[:space:]]+release[[:space:]]+create' "$rehearsal"; then
    printf 'FAIL: rehearsal contains a publication command\n' >&2
    exit 1
fi

printf 'Release rehearsal contract passed.\n'
