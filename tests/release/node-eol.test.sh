#!/usr/bin/env bash
# node-eol.test.sh — no workflow may pin a Node major that upstream has retired.
#
# A GitHub Actions runner executes `npm ci` with the workflow token in its
# environment. Running that on a Node release that no longer receives security
# fixes puts an unpatched runtime on the trusted side of the build, and it also
# blocks dependency updates: jsdom 30 needs Node 22.22 or newer, so a CI pinned
# to 20 cannot take it.
#
# The end-of-life dates below are copied from the Node.js release schedule:
#   https://github.com/nodejs/Release/blob/main/schedule.json
# They are compared against today, so this test starts failing on its own when
# the pinned major ages out, rather than waiting for someone to notice.
#
# Host-side only: no network, no VM.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflows="$repo_root/.github/workflows"

[ -d "$workflows" ] || { printf 'missing %s\n' "$workflows" >&2; exit 1; }

# major:end-of-life
NODE_SCHEDULE="18:2025-04-30 20:2026-04-30 22:2027-04-30 24:2028-04-30 26:2029-04-30"

eol_of() {
    local major="$1" entry
    for entry in $NODE_SCHEDULE; do
        if [ "${entry%%:*}" = "$major" ]; then
            printf '%s' "${entry#*:}"
            return 0
        fi
    done
    return 1
}

today="$(date -u +%Y-%m-%d)"
failures=0
pins=0

report() {
    printf 'FAIL  %s\n' "$1" >&2
    failures=$((failures + 1))
}

while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    line="${rest%%:*}"
    # `node-version: "20"`, `node-version: '20'` and `node-version: 20` all
    # reach here; keep only the leading integer.
    version="$(printf '%s' "${rest#*:}" | tr -d "\"' " | sed 's/^node-version://')"
    major="${version%%.*}"
    pins=$((pins + 1))

    case "$major" in
        '' | *[!0-9]*)
            report "$(basename "$file"):$line pins an unreadable Node version '$version'"
            continue
            ;;
    esac

    if ! eol="$(eol_of "$major")"; then
        report "$(basename "$file"):$line pins Node $major, which is absent from the schedule table in this test; add it from nodejs/Release"
        continue
    fi

    if [ "$eol" \< "$today" ]; then
        report "$(basename "$file"):$line pins Node $major, end-of-life since $eol"
    fi
done < <(grep -rn '^[[:space:]]*node-version:' "$workflows" || true)

# The extraction above recognises the block-style `node-version:` key only.
# Two other spellings pin a Node major without matching it, and neither would
# trip the "found no pin" fallback while other files still carry real pins:
# `node-version-file:` (reads a possibly stale .nvmrc) and a flow-style inline
# mapping. Neither is used here today. Refuse them rather than let a future
# workflow pin an end-of-life release through a form this test cannot read.
while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    report "$(basename "$file"):${rest%%:*} pins Node through a form this check cannot read; use a literal \`node-version:\` line"
done < <(grep -rnE '^[[:space:]]*node-version-file:|\{[^}]*node-version[[:space:]]*:' "$workflows" || true)

if [ "$pins" -eq 0 ]; then
    printf 'no node-version pin found under .github/workflows; the extraction is broken, not the workflows\n' >&2
    exit 1
fi

if [ "$failures" -ne 0 ]; then
    printf '\n%d workflow Node pin failure(s).\n' "$failures" >&2
    exit 1
fi

printf '%d workflow Node pins, all on a supported release as of %s.\n' "$pins" "$today"
