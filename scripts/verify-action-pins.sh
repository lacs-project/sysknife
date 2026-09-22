#!/usr/bin/env bash
# Adapted from vladimirrott/maintainer-agent/scripts/verify-action-pins.sh.
# Upstream revision: 9d1dbd61d0ec3ef102fe2ed9dcd215d874388b1e
#
# MIT License
# Copyright (c) 2026 Vladimir Rotariu
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Preserve SHA pins; verify the tag named by each comment, peeling tag objects.
# `# stable (branch)` is a deliberate moving reference, reported without a
# comparison to today's branch head. Use exact release tags for other comments.
# Requires authenticated gh, Python 3 and PyYAML (provided by yamllint).
set -uo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${1:-$script_dir/..}"
rows="$(mktemp)" || exit 1
trap 'rm -f "$rows"' EXIT
python3 "$script_dir/action-pin-comments.py" "$root" > "$rows" || exit 1
fail=0
count=0
declare -A resolved

deref() {  # $1 repository, $2 tag -> commit (including nested annotated tags)
    local obj type sha depth=0
    obj="$(gh api "repos/$1/git/ref/tags/$2" --jq '.object.type + " " + .object.sha')" || return 1
    while :; do
        read -r type sha <<< "$obj"
        [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
        case "$type" in
            commit) printf '%s' "$sha"; return 0 ;;
            tag)
                depth=$((depth + 1))
                ((depth <= 16)) || return 1
                obj="$(gh api "repos/$1/git/tags/$sha" --jq '.object.type + " " + .object.sha')" || return 1
                ;;
            *) return 1 ;;
        esac
    done
}

while IFS=$'\t' read -r action sha claim location; do
    count=$((count + 1))
    if [[ "$claim" == *' (branch)' ]]; then
        printf '  BRANCH %-46s tracks %s by design (%s)\n' "$action" "${claim% (branch)}" "$location"
        continue
    fi
    # Action subpaths (e.g. codeql-action/analyze) share the repository's tags.
    owner="${action%%/*}"
    rest="${action#*/}"
    repo="$owner/${rest%%/*}"
    key="$repo@$claim"
    if [[ -z "${resolved[$key]+present}" ]]; then
        if real="$(deref "$repo" "$claim")"; then
            resolved[$key]="$real"
        else
            resolved[$key]='ERROR'
        fi
    fi
    real="${resolved[$key]}"
    if [[ "$real" == ERROR ]]; then
        printf '  ERROR %-46s cannot resolve tag %s; check ref, authentication and API availability (%s)\n' "$action" "$claim" "$location"
        fail=1
    elif [[ "$real" == "$sha" ]]; then
        printf '  OK %-46s %s is %s (%s)\n' "$action" "${sha:0:8}" "$claim" "$location"
    else
        printf '  FAIL %-46s pinned %s but %s is %s (%s)\n' "$action" "${sha:0:8}" "$claim" "${real:0:8}" "$location"
        fail=1
    fi
done < "$rows"
((count > 0)) || { echo 'verify-action-pins: no pinned actions' >&2; exit 1; }
printf 'verify-action-pins: checked %d pins\n' "$count"
exit "$fail"
