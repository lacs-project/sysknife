#!/usr/bin/env bash
#
# check_dco.sh — every commit in BASE..HEAD must carry a Signed-off-by trailer
# from its author.
#
# The trailer is how a contributor certifies the Developer Certificate of
# Origin (https://developercertificate.org/): they wrote the change, or have
# the right to submit it under the project's licence. `git commit -s` adds it,
# and CONTRIBUTING.md explains how to sign off commits already pushed.
#
# Usage: scripts/check_dco.sh BASE HEAD
#
# Only a trailer counts, as git parses one: a Signed-off-by in the middle of a
# sentence or above a later paragraph does not. The trailer's address must
# match the commit author's, ignoring case; the name may differ. Merge commits
# are skipped, because the "Update branch" button makes them and they add no
# authorship of their own. A range with nothing to check is refused, never
# passed, so a shallow clone or a wrong ref cannot report green.
#
# The `dco` job in .github/workflows/ci.yml runs this on every pull request;
# tests/release/dco.test.sh pins the behaviour.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    printf 'usage: %s BASE HEAD\n' "${0##*/}" >&2
    exit 2
fi
base="$1"
head="$2"

for ref in "$base" "$head"; do
    if ! git rev-parse --verify --quiet "$ref^{commit}" >/dev/null; then
        printf 'dco: cannot resolve %s to a commit; nothing was checked\n' "$ref" >&2
        exit 1
    fi
done
range="$(git rev-parse --short "$base")..$(git rev-parse --short "$head")"

# Dependabot authors commits as its noreply address and signs them off as
# support@github.com. Accept exactly that pair, and neither address for anyone
# else.
declare -A bot_signoff=(
    ['49699333+dependabot[bot]@users.noreply.github.com']='support@github.com'
)

if ! commits="$(git rev-list --no-merges --reverse "$base..$head")"; then
    printf 'dco: git rev-list %s failed; nothing was checked\n' "$range" >&2
    exit 1
fi
if [ -z "$commits" ]; then
    printf 'dco: %s holds no commits apart from merges; nothing was checked\n' "$range" >&2
    exit 1
fi

checked=0
unsigned=0
while IFS= read -r commit; do
    checked=$((checked + 1))
    author="$(git log -1 --format='%ae' "$commit")"
    author="${author,,}"
    want="${bot_signoff[$author]:-$author}"
    trailers="$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly,unfold,separator=%x0A)' "$commit")"

    signed=no
    others=()
    while IFS= read -r value; do
        [ -n "$value" ] || continue
        email="$(sed -n 's/.*<\([^>]*\)>.*/\1/p' <<<"$value")"
        if [ "${email,,}" = "$want" ]; then
            signed=yes
        else
            others+=("$value")
        fi
    done <<<"$trailers"
    [ "$signed" = yes ] && continue

    unsigned=$((unsigned + 1))
    if [ "${#others[@]}" -eq 0 ]; then
        reason="no Signed-off-by trailer from <$want>"
    else
        reason="Signed-off-by names $(printf '%s; ' "${others[@]}")not the author <$want>"
    fi
    printf 'dco: %s %s\n     %s\n' \
        "$(git rev-parse --short "$commit")" "$(git log -1 --format='%s' "$commit")" "$reason" >&2
done <<<"$commits"

if [ "$unsigned" -ne 0 ]; then
    printf '\ndco: %s of %s commits in %s lack a sign-off from their author.\n' "$unsigned" "$checked" "$range" >&2
    # Fetching by URL works whatever the contributor named their remotes.
    printf 'Add one to each from your branch, then update the pull request:\n' >&2
    printf '    git fetch https://github.com/lacs-project/sysknife.git main\n' >&2
    printf '    git rebase --signoff FETCH_HEAD\n    git push --force-with-lease\n' >&2
    exit 1
fi

if [ "$checked" -eq 1 ]; then
    printf 'dco: 1 commit in %s carries its author'\''s sign-off\n' "$range"
else
    printf 'dco: %s commits in %s each carry their author'\''s sign-off\n' "$checked" "$range"
fi
