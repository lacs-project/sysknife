#!/usr/bin/env bash
#
# dco.test.sh — scripts/check_dco.sh must fail a pull request with any commit
# that lacks its author's Signed-off-by, and must refuse to pass a range it
# could not read.
#
# The `dco` job in ci.yml runs the script over every pull request, and the
# branch ruleset requires that job, so the script decides whether a commit
# without a Developer Certificate of Origin sign-off can reach main. A check
# that reads only the tip commit, matches the words anywhere in the message,
# or passes an empty range would let one through while reporting green.
#
# Builds throwaway repositories with known commits. No network.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
check="$repo_root/scripts/check_dco.sh"
[ -f "$check" ] || { printf 'dco: %s is missing\n' "$check" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Keep the caller's git configuration (signing keys, hooks, templates) out of
# the fixtures.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME='Ada Author' GIT_AUTHOR_EMAIL='ada@example.org'
export GIT_COMMITTER_NAME='Ada Author' GIT_COMMITTER_EMAIL='ada@example.org'

fail_count=0
note() { printf 'dco: %s\n' "$1" >&2; fail_count=$((fail_count + 1)); }

# A fresh repository holding one commit on main, whose path is printed. Called
# as r="$(fixture)", so it runs in a subshell and keeps no counter of its own.
fixture() {
    local dir
    dir="$(mktemp -d "$work/repo.XXXXXX")"
    git init -q -b main "$dir"
    git -C "$dir" commit -q --allow-empty -m 'base'
    printf '%s\n' "$dir"
}

# commit DIR MESSAGE [ENV...]: an empty commit with MESSAGE, under extra env.
commit() {
    local dir="$1" message="$2"
    shift 2
    env "$@" git -C "$dir" commit -q --allow-empty -m "$message"
}

SOB='Signed-off-by: Ada Author <ada@example.org>'

# expect DIR BASE HEAD WANT_RC PATTERN LABEL: run the check, compare the exit
# status, and require PATTERN in its combined output.
expect() {
    local dir="$1" base="$2" head="$3" want="$4" pattern="$5" label="$6"
    local out rc=0
    out="$(cd "$dir" && bash "$check" "$base" "$head" 2>&1)" || rc=$?
    if [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then
        note "$label: expected a pass, got exit $rc: $out"
    elif [ "$want" != 0 ] && [ "$rc" -eq 0 ]; then
        note "$label: expected a failure, got exit 0: $out"
    elif ! grep -qE -- "$pattern" <<<"$out"; then
        note "$label: output lacks /$pattern/: $out"
    fi
}

# ── 1. A signed-off commit passes, and the report counts what it read ───────

r="$(fixture)"
commit "$r" "feat: one"$'\n\n'"$SOB"
expect "$r" main~1 main 0 '^dco: 1 commit ' 'one signed commit'

# ── 2. A commit with no sign-off fails, named by its short hash ─────────────

r="$(fixture)"
commit "$r" 'feat: unsigned'
sha="$(git -C "$r" rev-parse --short HEAD)"
expect "$r" main~1 main 1 "$sha" 'one unsigned commit'

# ── 3. Every commit is read, not only the tip ───────────────────────────────

r="$(fixture)"
commit "$r" 'feat: unsigned and older'
older="$(git -C "$r" rev-parse --short HEAD)"
commit "$r" "feat: signed tip"$'\n\n'"$SOB"
expect "$r" main~2 main 1 "$older" 'unsigned commit below a signed tip'

# ── 4. The sign-off must name the author ─────────────────────────────────────

r="$(fixture)"
commit "$r" $'feat: signed by someone else\n\nSigned-off-by: Bo Other <bo@example.org>'
expect "$r" main~1 main 1 'bo@example.org' 'sign-off from another address'

# The address compares without regard to case; mail systems do the same.
r="$(fixture)"
commit "$r" $'feat: case\n\nSigned-off-by: Ada Author <Ada@Example.ORG>'
expect "$r" main~1 main 0 '^dco: 1 commit ' 'sign-off differing only in case'

# ── 5. Only a trailer counts, not the words somewhere in the body ───────────

r="$(fixture)"
commit "$r" "feat: quoted"$'\n\n'"The old check wanted $SOB on its own line."
expect "$r" main~1 main 1 'no Signed-off-by' 'sign-off quoted mid-sentence'

r="$(fixture)"
commit "$r" "feat: early"$'\n\n'"$SOB"$'\n\nA later paragraph closes the message.'
expect "$r" main~1 main 1 'no Signed-off-by' 'sign-off above a later paragraph'

# ── 6. Merge commits are skipped; the commits they bring in are not ─────────

r="$(fixture)"
git -C "$r" checkout -q -b side
commit "$r" "feat: side"$'\n\n'"$SOB"
git -C "$r" checkout -q main
commit "$r" "feat: main"$'\n\n'"$SOB"
git -C "$r" merge -q --no-ff --no-edit -m 'Merge branch side' side
expect "$r" main~1 main 0 '^dco: 1 commit ' 'unsigned merge commit over signed work'

# ── 7. Dependabot signs off under a different address than it authors ──────

bot=(GIT_AUTHOR_NAME='dependabot[bot]'
     GIT_AUTHOR_EMAIL='49699333+dependabot[bot]@users.noreply.github.com')
r="$(fixture)"
commit "$r" $'chore(deps): bump x\n\nSigned-off-by: dependabot[bot] <support@github.com>' "${bot[@]}"
expect "$r" main~1 main 0 '^dco: 1 commit ' 'a Dependabot commit'

# The exception covers that one pairing, not any address for the bot.
r="$(fixture)"
commit "$r" $'chore(deps): bump x\n\nSigned-off-by: Bo Other <bo@example.org>' "${bot[@]}"
expect "$r" main~1 main 1 'bo@example.org' 'a Dependabot commit signed off by someone else'

# Nor does the support address sign off for anybody else.
r="$(fixture)"
commit "$r" $'feat: x\n\nSigned-off-by: dependabot[bot] <support@github.com>'
expect "$r" main~1 main 1 'support@github.com' 'the Dependabot sign-off on a human commit'

# ── 8. A range the check cannot read is refused, never passed ───────────────

r="$(fixture)"
expect "$r" main main 1 'nothing was checked' 'an empty range'
expect "$r" main~1 main 1 'cannot resolve' 'a base that does not exist'
expect "$r" main no-such-ref 1 'cannot resolve' 'a head that does not exist'

# side..main holds the merge commit and nothing else.
r="$(fixture)"
git -C "$r" checkout -q -b side
commit "$r" "feat: side"$'\n\n'"$SOB"
git -C "$r" checkout -q main
git -C "$r" merge -q --no-ff --no-edit -m 'Merge branch side' side
expect "$r" side main 1 'nothing was checked' 'a range of merge commits only'

out="$(cd "$work" && bash "$check" 2>&1)" && note "no arguments: expected a usage failure, got exit 0"
grep -q 'usage' <<<"$out" || note "no arguments: output lacks a usage line: $out"

if [ "$fail_count" -ne 0 ]; then
    printf '\ndco: %s failure(s)\n' "$fail_count" >&2
    exit 1
fi

printf 'dco: check_dco.sh passes signed ranges and fails unsigned, foreign, quoted, empty and unreadable ones\n'
