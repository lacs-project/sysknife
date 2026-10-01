#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

scripts/shellcheck-files.sh >"$tmp/scanned"
mapfile -d '' scanned <"$tmp/scanned"
((${#scanned[@]} > 150)) || fail "shellcheck scan covers only ${#scanned[@]} files"

declare -A scanned_set=()
for file in "${scanned[@]}"; do
    scanned_set["$file"]=1
done

missing=()
tracked_shell=0
git ls-files -z >"$tmp/tracked"
while IFS= read -r -d '' file; do
    [[ -f "$file" ]] || continue
    first=''
    IFS= read -r first <"$file" || true
    is_shell=false
    if [[ "$file" == *.sh ]]; then
        is_shell=true
    elif [[ "$first" == '#!'* && ("$first" == *bash* || "$first" == */sh) ]]; then
        is_shell=true
    fi
    "$is_shell" || continue
    tracked_shell=$((tracked_shell + 1))
    [[ -n "${scanned_set[$file]:-}" ]] || missing+=("$file")
done <"$tmp/tracked"

((tracked_shell > 150)) || fail "tracked shell-file floor collapsed to $tracked_shell"
((${#missing[@]} == 0)) || fail "tracked shell files missing from ShellCheck scan: ${missing[*]}"
[[ -n "${scanned_set[.githooks/pre-commit]:-}" ]] || fail '.githooks/pre-commit is not ShellCheck-covered'
[[ -n "${scanned_set[.githooks/pre-push]:-}" ]] || fail '.githooks/pre-push is not ShellCheck-covered'

scripts/shellcheck-files.sh --print-roots >"$tmp/roots"
roots_seen=0
while IFS= read -r -d '' root; do
    roots_seen=$((roots_seen + 1))
    trigger="$root/**"
    trigger_count="$(grep -F -c -- "- \"$trigger\"" .github/workflows/e2e.yml || true)"
    ((trigger_count == 2)) || fail "ShellCheck root $root must trigger both push and pull_request e2e jobs"
done <"$tmp/roots"
((roots_seen > 0)) || fail 'shellcheck-files.sh --print-roots produced no roots'

grep -Fq 'scripts/shellcheck-files.sh >"$file_list"' scripts/ci-local.sh || fail 'ci-local shellcheck must use scripts/shellcheck-files.sh'
if grep -Fq -- "-name '*.sh'" scripts/ci-local.sh; then
    fail "ci-local shellcheck must not maintain its own '*.sh' find"
fi

if scripts/shellcheck-files.sh "$tmp/missing-root" >"$tmp/out" 2>"$tmp/err"; then
    fail 'missing search root was accepted'
fi
grep -Fq 'missing search root:' "$tmp/err" || fail 'missing-root failure did not name the missing root'

mkdir "$tmp/empty-root"
if scripts/shellcheck-files.sh "$tmp/empty-root" >"$tmp/out" 2>"$tmp/err"; then
    fail 'empty search root was accepted'
fi
grep -Fq 'no shell files found' "$tmp/err" || fail 'empty-root failure did not explain the zero-file scan'

printf 'ok: ShellCheck covers %d tracked shell files and refuses missing/empty roots\n' "$tracked_shell"
