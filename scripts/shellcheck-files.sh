#!/usr/bin/env bash
set -euo pipefail

if (($# > 0)); then
    roots=("$@")
else
    roots=(tests/e2e tests/release scripts assets/demo .githooks)
fi

for root in "${roots[@]}"; do
    [[ -d "$root" ]] || {
        printf 'shellcheck-files: missing search root: %s\n' "$root" >&2
        exit 1
    }
done

all_files="$(mktemp)"
trap 'rm -f "$all_files"' EXIT
find "${roots[@]}" -type f -print0 >"$all_files"

files=()
while IFS= read -r -d '' file; do
    first=''
    IFS= read -r first <"$file" || true
    if [[ "$first" == '#!'* && ("$first" == *bash* || "$first" == */sh) ]]; then
        files+=("$file")
    fi
done <"$all_files"

((${#files[@]} > 0)) || {
    printf 'shellcheck-files: no shell files found\n' >&2
    exit 1
}

printf '%s\0' "${files[@]}"
