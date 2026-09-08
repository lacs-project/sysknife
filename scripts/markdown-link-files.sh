#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exclusions_file="$repo_root/scripts/markdown-link-exclusions.txt"
external_files="$repo_root/scripts/markdown-link-external-files.txt"

if [[ "${1:-}" == "--external" ]]; then
    while IFS= read -r path || [[ -n "$path" ]]; do
        [[ -z "$path" || "$path" == \#* ]] && continue
        if ! git -C "$repo_root" ls-files --error-unmatch -- "$path" >/dev/null 2>&1 \
            || [[ "$path" != *.md ]]; then
            printf 'markdown-link-files: external-check path is not a tracked Markdown file: %s\n' \
                "$path" >&2
            exit 1
        fi
        printf '%s\0' "$path"
    done < "$external_files"
    exit 0
fi

if [[ $# -ne 0 ]]; then
    printf 'usage: %s [--external]\n' "${0##*/}" >&2
    exit 2
fi

exclusions=()
while IFS= read -r path || [[ -n "$path" ]]; do
    [[ -z "$path" || "$path" == \#* ]] && continue
    if ! git -C "$repo_root" ls-files --error-unmatch -- "$path" >/dev/null 2>&1 \
        || [[ "$path" != *.md ]]; then
        printf 'markdown-link-files: excluded path is not a tracked Markdown file: %s\n' \
            "$path" >&2
        exit 1
    fi
    exclusions+=("$path")
done < "$exclusions_file"

file_list="$(mktemp)"
trap 'rm -f "$file_list"' EXIT
if ! git -C "$repo_root" ls-files -z -- '*.md' > "$file_list"; then
    printf 'markdown-link-files: failed to enumerate tracked Markdown files\n' >&2
    exit 1
fi
count=0
while IFS= read -r -d '' path; do
    skip=false
    for excluded in "${exclusions[@]}"; do
        if [[ "$path" == "$excluded" ]]; then
            skip=true
            break
        fi
    done
    if [[ "$skip" != true ]]; then
        printf '%s\0' "$path"
        count=$((count + 1))
    fi
done < "$file_list"
if [[ "$count" -eq 0 ]]; then
    printf 'markdown-link-files: no tracked Markdown files to check\n' >&2
    exit 1
fi
