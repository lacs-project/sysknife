#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/scripts" "$fixture/docs"
cp "$repo_root/scripts/markdown-link-files.sh" "$fixture/scripts/"
cat > "$fixture/scripts/markdown-link-exclusions.txt" <<'EOF'
# One deliberately excluded fixture document.
docs/skipped.md
EOF
cat > "$fixture/scripts/markdown-link-external-files.txt" <<'EOF'
README.md
EOF
touch "$fixture/README.md" "$fixture/docs/guide.md" "$fixture/docs/skipped.md"

git -C "$fixture" init -q
git -C "$fixture" add README.md docs scripts/markdown-link-exclusions.txt \
    scripts/markdown-link-external-files.txt

files=()
while IFS= read -r -d '' file; do
    files+=("$file")
done < <("$fixture/scripts/markdown-link-files.sh")
expected=(README.md docs/guide.md)
[[ "${files[*]}" == "${expected[*]}" ]] || {
    printf 'markdown-link-files: expected <%s>, got <%s>\n' \
        "${expected[*]}" "${files[*]}" >&2
    exit 1
}

external_files=()
while IFS= read -r -d '' file; do
    external_files+=("$file")
done < <("$fixture/scripts/markdown-link-files.sh" --external)
[[ "${external_files[*]}" == 'README.md' ]] || {
    printf 'markdown-link-files: expected external set <README.md>, got <%s>\n' \
        "${external_files[*]}" >&2
    exit 1
}

printf 'docs/missing.md\n' > "$fixture/scripts/markdown-link-external-files.txt"
if output="$("$fixture/scripts/markdown-link-files.sh" --external 2>&1)"; then
    printf 'markdown-link-files: stale external-check path unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'external-check path is not a tracked Markdown file: docs/missing.md' \
    <<< "$output" || {
    printf 'markdown-link-files: stale external-check error omitted its path: %s\n' \
        "$output" >&2
    exit 1
}

printf 'docs/missing.md\n' >> "$fixture/scripts/markdown-link-exclusions.txt"
if output="$("$fixture/scripts/markdown-link-files.sh" 2>&1)"; then
    printf 'markdown-link-files: stale exclusion unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'excluded path is not a tracked Markdown file: docs/missing.md' <<< "$output" || {
    printf 'markdown-link-files: stale exclusion error omitted its path: %s\n' "$output" >&2
    exit 1
}

printf 'markdown-link-files: derived files and exclusions validated.\n'
