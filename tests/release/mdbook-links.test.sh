#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$repo_root/scripts/check-mdbook-links.sh"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/book"
cat > "$fixture/book/index.html" <<'EOF'
<a href="guide.html">guide</a>
EOF
cat > "$fixture/book/guide.html" <<'EOF'
<a href="https://example.com">external</a>
EOF

"$checker" "$fixture/book"

rm "$fixture/book/guide.html"
if output="$($checker "$fixture/book" 2>&1)"; then
    printf 'mdbook-links: missing generated page unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'index.html' <<< "$output" || {
    printf 'mdbook-links: missing-page error omitted its source: %s\n' "$output" >&2
    exit 1
}

cat > "$fixture/book/index.html" <<'EOF'
<a href="https://example.com">external only</a>
EOF
if output="$($checker "$fixture/book" 2>&1)"; then
    printf 'mdbook-links: zero-link fixture unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'no internal .html links were checked' <<< "$output" || {
    printf 'mdbook-links: zero-link error was not explicit: %s\n' "$output" >&2
    exit 1
}

if ! command -v mdbook >/dev/null 2>&1 || ! command -v mdbook-admonish >/dev/null 2>&1; then
    printf 'mdbook-links: SKIP real mdBook build (mdbook and mdbook-admonish are required)\n'
    exit 0
fi

build_dir="$fixture/real-book"
mdbook-admonish install "$repo_root"
mdbook build --dest-dir "$build_dir" "$repo_root"
"$checker" "$build_dir"