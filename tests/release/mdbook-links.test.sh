#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$repo_root/scripts/check-mdbook-links.sh"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/book"
cat > "$fixture/book/index.html" <<'HTML'
<a href="guide.html">guide</a>
HTML
cat > "$fixture/book/guide.html" <<'HTML'
<a href="https://example.com">external</a>
HTML

"$checker" "$fixture/book"

rm "$fixture/book/guide.html"
if output="$("$checker" "$fixture/book" 2>&1)"; then
    printf 'mdbook-links: missing generated page unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'index.html' <<< "$output" || {
    printf 'mdbook-links: missing-page error omitted its source: %s\n' "$output" >&2
    exit 1
}

cat > "$fixture/book/index.html" <<'HTML'
<a href="https://example.com">external only</a>
HTML
if output="$("$checker" "$fixture/book" 2>&1)"; then
    printf 'mdbook-links: zero-link fixture unexpectedly passed\n' >&2
    exit 1
fi
grep -Fq 'no internal .html links were checked' <<< "$output" || {
    printf 'mdbook-links: zero-link error was not explicit: %s\n' "$output" >&2
    exit 1
}

if ! command -v mdbook >/dev/null 2>&1 || ! command -v mdbook-admonish >/dev/null 2>&1; then
    if [ -n "${CI:-}" ]; then
        printf 'mdbook-links: mdbook and mdbook-admonish must be installed under CI\n' >&2
        exit 1
    fi
    printf 'mdbook-links: SKIP real mdBook build (mdbook and mdbook-admonish are required)\n'
    exit 0
fi

# Do not modify the real working tree with mdbook-admonish install. Work out of
# a temporary fixture instead.
src_dir="$fixture/src"
build_dir="$fixture/real-book"
mkdir -p "$src_dir"

# Copy just enough structure for mdBook to compile the book.
cp -r "$repo_root/docs" "$src_dir/docs"
cp "$repo_root/book.toml" "$src_dir/"
# theme/custom.css is referenced in book.toml
if [ -d "$repo_root/theme" ]; then
    cp -r "$repo_root/theme" "$src_dir/theme"
fi

mdbook-admonish install "$src_dir"
mdbook build --dest-dir "$build_dir" "$src_dir"
"$checker" "$build_dir"
