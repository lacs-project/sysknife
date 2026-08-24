#!/usr/bin/env bash
#
# docs-share-cards.test.sh — the docs pages' og:image must name a file the
# build actually produces, at the size the tags declare.
#
# theme/head.hbs gives every docs page an Open Graph and Twitter card, so a
# link shared into Slack, Mastodon, LinkedIn or HN renders as a card instead of
# a bare URL. The image URL in those tags is absolute and hand-written, because
# mdBook exposes the source path (`index.md`) rather than the built one and
# handlebars has no string replace. A hand-written URL rots: rename the file,
# move the site, change the image, and the tags keep pointing at a 404 that
# nothing in the build notices. A card that fails to load is worse than no
# card, because the scraper caches the failure.
#
# So derive both sides and compare:
#
#   og:image URL      ──strip──▶  site-url from book.toml  ──▶  images/social-preview.png
#   book.toml `src`   ──join──▶   docs/images/social-preview.png  ──▶  must exist
#   declared w/h      ──vs──▶     the PNG's own IHDR header
#
# Needs no mdbook, no network and no built book, so it runs in the same job as
# the rest of tests/release.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
head_hbs="$repo_root/theme/head.hbs"
book_toml="$repo_root/book.toml"
for f in "$head_hbs" "$book_toml"; do
    [ -f "$f" ] || { printf 'missing file: %s\n' "$f" >&2; exit 1; }
done

fail() { printf 'docs-share-cards: %s\n' "$1" >&2; exit 1; }

# ── The URL the tags advertise ───────────────────────────────────────────────
og_image="$(sed -nE 's#.*property="og:image" content="([^"]+)".*#\1#p' "$head_hbs" | head -1)"
[ -n "$og_image" ] || fail 'theme/head.hbs declares no og:image'

tw_image="$(sed -nE 's#.*name="twitter:image" content="([^"]+)".*#\1#p' "$head_hbs" | head -1)"
[ "$tw_image" = "$og_image" ] \
    || fail "twitter:image ($tw_image) and og:image ($og_image) name different files"

# ── Where that URL lands in the source tree ──────────────────────────────────
site_url="$(sed -nE 's#^site-url *= *"([^"]+)".*#\1#p' "$book_toml" | head -1)"
[ -n "$site_url" ] || fail 'book.toml sets no site-url, so the URL cannot be checked'
src_dir="$(sed -nE 's#^src *= *"([^"]+)".*#\1#p' "$book_toml" | head -1)"
[ -n "$src_dir" ] || fail 'book.toml sets no src, so the URL cannot be checked'

# Strip scheme+host, then the site-url prefix, leaving the path inside the book.
url_path="${og_image#*://}"
url_path="/${url_path#*/}"
case "$url_path" in
    "$site_url"*) rel="${url_path#"$site_url"}" ;;
    *) fail "og:image path ($url_path) is not under book.toml's site-url ($site_url)" ;;
esac
[ -n "$rel" ] || fail "og:image resolves to the site root, not an image"

asset="$repo_root/$src_dir/$rel"
[ -f "$asset" ] \
    || fail "og:image names $rel, but $src_dir/$rel does not exist, so every card 404s"

# ── The size the tags declare must be the size the file is ───────────────────
declared_w="$(sed -nE 's#.*property="og:image:width" content="([0-9]+)".*#\1#p' "$head_hbs" | head -1)"
declared_h="$(sed -nE 's#.*property="og:image:height" content="([0-9]+)".*#\1#p' "$head_hbs" | head -1)"
if [ -n "$declared_w" ] || [ -n "$declared_h" ]; then
    read -r actual_w actual_h < <(python3 - "$asset" <<'PY'
import struct, sys
with open(sys.argv[1], 'rb') as fh:
    header = fh.read(24)
if header[:8] != b'\x89PNG\r\n\x1a\n':
    raise SystemExit('og:image is not a PNG; the width/height check cannot read it')
print(*struct.unpack('>II', header[16:24]))
PY
    )
    [ "$declared_w" = "$actual_w" ] && [ "$declared_h" = "$actual_h" ] \
        || fail "tags declare ${declared_w}x${declared_h} but $rel is ${actual_w}x${actual_h}"

    # Below this, Slack, LinkedIn and X all drop to the small square card, which
    # is the layout the summary_large_image tag exists to avoid.
    if [ "$actual_w" -lt 1200 ] || [ "$actual_h" -lt 630 ]; then
        fail "$rel is ${actual_w}x${actual_h}; summary_large_image needs at least 1200x630"
    fi
fi

printf 'docs-share-cards: og:image %s -> %s/%s (%sx%s)\n' \
    "$rel" "$src_dir" "$rel" "$actual_w" "$actual_h"
