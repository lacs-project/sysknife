#!/usr/bin/env bash
set -euo pipefail

book_dir="${1:-book}"

python3 - "$book_dir" <<'PY'
import pathlib
import re
import sys
import urllib.parse

book = pathlib.Path(sys.argv[1])
if not book.is_dir():
    raise SystemExit(f"mdbook-links: book directory does not exist: {book}")

href_pattern = re.compile(r'href="([^"]+)"')
checked = 0
broken = []

for page in sorted(book.rglob("*.html")):
    if page.name == "print.html":
        continue
    for href in href_pattern.findall(page.read_text(errors="replace")):
        if href.startswith(("http://", "https://", "#", "mailto:", "//")):
            continue
        target = urllib.parse.unquote(href.split("#", 1)[0].split("?", 1)[0])
        if not target.endswith(".html"):
            continue
        checked += 1
        if not (page.parent / target).resolve().exists():
            broken.append(f"{page}\t{href}")

if checked == 0:
    raise SystemExit("mdbook-links: no internal .html links were checked")
if broken:
    print("mdbook-links: broken generated links:", file=sys.stderr)
    print("\n".join(broken), file=sys.stderr)
    raise SystemExit(1)

print(f"mdbook-links: checked {checked} internal .html links")
PY