#!/usr/bin/env python3
"""Check the rehearsal's reviewed publication/tool source lines.

This is a bounded source contract, not a general shell sandbox. Changes to
these lines require updating the reviewed set and the mutation fixtures.
"""

from pathlib import Path
import re
import sys

PUBLICATION_PATTERN = r"publish"
# Literal assignment values may contain quoted whitespace; this is not shell parsing.
ASSIGNMENT = r"""[A-Za-z_][A-Za-z0-9_]*=(?:[^\s'"]|'[^']*'|"[^"]*")*"""
SHELL_PREFIX = rf"(?:if|then|else|elif|do|while|until|!|command|exec|time|env|{ASSIGNMENT})"
TOOL_PATTERN = rf"(?:^\s*|[|&;(]\s*)(?:{SHELL_PREFIX}\s+)*(?:cargo|npm|gh|curl|wget|git)\s+"

PUBLICATION_LINES = {
    "This command never publishes packages, creates tags, or creates GitHub releases.",
    "--publish)",
    "printf '%s\\n' 'ERROR: release rehearsal never publishes; use the protected tag workflow' >&2",
    "# from crates.io. Rehearsal-only patches model the crates already published",
}
TOOL_LINES = {
    "cargo metadata --locked --no-deps --format-version 1 >/dev/null",
    'cargo package -p "$crate" --locked --allow-dirty \\',
    'npm pack ./packages/setup --pack-destination "$output" >/dev/null',
    "cargo build --release --locked -p sysknife-cli -p sysknife-daemon",
}


def fail(message):
    sys.exit(f"FAIL: {message}")


def screen(path, lines, pattern, reviewed, name, skip_comments=False):
    seen = set()
    count = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if skip_comments and stripped.startswith("#"):
            continue
        if not re.search(pattern, line, re.IGNORECASE):
            continue
        count += 1
        if stripped not in reviewed:
            fail(f"{path.name}:{number}: {name} not on the reviewed list: {line}")
        seen.add(stripped)
    if seen != reviewed:
        fail(f"{name} screen read {count} line(s) of {path.name}; "
             f"expected all {len(reviewed)} reviewed lines")


def main():
    if len(sys.argv) != 2:
        fail("usage: check-rehearsal-publication.py SCRIPT")
    path = Path(sys.argv[1])
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {path}: {error}")
    screen(path, lines, PUBLICATION_PATTERN, PUBLICATION_LINES, "publication word")
    screen(path, lines, TOOL_PATTERN, TOOL_LINES, "tool-invocation", skip_comments=True)


if __name__ == "__main__":
    main()
