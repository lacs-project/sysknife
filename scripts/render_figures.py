#!/usr/bin/env python3
"""Render the figures in SysKnife's README and docs from their sources.

A figure that describes the project is never typed. It sits in a marker:

  <!-- fig:NAME -->VALUE<!-- /fig -->            exact, thousands separators: 2,004
  <!-- fig:NAME floor=K -->VALUE<!-- /fig -->    rounded floor: 2,000+

and this script writes VALUE. HTML comments are invisible on GitHub and in mdBook.
`floor=K` renders floor(v / K) * K with a trailing "+", and refuses when v < K
(a floor of zero says nothing). A figure a routine PR moves is a floor; a figure
only a deliberate act changes (a recorded story run) stays exact.

  render_figures.py [--check] [ROOT]    exit 1 naming file:line, the stored value and
                                        the rendered one, for a stale marker, an
                                        unknown NAME, a malformed marker (unbalanced,
                                        nested) and a marker inside a code fence
  render_figures.py --write [ROOT]      rewrite only the marker contents; a second
                                        run changes no byte

Every value comes from a reader imported out of check_evidence_claims.py, the one
place that knows how to read each source: one source per figure, never a second
implementation here. A source that cannot be read, or a run that finds no marker
at all in CLAIM_FILES, is an error and exits 2: nothing is skipped.

`UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh` records the test evidence and then
runs --write, so one command updates evidence and docs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import check_evidence_claims as sources  # noqa: E402
from check_evidence_claims import Failure, find_markers  # noqa: E402

# NAME -> reader. A NAME with an argument is `NAME:ARG` and its reader takes it.
SIMPLE: dict[str, Callable[[Path], "int | str"]] = {
    "rust_tests": lambda root: sources.load_test_baseline(root)["tests"],
    "frontend_tests": lambda root: sources.load_test_baseline(root)["frontend_tests"],
    "typed_actions": sources.count_actions,
    "action_specs": sources.count_action_specs,
    "stories_total": lambda root: sum(sources.story_family_sizes(root).values()),
    "stories_atomic": lambda root: sources.story_family_sizes(root)["atomic"],
    "stories_ubuntu": lambda root: sources.story_family_sizes(root)["ubuntu"],
    "uncovered_all": lambda root: sources.uncovered_action_counts(root)["All"],
    "uncovered_fedora": lambda root: sources.uncovered_action_counts(root)["Fedora"],
    "uncovered_ubuntu": lambda root: sources.uncovered_action_counts(root)["Ubuntu"],
    "lts_story_total": sources.lts_story_total,
    "lts_story_rate": sources.lts_story_rate,
    "stories_ubuntu_unrecorded": lambda root: (
        sources.story_family_sizes(root)["ubuntu"] - sources.lts_story_total(root)
    ),
}
PARAMETRIC: dict[str, Callable[[Path, str], "int | str"]] = {
    "story_run": sources.story_run_rate,
    "story_run_total": sources.story_run_total,
    "story_run_served": sources.story_run_served,
}


def known_names() -> list[str]:
    return sorted(SIMPLE) + [f"{name}:ARG" for name in sorted(PARAMETRIC)]


def read_value(root: Path, name: str, cache: dict) -> "int | str":
    """Read one figure's source. Raises KeyError for an unknown NAME and Failure
    when the source cannot be read."""
    if name in cache:
        return cache[name]
    if name in SIMPLE:
        value = SIMPLE[name](root)
    else:
        base, _, arg = name.partition(":")
        if base not in PARAMETRIC or not arg:
            raise KeyError(name)
        value = PARAMETRIC[base](root, arg)
    cache[name] = value
    return value


def render(value: "int | str", floor: "int | None") -> str:
    """Format a source value. Raises ValueError when a floor cannot be applied."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"source returned {value!r}")
    if floor is None:
        return f"{value:,}" if isinstance(value, int) else value
    if not isinstance(value, int):
        raise ValueError(f"floor={floor} needs a count, the source gave {value!r}")
    if value < floor:
        raise ValueError(f"value {value:,} is below floor={floor:,}; state it exactly or lower K")
    return f"{value // floor * floor:,}+"


def process(root: Path, write: bool) -> tuple[list[str], list[str], int, int]:
    """Check (or rewrite) every marker in CLAIM_FILES.

    Returns (problems, stale, marker count, files rewritten). A problem is what
    --write cannot fix (unknown NAME, malformed marker, a floor that cannot apply,
    no markers at all); stale markers are what it fixes. Nothing is written while
    there is a problem.
    """
    texts = sources.read_claim_files(root)
    cache: dict = {}
    problems: list[str] = []
    stale: list[str] = []
    rewrites: dict[str, str] = {}
    total = 0
    for rel, text in texts.items():
        markers, structural = find_markers(text)
        problems += [f"{rel}:{line}: {message}" for line, message in structural]
        total += len(markers)
        pieces, last = [], 0
        for marker in markers:
            try:
                value = read_value(root, marker.name, cache)
            except KeyError:
                problems.append(
                    f"{rel}:{marker.line}: unknown figure NAME {marker.name!r}; "
                    f"known: {', '.join(known_names())}"
                )
                continue
            try:
                rendered = render(value, marker.floor)
            except ValueError as exc:
                problems.append(f"{rel}:{marker.line}: figure {marker.name!r}: {exc}")
                continue
            if rendered != marker.value:
                stale.append(
                    f"{rel}:{marker.line}: stale figure {marker.name!r}: stored "
                    f"{marker.value!r}, rendered {rendered!r}"
                )
            pieces.append(text[last : marker.value_start])
            pieces.append(rendered)
            last = marker.value_end
        pieces.append(text[last:])
        new_text = "".join(pieces)
        if new_text != text:
            rewrites[rel] = new_text
    if total == 0:
        problems.append("no figure markers found in CLAIM_FILES; refusing to treat that as success")
    written = 0
    if write and not problems:
        for rel, new_text in rewrites.items():
            with open(root / rel, "w", encoding="utf-8", newline="") as handle:
                handle.write(new_text)
            written += 1
    return problems, stale, total, written


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if flags - {"--check", "--write"} or {"--check", "--write"} <= flags or len(args) > 1:
        print("usage: render_figures.py [--check | --write] [ROOT]", file=sys.stderr)
        return 2
    write = "--write" in flags
    root = Path(args[0] if args else SCRIPT_DIR.parent).resolve()
    try:
        problems, stale, total, written = process(root, write)
    except Failure as exc:
        print(f"Figures could not be rendered: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Figures could not be rendered: could not read or write a file: {exc}", file=sys.stderr)
        return 2
    if problems or (stale and not write):
        print("Figure markers that do not render from their sources:", file=sys.stderr)
        for problem in problems + stale:
            print(f"  - {problem}", file=sys.stderr)
        if write:
            print("Nothing was written.", file=sys.stderr)
        return 1
    if write:
        print(f"Rendered {total} figure markers; rewrote {written} files.")
    else:
        print(f"All {total} figure markers match their sources.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
