#!/usr/bin/env python3
"""Every number SysKnife publishes must come from evidence, not from memory.

The README claimed "65/65 stories" validated on a live VM in eight places. No
run had ever produced that number — the real measurements were 46/50 and 45/50 —
and it survived for months because nothing connected the claim to a measurement.
The test count rotted the same way, in the opposite direction: three docs said
"1,561 Rust tests" and check_public_claims.sh *required* that literal string
while the suite had grown to 1,681.

So each published figure is checked against the artifact that produced it:

  workspace tests   tests/evidence/workspace-tests.json  (scripts/test_baseline.sh)
  frontend tests    tests/evidence/workspace-tests.json  (--frontend)
  typed actions     counted from the action catalogue source
  story pass rate   tests/evidence/story-runs/*.json      (run-stories.sh)

A story claim additionally has to name a *full* family run. Subset runs record an
empty `story_set`, so a four-story probe can never be quoted as the headline.

Figures are not typed. Every figure these checks match in CLAIM_FILES must sit
inside a marker that scripts/render_figures.py owns:

  <!-- fig:NAME -->VALUE<!-- /fig -->            exact ("2,004")
  <!-- fig:NAME floor=K -->VALUE<!-- /fig -->    rounded floor ("2,000+")

This module refuses a matched figure outside a marker (check_unmarked_figures),
so a hand-typed number cannot creep back, and it keeps the semantic checks
(a story claim must name a full family run, validated tiers, ...) running on the
rendered text, with the markers unwrapped. Freshness of the marked values is
render_figures.py --check; `UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh`
re-renders them. The marker grammar lives here, once, and render_figures.py
imports it together with the value readers below.

Run via scripts/check_public_claims.sh; tests/release/public-claims.test.sh
mutates each claim and asserts this rejects it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# The release contract tests import this module to derive CLAIM_FILES. Keep the
# sibling baseline schema available in both direct-script and importlib modes.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from record_test_baseline import validate_document

# Files that carry public claims. Kept in step with claim_files in
# check_public_claims.sh; a file listed there but not here is simply unchecked
# for numbers, which is why the pristine-fixture guard in the test matters.
#
# The list started as "the files a visitor reads first" and that turned out to be
# the wrong boundary: unchecked files drift, and they drift further precisely
# because nothing complains. When this was widened, every newly covered file was
# already wrong — three docs still said 189 actions against a 190-action
# catalogue, one said the harness runs 10 stories against 104 on disk, and one
# advertised a "we want 100+ stories" goal that had been passed four times over.
# None of that was a subtle rounding error; it was simply never looked at again.
#
# So the rule is now: if a file states a figure about this project, it belongs
# here. Adding a file is cheap; the guard only complains about numbers it can
# derive an answer for.
#
# SECURITY.md carries the Security Model wording that
# check_public_claims.sh's independence pin screens. Without it listed here the
# pin ran over claim_files and could not fire on the one file it was written
# for: restoring the retired sentence left the check green.
CLAIM_FILES = (
    "README.md",
    "ROADMAP.md",
    "CONTRIBUTING.md",
    "HACKING.md",
    "SECURITY.md",
    "docs/introduction.md",
    "docs/quickstart.md",
    "docs/distro-support.md",
    "docs/architecture.md",
    "docs/typed-actions.md",
    "docs/action-reference.md",
    "docs/developer-guide.md",
    "docs/release-readiness.md",
    "docs/testing/user-stories.md",
    "docs/contributing/ubuntu-vm-testing.md",
    "docs/contributing/testing.md",
    "packages/setup/index.js",
)

# Docs that must state the workspace test baseline, not merely avoid
# contradicting it. Dropping the figure would otherwise pass silently.
REQUIRE_TEST_COUNT = (
    "README.md",
    "docs/introduction.md",
    "docs/distro-support.md",
)

TEST_BASELINE = "tests/evidence/workspace-tests.json"
STORY_RUNS = "tests/evidence/story-runs"
STORY_DIR = "tests/e2e/stories"
ACTION_SOURCE = "crates/sysknife-brain/src/planning_tools/propose_plan.rs"
ACTION_REFERENCE = "docs/action-reference.md"
STORY_COVERAGE_FILE = "CONTRIBUTING.md"

# Full family sets that run-stories.sh can run and record. A claim may only rest
# on one of these.
FULL_STORY_SETS = ("ubuntu", "atomic")


class Failure(Exception):
    pass


def read_claim_files(root: Path) -> dict[str, str]:
    texts = {}
    missing = []
    for rel in CLAIM_FILES:
        path = root / rel
        if path.exists():
            texts[rel] = path.read_text(encoding="utf-8")
        else:
            missing.append(rel)
    if missing:
        raise Failure(
            "claim files are missing, so their figures would go unchecked: "
            + ", ".join(missing)
        )
    return texts

# ---------------------------------------------------------------------------
# Figure markers. The grammar has one implementation, here; render_figures.py
# imports it.
#
#   <!-- fig:NAME -->VALUE<!-- /fig -->            exact
#   <!-- fig:NAME floor=K -->VALUE<!-- /fig -->    rounded floor, rendered "N+"
#
# HTML comments are invisible on GitHub and in mdBook. A marker sits on one line.
# Markers inside a fenced code block are refused (a fence is shown literally, so
# the comments would be visible and the value would never be read as a figure);
# markers inside an inline code span are documentation of the syntax and are
# ignored.
# ---------------------------------------------------------------------------
MARKER_START = re.compile(r"<!--\s*/?fig\b")
MARKER_TOKEN = re.compile(r"<!--\s*(?P<close>/)?fig(?P<rest>[^>]*?)\s*-->")
MARKER_OPEN_REST = re.compile(
    r"^:(?P<name>[A-Za-z0-9_.:-]+)(?:\s+floor=(?P<floor>[0-9]+))?$"
)
CODE_FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`\n]*`")


class Marker:
    """One well-formed marker: where it sits and what it currently says."""

    __slots__ = ("name", "floor", "start", "end", "value_start", "value_end", "line", "value")

    def __init__(self, name, floor, start, end, value_start, value_end, line, value):
        self.name = name
        self.floor = floor
        self.start = start
        self.end = end
        self.value_start = value_start
        self.value_end = value_end
        self.line = line
        self.value = value


def find_markers(text: str) -> tuple[list[Marker], list[tuple[int, str]]]:
    """Return the well-formed markers and every structural problem as (line, message).

    Problems: a marker inside a code fence, an unparseable marker comment, an
    unbalanced or nested pair, a pair split across lines, a floor of zero.
    """
    problems: list[tuple[int, str]] = []
    tokens = []  # (is_close, name, floor, start, end, line)
    in_fence = False
    offset = 0
    for lineno, line in enumerate(text.splitlines(keepends=True), 1):
        line_start = offset
        offset += len(line)
        if CODE_FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            if MARKER_START.search(line):
                problems.append((lineno, "figure marker inside a fenced code block"))
            continue
        spans = [m.span() for m in INLINE_CODE.finditer(line)]
        for start in MARKER_START.finditer(line):
            if any(a <= start.start() < b for a, b in spans):
                continue
            token = MARKER_TOKEN.match(line, start.start())
            if token is None:
                problems.append((lineno, "malformed figure marker (no closing '-->')"))
                continue
            rest = token.group("rest")
            if token.group("close"):
                if rest.strip():
                    problems.append((lineno, f"malformed closing marker {token.group(0)!r}"))
                    continue
                tokens.append((True, None, None, line_start + token.start(),
                               line_start + token.end(), lineno))
                continue
            opened = MARKER_OPEN_REST.match(rest.strip())
            if opened is None:
                problems.append((lineno, f"malformed figure marker {token.group(0)!r}"))
                continue
            floor = opened.group("floor")
            if floor is not None and int(floor) == 0:
                problems.append((lineno, "floor=0 is not a rounding"))
                continue
            tokens.append((False, opened.group("name"),
                           int(floor) if floor is not None else None,
                           line_start + token.start(), line_start + token.end(), lineno))

    markers: list[Marker] = []
    pending = None
    for token in tokens:
        is_close, name, floor, start, end, lineno = token
        if not is_close:
            if pending is not None:
                problems.append((lineno, f"nested figure marker inside the one opened on line {pending[5]}"))
                pending = token
                continue
            pending = token
            continue
        if pending is None:
            problems.append((lineno, "closing figure marker without an opening one"))
            continue
        _, name, floor, open_start, open_end, open_line = pending
        pending = None
        value = text[open_end:start]
        if "\n" in value:
            problems.append((open_line, "figure marker spans lines"))
            continue
        markers.append(Marker(name, floor, open_start, end, open_end, start, open_line, value))
    if pending is not None:
        problems.append((pending[5], "unbalanced figure marker: opened and never closed"))
    return markers, problems


def unwrap_markers(text: str) -> str:
    """The text a reader sees: each marker replaced by its value."""
    markers, _ = find_markers(text)
    out, last = [], 0
    for marker in markers:
        out.append(text[last : marker.start])
        out.append(marker.value)
        last = marker.end
    out.append(text[last:])
    return "".join(out)


def mask_markers(text: str) -> str:
    """The text with every marker replaced by a placeholder, so what is left is
    exactly the figures nothing owns."""
    markers, _ = find_markers(text)
    out, last = [], 0
    for marker in markers:
        out.append(text[last : marker.start])
        out.append("FIG")
        last = marker.end
    out.append(text[last:])
    return "".join(out)


# The README badge URLs are not figures and need no exemption: they are
# percent-encoded (`label=Rust%20tests`), so no shape below can match inside one.
# The pristine tree passing with both badges present is the proof.
# Digits followed by a floor's trailing plus ("2,000+ Rust tests"): read as the
# bare number so the shapes below match a hand-typed floor exactly as they match
# a hand-typed exact figure.
FLOOR_PLUS = re.compile(r"(?<=[0-9])\+(?=[\s-])")

# The shapes the checks below match. check_figure builds its pattern from these
# nouns; the rest are the patterns of the check named beside each one.
FIGURE_NOUNS = ("Rust tests", "frontend tests", "typed actions")
BARE_TOTAL_RE = re.compile(r"([0-9][0-9,]*)\s+tests\b")  # check_bare_test_totals
STORY_RATE_RE = re.compile(r"([0-9]+)\s*/\s*([0-9]+)\s+stories")  # check_story_claims
BARE_STORY_RE = re.compile(r"(?<!/)\b([0-9]{2,})[-\s]stor(?:y|ies)\b")  # check_bare_story_counts
FAMILY_RE = re.compile(
    r"\b(?P<count>[0-9]{2,})\s+(?P<family>atomic|ubuntu)\b", re.IGNORECASE
)  # check_bare_story_counts
ACTION_BARE_RE = re.compile(r"\b([0-9]{2,})\s+(?:typed\s+)?actions\b", re.IGNORECASE)
ACTION_SUBSET_RE = re.compile(
    r"\b([0-9]+)\s+actions\s+(?:with|have)\s+an\s+`?ActionSpec`?\b", re.IGNORECASE
)  # check_action_figures
# check_story_coverage_claims reads these three counts out of one sentence; each
# is a figure on its own.
UNCOVERED_FIGURE_RES = (
    re.compile(r"\b[0-9]+\s+are\s+still\s+untouched\s+by\s+any\s+story\b", re.IGNORECASE),
    re.compile(r"\b[0-9]+\s+Fedora-only\s+and\b", re.IGNORECASE),
    re.compile(r"\b[0-9]+\s+Ubuntu-only\s+ones\b", re.IGNORECASE),
)


def _figure_shapes(text: str) -> list[tuple[int, int]]:
    """Every (start, end) span any figure check would match in `text`."""
    hits: list[tuple[int, int]] = []
    for noun in FIGURE_NOUNS:
        spaced = r"\s+".join(re.escape(word) for word in noun.split())
        for match in re.finditer(rf"([0-9][0-9,]*)\s+{spaced}", text):
            hits.append(match.span())
    for match in BARE_TOTAL_RE.finditer(text):
        if int(match.group(1).replace(",", "")) >= BARE_TOTAL_FLOOR:
            hits.append(match.span())
    for regex in (STORY_RATE_RE, BARE_STORY_RE, FAMILY_RE, ACTION_BARE_RE, ACTION_SUBSET_RE,
                  *UNCOVERED_FIGURE_RES):
        for match in regex.finditer(text):
            hits.append(match.span())
    return hits


def check_unmarked_figures(raw_texts: dict[str, str]) -> list[str]:
    """Refuse a figure that the checks above would match but no marker owns.

    The marked figures belong to render_figures.py --check. Without this rule a
    hand-typed number would still be validated by the semantic checks, but it
    would be one more number a contributor has to edit by hand, and a floor typed
    by hand would not be validated at all (a floor is skipped by those checks, as
    `2,000+` is not an exact count).
    """
    problems = []
    for rel, text in raw_texts.items():
        _, structural = find_markers(text)
        for lineno, message in structural:
            problems.append(f"{rel}:{lineno}: {message}")
        masked = mask_markers(text)
        scanned = FLOOR_PLUS.sub("", masked)
        # Offsets in `scanned` map back into `masked` by adding the floor-plus
        # characters removed before them, so a hand-typed "2,000+" is quoted as typed.
        removed = [m.start() for m in FLOOR_PLUS.finditer(masked)]

        def original(offset: int) -> int:
            for index, position in enumerate(removed):
                if position - index >= offset:
                    return offset + index
            return offset + len(removed)

        seen = set()
        for start, end in sorted(_figure_shapes(scanned)):
            lineno = scanned.count("\n", 0, start) + 1
            matched = masked[original(start) : original(end)]
            key = (lineno, " ".join(matched.split()))
            if key in seen:
                continue
            seen.add(key)
            problems.append(
                f"{rel}:{lineno}: figure {' '.join(matched.split())!r} is not inside a "
                "<!-- fig:NAME --> marker. Do not type figures: wrap it and run "
                "scripts/render_figures.py --write"
            )
    return problems


def count_actions(root: Path) -> int:
    """Count entries in the brain's KNOWN_ACTIONS table."""
    source = root / ACTION_SOURCE
    if not source.exists():
        raise Failure(f"action catalogue source is missing: {ACTION_SOURCE}")
    text = source.read_text(encoding="utf-8")
    marker = "pub const KNOWN_ACTIONS: &[(&str, &str)] = &["
    if marker not in text:
        raise Failure(f"{ACTION_SOURCE} no longer declares KNOWN_ACTIONS as expected")
    table = text.split(marker, 1)[1].split("\n];", 1)[0]
    # Entries open with `("ActionName",` at the start of a line.
    count = len(re.findall(r'^\s*\("([A-Za-z0-9]+)",', table, re.M))
    if count < 50:
        raise Failure(
            f"only {count} actions parsed from {ACTION_SOURCE}; the pattern has drifted"
        )
    return count


def check_figure(texts: dict[str, str], noun: str, expected: int) -> list[str]:
    r"""Every `<n> <noun>` in the docs must equal `expected`.

    Whitespace between the words is matched as `\s+`, not literally. With
    `re.escape` the space in "frontend tests" only matched a space, so
    docs/distro-support.md's line-wrapped "72 frontend\ntests." was silently
    unchecked and could be edited to any value.
    """
    problems = []
    spaced = r"\s+".join(re.escape(word) for word in noun.split())
    pattern = re.compile(rf"([0-9][0-9,]*)\s+{spaced}")
    for rel, text in texts.items():
        for match in pattern.finditer(text):
            claimed = int(match.group(1).replace(",", ""))
            if claimed != expected:
                problems.append(
                    f"{rel}: claims {match.group(1)} {noun}, evidence says "
                    f"{expected:,} — regenerate the figure, do not retype it"
                )
    return problems


BARE_TOTAL_FLOOR = 1000


def check_bare_test_totals(texts: dict[str, str], allowed: tuple[int, ...]) -> list[str]:
    """Flag an unqualified `<n> tests` that looks like a stale workspace total."""
    problems = []
    for rel, text in texts.items():
        for match in BARE_TOTAL_RE.finditer(text):
            # Skip the qualified forms; check_figure owns those.
            preceding = text[max(0, match.start() - 12) : match.start()]
            claimed = int(match.group(1).replace(",", ""))
            if claimed < BARE_TOTAL_FLOOR or claimed in allowed:
                continue
            problems.append(
                f"{rel}: claims {match.group(1)} tests"
                + (f" (after {preceding.strip()!r})" if preceding.strip() else "")
                + f", which matches no recorded suite size {allowed}"
            )
    return problems


def load_story_runs(root: Path) -> list[dict]:
    directory = root / STORY_RUNS
    if not directory.is_dir():
        return []
    runs = []
    for path in sorted(directory.glob("*.json")):
        try:
            runs.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise Failure(f"{path.name} is not readable JSON: {exc}") from exc
    return runs


def story_run_has_no_unproven_results(run: dict) -> bool:
    """Only a run with explicit zero skipped and rate-limited stories can prove claims."""
    totals = run.get("totals")
    if not isinstance(totals, dict):
        return False
    return all(
        isinstance(totals.get(field), int)
        and not isinstance(totals.get(field), bool)
        and totals[field] == 0
        for field in ("skipped", "rate_limited")
    )


def check_story_claims(texts: dict[str, str], runs: list[dict]) -> list[str]:
    problems = []
    for rel, text in texts.items():
        for line in text.splitlines():
            match = STORY_RATE_RE.search(line)
            if not match:
                continue
            passed, total = int(match.group(1)), int(match.group(2))
            backing = [
                run
                for run in runs
                if run.get("story_set") in FULL_STORY_SETS
                and run.get("totals", {}).get("passed") == passed
                and run.get("totals", {}).get("total") == total
                and story_run_has_no_unproven_results(run)
                # A replay that missed, or served nothing, proves nothing — the
                # harness says so and fails the run. Such an artifact used to be
                # written anyway, with a healthy-looking pass rate.
                and run.get("cassette_audit", {}).get("verdict")
                in ("ok", "not-applicable")
            ]
            if not backing:
                problems.append(
                    f"{rel}: claims {passed}/{total} stories with no run in "
                    f"{STORY_RUNS}/ to back it. Record one with "
                    f"SYSKNIFE_RESULTS_JSON=... run-stories.sh ubuntu, or drop the figure."
                )
                continue
            # If the line names a model, the run that produced the number has to
            # be a run of that model. "65/65 with gpt-4.1" was wrong twice over.
            models = re.findall(r"`([a-z0-9][a-z0-9._/-]*(?:gpt|claude|llama|qwen)[a-z0-9._/-]*)`", line)
            models += re.findall(r"\b(gpt-[0-9][a-z0-9.-]*)\b", line)
            for model in set(models):
                if not any(model in run.get("surface", "") for run in backing):
                    surfaces = sorted({run.get("surface", "?") for run in backing})
                    problems.append(
                        f"{rel}: attributes {passed}/{total} stories to {model}, "
                        f"but the run recording that result used {', '.join(surfaces)}"
                    )
    return problems


# The Story-header grammar has exactly one implementation:
# `tests/e2e/run-stories.sh`, surfaced as `run-stories.sh --metadata`
# (tab-separated `id`, `family`, `title` rows). This checker must not parse
# story files itself — a second parser is a second answer, and the two have
# already disagreed about which line the header lives on and what an
# unparseable header means. Family counts are derived by running the runner
# and counting column 2.
STORY_METADATA_RUNNER = "tests/e2e/run-stories.sh"
STORY_FAMILIES = ("ubuntu", "atomic")


def _canonical_story_metadata(root: Path) -> list[tuple[str, str, str]]:
    """Load `(id, family, title)` rows from the canonical story parser.

    Every failure here raises `Failure` naming the cause: a broken or missing
    parser must never read as "zero stories", which would let the guards that
    consume these counts pass vacuously over an empty set.
    """
    runner = root / STORY_METADATA_RUNNER
    if not runner.is_file():
        raise Failure(
            f"could not derive story families: canonical metadata runner is "
            f"missing: {STORY_METADATA_RUNNER}"
        )
    runner_arg = runner.relative_to(root).as_posix()
    try:
        completed = subprocess.run(
            ["bash", runner_arg, "--metadata"],
            capture_output=True,
            cwd=root,
            text=True,
            encoding="utf-8",
            timeout=120,
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise Failure(
            f"could not derive story families: could not run "
            f"{STORY_METADATA_RUNNER} --metadata: {exc}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise Failure(
            f"could not derive story families: {STORY_METADATA_RUNNER} "
            f"--metadata timed out: {exc}"
        ) from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        detail = "; ".join(line for line in detail if line.strip())
        raise Failure(
            f"could not derive story families: {STORY_METADATA_RUNNER} "
            f"--metadata exited {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    rows: list[tuple[str, str, str]] = []
    for lineno, line in enumerate(completed.stdout.splitlines(), 1):
        fields = line.split("\t")
        if len(fields) != 3:
            raise Failure(
                f"could not derive story families: malformed metadata row "
                f"{lineno} from {STORY_METADATA_RUNNER} --metadata: {line!r}"
            )
        story_id, family, title = fields
        if not story_id.isdigit():
            raise Failure(
                f"could not derive story families: malformed story id in "
                f"metadata row {lineno}: {line!r}"
            )
        if family not in STORY_FAMILIES:
            raise Failure(
                f"could not derive story families: unknown family "
                f"{family!r} in metadata row {lineno}: {line!r}"
            )
        if not title.strip():
            raise Failure(
                f"could not derive story families: empty title in metadata "
                f"row {lineno}: {line!r}"
            )
        rows.append((story_id, family, title))
    if not rows:
        raise Failure(
            f"could not derive story families: {STORY_METADATA_RUNNER} "
            f"--metadata returned no stories while {STORY_DIR}/ holds story "
            f"files; refusing to treat the suite as empty"
        )
    return rows


def story_family_sizes(root: Path) -> dict[str, int]:
    """Return story-family sizes counted from the canonical story metadata.

    Runs `tests/e2e/run-stories.sh --metadata` and counts column 2, rather
    than reimplementing the header grammar. A story whose tags name `ubuntu`
    is in the ubuntu family; everything else is atomic — that classification
    lives in the runner, not here.
    """
    directory = root / STORY_DIR
    if not directory.is_dir():
        return {}
    if not sorted(directory.glob("story-*.sh")):
        return {}
    families: dict[str, int] = {"ubuntu": 0, "atomic": 0}
    for _, family, _ in _canonical_story_metadata(root):
        families[family] += 1
    return families


def story_set_sizes(root: Path) -> set[int]:
    """Legitimate story-suite sizes, derived from the canonical story metadata."""
    families = story_family_sizes(root)
    if not families:
        return set()
    return set(families.values()) | {sum(families.values())}


def uncovered_action_counts(root: Path) -> dict[str, int]:
    """Count uncovered catalogue rows by distro family.

    Catalogue rows come from the generated action reference. An action counts as
    covered when its name appears as a quoted action-like identifier anywhere in
    a story file. That intentionally keeps the approximation from #229: names
    in "must not confuse with" comments can count as covered, and this is not a
    stricter "covered by an Ubuntu-tagged story" metric from #233.
    """
    source = root / ACTION_REFERENCE
    if not source.exists():
        raise Failure(f"action reference is missing: {ACTION_REFERENCE}")
    rows = re.findall(
        r"^\| `([A-Za-z0-9_]+)` \|.*?\| (All|Ubuntu|Fedora) \|",
        source.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not rows:
        raise Failure(
            f"no action rows could be derived from {ACTION_REFERENCE}; "
            "the generated catalogue shape may have changed"
        )
    names = [name for name, _ in rows]
    if len(set(names)) != len(names):
        raise Failure(f"duplicate action rows found in {ACTION_REFERENCE}")

    story_dir = root / STORY_DIR
    story_files = sorted(story_dir.glob("story-*.sh"))
    if not story_files:
        raise Failure(
            f"no story files could be derived from {STORY_DIR}; "
            "the story glob may have changed"
        )
    named = set()
    for path in story_files:
        named.update(
            re.findall(r'"([A-Za-z0-9_]+)"', path.read_text(encoding="utf-8", errors="replace"))
        )
    if not named:
        raise Failure(
            f"no quoted action-like identifiers found in {STORY_DIR}; "
            "story coverage could not be derived"
        )

    counts = {family: 0 for family in ("All", "Fedora", "Ubuntu")}
    for name, family in rows:
        if name not in named:
            counts[family] += 1
    return counts


_NUMBER_WORDS = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}


def _claim_count(value: str) -> int:
    return int(value) if value.isdigit() else _NUMBER_WORDS[value.lower()]


# The two Debian-only prose shapes, shared by the CONTRIBUTING sentence check
# and the every-file universal-claim check so they cannot drift apart.
DEBIAN_GAP_PROSE = (
    r"\b(?P<count>\d+|zero|one|two|three|four|five|six|seven|eight|"
    r"nine|ten)\s+Debian-only\s+(?:actions?|ones?)\s+"
    r"(?:that\s+)?still\s+(?:have|has)\s+no(?:ne|\s+story)\b"
)
DEBIAN_EVERY_CLAIM = re.compile(
    r"\bEvery\s+Debian-only\s+action\s+(?:now\s+)?has\s+(?:one|a\s+story)\b",
    re.IGNORECASE,
)


def check_story_coverage_claims(texts: dict[str, str], root: Path) -> list[str]:
    """Keep the current story-coverage sentence derived from the tree.

    The claim is deliberately anchored to the contributor-facing sentence. If
    someone moves or rewrites that anchor, the check fails loudly instead of
    silently deciding that no story-coverage claim exists.
    """
    rel = STORY_COVERAGE_FILE
    text = texts.get(rel)
    if text is None:
        return [f"{rel}: story coverage claim file is not available"]
    text = re.sub(r"\s+", " ", text)
    family_sizes = story_family_sizes(root)
    if not family_sizes:
        raise Failure(
            f"could not derive story coverage from {STORY_DIR}; no story families found"
        )
    total = sum(family_sizes.values())
    uncovered = uncovered_action_counts(root)
    problems = []

    family_claim = re.search(
        r"\bThe suite is\s+(?P<total>\d+\+?)\s+stories?\s*:\s*"
        r"(?P<atomic>\d+\+?)\s+atomic\s*\+\s*(?P<ubuntu>\d+\+?)\s+Ubuntu\b",
        text,
        re.IGNORECASE,
    )
    if not family_claim:
        problems.append(
            f"{rel}: could not derive story coverage claim; expected "
            "'The suite is N stories: A atomic + U Ubuntu'"
        )
    else:
        # A rounded floor ("150+") is owned by render_figures.py --check; only an
        # exact count is compared here.
        published_sizes = {
            label: int(family_claim.group(label))
            for label in ("total", "atomic", "ubuntu")
            if not family_claim.group(label).endswith("+")
        }
        derived_sizes = {
            "total": total,
            "atomic": family_sizes.get("atomic", 0),
            "ubuntu": family_sizes.get("ubuntu", 0),
        }
        for label in published_sizes:
            if published_sizes[label] != derived_sizes[label]:
                problems.append(
                    f"{rel}: story coverage {label} count has published "
                    f"{published_sizes[label]}, derived {derived_sizes[label]}"
                )

    uncovered_claim = re.search(
        r"\bof the action names available on both families,\s*"
        r"(?P<all>\d+)\s+are still untouched by any story,\s*"
        r"plus\s+(?P<fedora>\d+)\s+Fedora-only\s+and\s+"
        r"(?P<ubuntu>\d+)\s+Ubuntu-only\s+ones\b",
        text,
        re.IGNORECASE,
    )
    if not uncovered_claim:
        problems.append(
            f"{rel}: could not derive story coverage claim; expected the "
            "'action names available on both families' uncovered-count anchor"
        )
    else:
        published_uncovered = {
            family: int(uncovered_claim.group(family.lower()))
            for family in ("All", "Fedora", "Ubuntu")
        }
        for family in ("All", "Fedora", "Ubuntu"):
            if published_uncovered[family] != uncovered[family]:
                problems.append(
                    f"{rel}: uncovered {family} action count has published "
                    f"{published_uncovered[family]}, derived {uncovered[family]}"
                )

    gap_claim = re.search(DEBIAN_GAP_PROSE, text, re.IGNORECASE)
    covered_claim = DEBIAN_EVERY_CLAIM.search(text)
    # Symmetric in both directions: a stated gap must equal the derived count
    # whether that count is zero or not, and the universal "every ... has one"
    # is valid only when the derived count is zero — so the two can never pass
    # together while disagreeing.
    if gap_claim:
        if _claim_count(gap_claim.group("count")) != uncovered["Ubuntu"]:
            problems.append(
                f"{rel}: Debian-only uncovered prose has published "
                f"{_claim_count(gap_claim.group('count'))}, derived "
                f"{uncovered['Ubuntu']}"
            )
    elif uncovered["Ubuntu"]:
        problems.append(
            f"{rel}: could not derive the Debian-only coverage prose; "
            f"expected a statement that {uncovered['Ubuntu']} actions still "
            "have no story"
        )
    if covered_claim:
        if uncovered["Ubuntu"]:
            problems.append(
                f"{rel}: says every Debian-only action has a story, but the tree "
                f"leaves {uncovered['Ubuntu']} Ubuntu-only actions uncovered"
            )
    elif not uncovered["Ubuntu"] and not gap_claim:
        problems.append(
            f"{rel}: could not derive the Debian-only coverage prose; "
            "expected every Debian-only action to have a story"
        )

    return problems


def check_debian_only_prose_claims(texts: dict[str, str], root: Path) -> list[str]:
    """Every screened file's Debian-only prose must match the derived gap.

    A universal "every ... has a story" is valid only when the derived
    Ubuntu-only uncovered count is zero; a stated gap count must equal it,
    whether it is zero or not — so contradictory claims can never pass
    together. The same sentence lived in two screened files saying opposite
    things, so both forms are checked everywhere, not just where the counts
    sit. No action-name list is maintained or validated here.
    """
    uncovered_ubuntu = uncovered_action_counts(root)["Ubuntu"]
    problems = []
    for rel, text in texts.items():
        # CONTRIBUTING.md is skipped here: check_story_coverage_claims already
        # reports both shapes with the same messages, so including it would
        # only double-report the same sentences.
        if rel == STORY_COVERAGE_FILE:
            continue
        normalized = re.sub(r"\s+", " ", text)
        gap_claim = re.search(DEBIAN_GAP_PROSE, normalized, re.IGNORECASE)
        if gap_claim and _claim_count(gap_claim.group("count")) != uncovered_ubuntu:
            problems.append(
                f"{rel}: Debian-only uncovered prose has published "
                f"{_claim_count(gap_claim.group('count'))}, derived "
                f"{uncovered_ubuntu}"
            )
        if DEBIAN_EVERY_CLAIM.search(normalized) and uncovered_ubuntu:
            problems.append(
                f"{rel}: says every Debian-only action has a story, but the tree "
                f"leaves {uncovered_ubuntu} Ubuntu-only actions uncovered"
            )
    return problems


def check_bare_story_counts(
    texts: dict[str, str], runs: list[dict], root: Path
) -> list[str]:
    """Catch a story count written without a pass/total slash.

    `check_story_claims` only sees `N/M stories`, so
    "validated with the full 65-story VM suite" was invisible to it — a figure
    matching no run and no story set, sitting in the introduction while the one
    recorded artifact said 49/50 on a different release. A guard that only
    inspects the shape a claim happened to be written in is not a guard.

    A bare count is allowed if it equals a story-set size on disk (the whole
    suite, or one family) or the total of some recorded full-family run.
    Anything else names a suite that does not exist.

    A family-labelled count (`N atomic`, `N Ubuntu`) is additionally checked
    against the derived size of the family it names: both numbers being
    individually legitimate sizes is not enough, since swapped labels would
    otherwise pass.
    """
    bare = BARE_STORY_RE
    family = FAMILY_RE

    allowed = {
        run.get("totals", {}).get("total")
        for run in runs
        if run.get("story_set") in FULL_STORY_SETS
    }
    allowed.discard(None)
    allowed |= story_set_sizes(root)
    families = story_family_sizes(root)
    if not families:
        raise Failure(
            f"could not derive story coverage from {STORY_DIR}; no story families found"
        )

    problems = []
    for rel, text in texts.items():
        normalized = re.sub(r"\s+", " ", text)
        for match in bare.finditer(normalized):
            count = int(match.group(1))
            if count in allowed:
                continue
            known = ", ".join(str(c) for c in sorted(allowed)) or "none"
            problems.append(
                f"{rel}: claims a {count}-story suite, which matches neither "
                f"the stories on disk nor any recorded run (known: {known}). "
                f"Quote a figure from {STORY_RUNS}/ or drop it."
            )
        for match in family.finditer(normalized):
            count = int(match.group("count"))
            label = match.group("family")
            expected = families[label.lower()]
            if count != expected:
                problems.append(
                    f"{rel}: {label} family story count has published "
                    f"{count}, derived {expected}"
                )
    return problems


def count_action_specs(root: Path) -> int:
    """Derive the executor ActionSpec count from the generated reference table."""
    path = root / "docs/action-reference.md"
    if not path.exists():
        raise Failure("docs/action-reference.md is missing; cannot derive ActionSpec count")
    row = re.compile(r"^\| `[A-Za-z0-9_]+` \|")
    count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if row.match(line))
    if count == 0:
        raise Failure("docs/action-reference.md contains no generated ActionSpec rows")
    return count


def check_action_figures(
    texts: dict[str, str], catalogue: int, action_specs: int
) -> list[str]:
    """Catch a bare "N actions" that is not the catalogue size.

    `check_figure` only sees the exact noun it is given ("typed actions"), so
    "the catalogue defines 189 actions" sailed past it in three documents while
    the catalogue held 190. The count is not wrong by accident: 189 is the number
    of actions carrying an `ActionSpec`, with `ListJobHistory` handled by the
    dispatcher instead, so both figures are real and the difference is a genuine
    distinction — one that was explained in exactly one file while three others
    stated 189 as if it were the total.

    So a bare "N actions" must be the catalogue size, UNLESS the line says which
    subset it means by naming `ActionSpec`. That keeps the honest sub-count
    writable, forces it to carry its qualifier, and still catches the count
    drifting.
    """
    bare = ACTION_BARE_RE
    subset = ACTION_SUBSET_RE

    problems = []
    for rel, text in texts.items():
        for line in text.splitlines():
            subset_match = subset.search(line)
            if subset_match:
                count = int(subset_match.group(1))
                if count != action_specs:
                    problems.append(
                        f"{rel}: claims {count} actions with an ActionSpec, "
                        f"derived {action_specs} from docs/action-reference.md"
                    )
                continue
            for match in bare.finditer(line):
                count = int(match.group(1))
                if count == catalogue:
                    continue
                problems.append(
                    f"{rel}: says {count} actions, but the catalogue holds {catalogue}. "
                    f"Either state {catalogue}, or name the subset by mentioning "
                    "`ActionSpec` on the same line."
                )
    return problems


def replay_verified_releases(root: Path) -> set[str]:
    """Releases with a committed record run AND a replay twin that reproduced it.

    That pair is what `tests/release/cassette-replay-parity.test.sh` proves
    reproduces: the record run says what happened live, the replay says the
    cassette reproduces it. A release with only a record run has a pass rate
    nothing has re-derived; a release with neither has nothing at all.

    The twin has to have *worked*. Merely existing was enough here for a while,
    and the gap was not hypothetical: all three LTSes carried a twin whose
    `cassette_audit.verdict` was `failed`, because the cassette stored only
    successes and so could not reproduce any story whose first call the provider
    rejected. Each release was tiered "Validated" on the strength of a file that
    says, in its own fields, that it did not reproduce the run. A pass-rate
    figure was already refused on those grounds; the tier was not.
    """
    directory = root / STORY_RUNS
    if not directory.is_dir():
        return set()

    records: dict[str, Path] = {}
    replays: set[str] = set()
    for path in sorted(directory.glob("*.json")):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise Failure(f"{path.name} is not readable JSON: {exc}") from exc
        release = str(run.get("release", ""))
        if not release:
            continue
        if path.name.endswith(".replay.json"):
            if (
                str(run.get("cassette_audit", {}).get("verdict", "")) == "ok"
                and story_run_has_no_unproven_results(run)
            ):
                replays.add(release)
        elif story_run_has_no_unproven_results(run):
            records[release] = path
    return set(records) & replays


def check_validated_tiers(texts: dict[str, str], root: Path) -> list[str]:
    """A release may be tiered "Validated" only where the evidence says so.

    This replaced a hardcoded `reject_pattern` naming 22.04 and 26.04 as
    "smoke-tested, not launch-validated". That was the same hand-maintained
    blacklist the numeric guards were rewritten to remove, and it aged the same
    way — but worse than stale: it began forbidding the truth. 22.04 accumulated
    five live runs and a committed replay pair, so the honest tier for it became
    unwritable, and the only ways to satisfy the guard were to understate the
    evidence or to switch the guard off.

    So the permitted set is derived. A table row whose FIRST cell names an Ubuntu
    version may end in a "Validated" tier cell if and only if that release has a
    replay-verified artifact pair on disk. Aspiration still cannot be published
    as fact, which is the point of the original rule, and a release earns the
    tier by having a run committed rather than by someone editing this file.
    """
    verified = replay_verified_releases(root)
    row = re.compile(
        r"^\|[^|]*?(?P<release>\d\d\.\d\d)[^|]*\|.*\|\s*\*{0,2}validated\*{0,2}\s*\|\s*$",
        re.IGNORECASE,
    )

    problems = []
    for rel, text in texts.items():
        for line in text.splitlines():
            match = row.match(line.strip())
            if not match:
                continue
            release = match.group("release")
            if release in verified:
                continue
            known = ", ".join(sorted(verified)) or "none"
            problems.append(
                f"{rel}: tiers Ubuntu {release} as Validated, but no replay-verified "
                f"run is committed for it (replay-verified: {known}). Record one into "
                f"{STORY_RUNS}/ or use a weaker tier."
            )
    return problems


def load_test_baseline(root: Path) -> dict:
    path = root / TEST_BASELINE
    if not path.exists():
        raise Failure(
            f"{TEST_BASELINE} is missing; record it with "
            "UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh"
        )
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Failure(f"{TEST_BASELINE} is not readable JSON: {exc}") from exc

    problems = validate_document(baseline, require_all_fields=True)
    if problems:
        raise Failure(f"{TEST_BASELINE} is invalid: {'; '.join(problems)}")
    return baseline


LTS_RELEASES = ("22.04", "24.04", "26.04")


def story_run_totals(root: Path, stem: str) -> dict:
    """The totals of one recorded run, addressed by its file name stem."""
    path = root / STORY_RUNS / f"{stem}.json"
    if not path.is_file():
        raise Failure(f"no recorded story run {STORY_RUNS}/{stem}.json")
    try:
        run = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Failure(f"{STORY_RUNS}/{stem}.json is not readable JSON: {exc}") from exc
    totals = run.get("totals") if isinstance(run, dict) else None
    if not isinstance(totals, dict) or not all(
        isinstance(totals.get(f), int) and not isinstance(totals.get(f), bool)
        for f in ("passed", "total")
    ):
        raise Failure(f"{STORY_RUNS}/{stem}.json has no integer totals.passed and totals.total")
    return totals


def story_run_rate(root: Path, stem: str) -> str:
    """`passed/total` of one recorded run, read from its artifact."""
    totals = story_run_totals(root, stem)
    return f"{totals['passed']}/{totals['total']}"


def story_run_total(root: Path, stem: str) -> int:
    """Stories in one recorded run, read from its artifact."""
    return story_run_totals(root, stem)["total"]


def story_run_served(root: Path, stem: str) -> int:
    """Calls a replay served, from its `cassette_audit`."""
    path = root / STORY_RUNS / f"{stem}.json"
    story_run_totals(root, stem)  # missing or unreadable: fail with the reader's message
    audit = json.loads(path.read_text(encoding="utf-8")).get("cassette_audit")
    served = audit.get("served") if isinstance(audit, dict) else None
    if not isinstance(served, int) or isinstance(served, bool):
        raise Failure(f"{STORY_RUNS}/{stem}.json has no integer cassette_audit.served")
    return served


def lts_story_rates(root: Path) -> dict[str, tuple[int, int]]:
    """`(passed, total)` of the latest full-family record run of each Ubuntu LTS."""
    latest: dict[str, tuple[str, tuple[int, int]]] = {}
    for run in load_story_runs(root):
        release = str(run.get("release", ""))
        if (
            release in LTS_RELEASES
            and run.get("story_set") in FULL_STORY_SETS
            and run.get("cassette_mode") == "record"
            and story_run_has_no_unproven_results(run)
        ):
            totals = run.get("totals", {})
            key = str(run.get("ran_at", ""))
            if release not in latest or key > latest[release][0]:
                latest[release] = (key, (totals.get("passed"), totals.get("total")))
    missing = [release for release in LTS_RELEASES if release not in latest]
    if missing:
        raise Failure(
            "no full-family record run is committed for Ubuntu " + ", ".join(missing)
        )
    return {release: latest[release][1] for release in LTS_RELEASES}


def lts_story_total(root: Path) -> int:
    """The story count every LTS run covers. Refuses when the runs disagree."""
    rates = lts_story_rates(root)
    totals = {total for _, total in rates.values()}
    if len(totals) != 1:
        raise Failure(f"the LTS runs cover different story counts: {rates}")
    return totals.pop()


def lts_story_rate(root: Path) -> str:
    """`passed/total` shared by every LTS run. Refuses when the runs disagree."""
    rates = lts_story_rates(root)
    if len(set(rates.values())) != 1:
        raise Failure(f"the LTS runs do not share one pass rate: {rates}")
    passed, total = next(iter(rates.values()))
    return f"{passed}/{total}"


def check_pre_commit_commands(root: Path, guide: str) -> list[str]:
    """Compare the documented gate with the executable hook, in order."""
    hook = root / ".githooks/pre-commit"
    if not hook.exists():
        raise Failure(".githooks/pre-commit is missing")
    commands = [
        line.strip()
        for line in hook.read_text(encoding="utf-8").splitlines()
        if line.strip()
        and not line.lstrip().startswith(("#", "set ", "cd ", "echo "))
    ]
    section = guide.split("## Pre-commit Hooks\n", 1)[-1].split("\n## ", 1)[0]
    block = re.search(r"```sh\n(.*?)\n```", section, re.S)
    documented = block.group(1).splitlines() if block else []
    if documented == commands:
        return []
    return [
        "docs/developer-guide.md: pre-commit steps differ from .githooks/pre-commit; "
        f"expected {commands!r}; documented {documented!r}"
    ]


SHELL_FENCE = re.compile(r"^\s*```(?:sh|bash|shell|console|zsh)\s*$")
FRAMEWORK_COMMAND = re.compile(
    r"\bpre-commit\s+(?:install|run)\b|\b(?:pip3?|pipx|uv\s+tool)\s+install\s+pre-commit\b"
)
SKIPPED_DIRS = {".git", "node_modules", "target", "dist", "book"}


def check_framework_commands(root: Path) -> list[str]:
    """Reject the pre-commit framework as a command in any Markdown shell block."""
    problems = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIPPED_DIRS)
        for name in sorted(n for n in names if n.endswith(".md")):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            in_shell = False
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.lstrip().startswith("```"):
                    in_shell = not in_shell and bool(SHELL_FENCE.match(line))
                    continue
                command = line.strip().removeprefix("$ ")
                if in_shell and not command.startswith("#") and FRAMEWORK_COMMAND.search(command):
                    problems.append(
                        f"{rel}:{number}: runs `{command}`, but the hooks run through "
                        "core.hooksPath and the pre-commit framework is not used "
                        "(see docs/developer-guide.md)"
                    )
    return problems


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    try:
        raw_texts = read_claim_files(root)
        # The semantic checks read what a visitor reads: markers unwrapped.
        texts = {rel: unwrap_markers(text) for rel, text in raw_texts.items()}

        baseline = load_test_baseline(root)

        problems = []
        problems += check_unmarked_figures(raw_texts)
        problems += check_pre_commit_commands(root, texts["docs/developer-guide.md"])
        problems += check_framework_commands(root)
        problems += check_figure(texts, "Rust tests", baseline["tests"])
        problems += check_figure(texts, "frontend tests", baseline["frontend_tests"])
        problems += check_figure(texts, "typed actions", count_actions(root))
        # The rule this replaced also caught an unqualified "1,347 tests". Only
        # workspace-scale numbers are treated as totals, so ordinary prose like
        # "3 tests" is left alone; 1000 is below either suite and above any count
        # a sentence would mention in passing.
        problems += check_bare_test_totals(
            texts, (baseline["tests"], baseline["frontend_tests"])
        )
        story_runs = load_story_runs(root)
        problems += check_story_claims(texts, story_runs)
        problems += check_story_coverage_claims(texts, root)
        problems += check_debian_only_prose_claims(texts, root)
        problems += check_bare_story_counts(texts, story_runs, root)
        problems += check_validated_tiers(texts, root)
        problems += check_action_figures(texts, count_actions(root), count_action_specs(root))

        for rel in REQUIRE_TEST_COUNT:
            names = [m.name for m in find_markers(raw_texts[rel])[0]]
            if "rust_tests" not in names:
                problems.append(
                    f"{rel}: does not state the measured baseline; it needs a "
                    "<!-- fig:rust_tests floor=1000 --> marker"
                )

        if problems:
            print("Claims that do not derive from evidence:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 1
    except Failure as exc:
        print(f"Evidence check could not run: {exc}", file=sys.stderr)
        return 1

    print("Published figures match the evidence artifacts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
