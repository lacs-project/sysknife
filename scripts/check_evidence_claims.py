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

Run via scripts/check_public_claims.sh; tests/release/public-claims.test.sh
mutates each claim and asserts this rejects it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

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
CLAIM_FILES = (
    "README.md",
    "ROADMAP.md",
    "CONTRIBUTING.md",
    "HACKING.md",
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
            texts[rel] = path.read_text()
        else:
            missing.append(rel)
    if missing:
        raise Failure(
            "claim files are missing, so their figures would go unchecked: "
            + ", ".join(missing)
        )
    return texts


def count_actions(root: Path) -> int:
    """Count entries in the brain's KNOWN_ACTIONS table."""
    source = root / ACTION_SOURCE
    if not source.exists():
        raise Failure(f"action catalogue source is missing: {ACTION_SOURCE}")
    text = source.read_text()
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
    pattern = re.compile(r"([0-9][0-9,]*)\s+tests\b")
    for rel, text in texts.items():
        for match in pattern.finditer(text):
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
            runs.append(json.loads(path.read_text()))
        except json.JSONDecodeError as exc:
            raise Failure(f"{path.name} is not readable JSON: {exc}") from exc
    return runs


def check_story_claims(texts: dict[str, str], runs: list[dict]) -> list[str]:
    problems = []
    pattern = re.compile(r"([0-9]+)\s*/\s*([0-9]+)\s+stories")
    for rel, text in texts.items():
        for line in text.splitlines():
            match = pattern.search(line)
            if not match:
                continue
            passed, total = int(match.group(1)), int(match.group(2))
            backing = [
                run
                for run in runs
                if run.get("story_set") in FULL_STORY_SETS
                and run.get("totals", {}).get("passed") == passed
                and run.get("totals", {}).get("total") == total
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


def story_set_sizes(root: Path) -> set[int]:
    """Legitimate story-suite sizes, derived from the story files themselves.

    The whole suite, and each family within it. Family membership is read the
    same way `tests/e2e/run-stories.sh` reads it — a story whose header tags name
    `ubuntu` is in the ubuntu family, everything else is atomic — so the guard
    and the harness cannot disagree about how big a family is.
    """
    directory = root / STORY_DIR
    if not directory.is_dir():
        return set()
    header = re.compile(r"^#\s*Story\s+\d+\s*(?:\(([^)]*)\))?\s*:")
    families: dict[str, int] = {"ubuntu": 0, "atomic": 0}
    for path in directory.glob("story-*.sh"):
        tags = ""
        for line in path.read_text(errors="replace").splitlines()[:6]:
            match = header.match(line)
            if match:
                tags = match.group(1) or ""
                break
        families["ubuntu" if "ubuntu" in tags else "atomic"] += 1
    return set(families.values()) | {sum(families.values())}


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
    """
    slash_form = re.compile(r"[0-9]+\s*/\s*[0-9]+\s+stor")
    bare = re.compile(r"\b([0-9]{2,})[-\s]stor(?:y|ies)\b")

    allowed = {
        run.get("totals", {}).get("total")
        for run in runs
        if run.get("story_set") in FULL_STORY_SETS
    }
    allowed.discard(None)
    allowed |= story_set_sizes(root)

    problems = []
    for rel, text in texts.items():
        for line in text.splitlines():
            # The slash form has its own, stricter check; do not report twice.
            if slash_form.search(line):
                continue
            for match in bare.finditer(line):
                count = int(match.group(1))
                if count in allowed:
                    continue
                known = ", ".join(str(c) for c in sorted(allowed)) or "none"
                problems.append(
                    f"{rel}: claims a {count}-story suite, which matches neither "
                    f"the stories on disk nor any recorded run (known: {known}). "
                    f"Quote a figure from {STORY_RUNS}/ or drop it."
                )
    return problems


def check_action_figures(texts: dict[str, str], catalogue: int) -> list[str]:
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
    bare = re.compile(r"\b([0-9]{2,})\s+(?:typed\s+)?actions\b", re.IGNORECASE)

    problems = []
    for rel, text in texts.items():
        for line in text.splitlines():
            if "ActionSpec" in line:
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
            run = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise Failure(f"{path.name} is not readable JSON: {exc}") from exc
        release = str(run.get("release", ""))
        if not release:
            continue
        if path.name.endswith(".replay.json"):
            if str(run.get("cassette_audit", {}).get("verdict", "")) == "ok":
                replays.add(release)
        else:
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


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    try:
        texts = read_claim_files(root)

        baseline_path = root / TEST_BASELINE
        if not baseline_path.exists():
            raise Failure(
                f"{TEST_BASELINE} is missing; record it with "
                "UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh"
            )
        baseline = json.loads(baseline_path.read_text())
        for field in ("tests", "frontend_tests"):
            if not isinstance(baseline.get(field), int):
                raise Failure(f"{TEST_BASELINE} has no integer '{field}' field")

        problems = []
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
        problems += check_bare_story_counts(texts, story_runs, root)
        problems += check_validated_tiers(texts, root)
        problems += check_action_figures(texts, count_actions(root))

        expected_tests = f"{baseline['tests']:,} Rust tests"
        for rel in REQUIRE_TEST_COUNT:
            if rel in texts and expected_tests not in texts[rel]:
                problems.append(
                    f"{rel}: does not state the measured baseline "
                    f"({expected_tests})"
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
