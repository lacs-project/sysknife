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
CLAIM_FILES = (
    "README.md",
    "ROADMAP.md",
    "docs/introduction.md",
    "docs/quickstart.md",
    "docs/distro-support.md",
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
ACTION_SOURCE = "crates/sysknife-brain/src/planning_tools/propose_plan.rs"

# Full family sets that run-stories.sh can run and record. A claim may only rest
# on one of these.
FULL_STORY_SETS = ("ubuntu", "atomic")


class Failure(Exception):
    pass


def read_claim_files(root: Path) -> dict[str, str]:
    texts = {}
    for rel in CLAIM_FILES:
        path = root / rel
        if path.exists():
            texts[rel] = path.read_text()
    if not texts:
        raise Failure(f"no claim files found under {root}")
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
    """Every `<n> <noun>` in the docs must equal `expected`."""
    problems = []
    pattern = re.compile(rf"([0-9][0-9,]*)\s+{re.escape(noun)}")
    for rel, text in texts.items():
        for match in pattern.finditer(text):
            claimed = int(match.group(1).replace(",", ""))
            if claimed != expected:
                problems.append(
                    f"{rel}: claims {match.group(1)} {noun}, evidence says "
                    f"{expected:,} — regenerate the figure, do not retype it"
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
        problems += check_story_claims(texts, load_story_runs(root))

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
