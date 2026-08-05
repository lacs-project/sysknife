#!/usr/bin/env python3
"""Serialise one story-suite run into a story-run evidence artifact.

Split out of `tests/e2e/run-stories.sh` so the writer and its reader
(`scripts/check_evidence_claims.py`) can be round-tripped by a test. They could
not be before, and the cost was immediate: the shell version assembled JSON with
`printf` and `sep=",\\n"`, which in double quotes is the three characters `,` `\\`
`n`. `printf` expands escapes only in its *format* operand, so a literal
backslash landed between story objects and every artifact from a run of two or
more stories was invalid JSON — unnoticed, because the only test that read an
artifact used a hand-written fixture.

Reads tab-separated `id<TAB>verdict<TAB>name` rows on stdin; everything else
arrives as EV_* environment variables.
"""

from __future__ import annotations

import json
import os
import sys

REQUIRED_ENV = (
    "EV_PATH",
    "EV_DISTRO_ID",
    "EV_RELEASE",
    "EV_SURFACE",
    "EV_CASSETTE_MODE",
    "EV_CASSETTE_HITS",
    "EV_CASSETTE_MISSES",
    "EV_CASSETTE_VERDICT",
    "EV_STORY_SET",
    "EV_RAN_AT",
    "EV_TOTAL",
    "EV_PASSED",
    "EV_FAILED",
    "EV_SKIPPED",
    "EV_RATELIMITED",
)


def main() -> int:
    missing = [name for name in REQUIRED_ENV if name not in os.environ]
    if missing:
        sys.exit(f"missing required environment: {', '.join(missing)}")

    stories: dict[str, dict[str, str]] = {}
    for line in sys.stdin.read().splitlines():
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            sys.exit(f"malformed story row (expected 3 tab-separated fields): {line!r}")
        story_id, verdict, name = parts
        stories[story_id] = {"verdict": verdict, "name": name}

    doc = {
        "version": 1,
        "distro_id": os.environ["EV_DISTRO_ID"],
        "release": os.environ["EV_RELEASE"],
        "surface": os.environ["EV_SURFACE"],
        "cassette_mode": os.environ["EV_CASSETTE_MODE"],
        "cassette_sha256": os.environ["EV_CASSETTE_SHA"] or None,
        # Recorded so a replay the harness declared unproven cannot later back a
        # published figure. The artifact used to be written before this audit ran.
        "cassette_audit": {
            "served": int(os.environ["EV_CASSETTE_HITS"]),
            "misses": int(os.environ["EV_CASSETTE_MISSES"]),
            "verdict": os.environ["EV_CASSETTE_VERDICT"],
        },
        "story_set": os.environ["EV_STORY_SET"],
        "ran_at": os.environ["EV_RAN_AT"],
        "totals": {
            "total": int(os.environ["EV_TOTAL"]),
            "passed": int(os.environ["EV_PASSED"]),
            "failed": int(os.environ["EV_FAILED"]),
            "skipped": int(os.environ["EV_SKIPPED"]),
            "rate_limited": int(os.environ["EV_RATELIMITED"]),
        },
        "stories": stories,
    }

    # A row count that disagrees with the totals means the caller lost a result on
    # the way here, and the totals are what a published figure would cite.
    if len(stories) != doc["totals"]["total"]:
        sys.exit(
            "story rows (%d) do not match the recorded total (%d)"
            % (len(stories), doc["totals"]["total"])
        )

    with open(os.environ["EV_PATH"], "w") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
