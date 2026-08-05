#!/usr/bin/env python3
"""Read or update one suite's count in the test-baseline evidence artifact.

Split out of test_baseline.sh because the artifact has to be *merged*, not
rewritten: the Rust and frontend counts are produced by different commands in
different CI jobs, so whichever runs second must leave the other's measurement
alone. Doing that in shell means hand-rolled JSON editing, which is how a
measurement gets replaced by a guess.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

COMMANDS = {
    "tests": "cargo nextest run --workspace --locked",
    "frontend_tests": "vitest run (apps/sysknife-shell)",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--field", required=True, choices=sorted(COMMANDS))
    parser.add_argument("--count", type=int)
    parser.add_argument("--commit")
    parser.add_argument(
        "--read",
        action="store_true",
        help="print the recorded count and exit; nothing is written",
    )
    args = parser.parse_args()

    doc: dict = {}
    if args.artifact.exists():
        doc = json.loads(args.artifact.read_text())

    if args.read:
        value = doc.get(args.field)
        if value is None:
            return 1
        print(value)
        return 0

    if args.count is None:
        parser.error("--count is required unless --read is given")

    doc["version"] = 1
    doc[args.field] = args.count
    doc.setdefault("commands", {})[args.field] = COMMANDS[args.field]
    # Recorded per field: one suite's figure can be fresh while the other is
    # stale, and a single timestamp would hide that.
    doc.setdefault("measured_at", {})[args.field] = subprocess.run(
        ["date", "--iso-8601=seconds"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    doc.setdefault("commit", {})[args.field] = args.commit or "unknown"

    args.artifact.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
