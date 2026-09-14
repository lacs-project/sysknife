#!/usr/bin/env python3
"""Read or update one suite's count in the test-baseline evidence artifact.

The artifact is deliberately count-only. The wrapper that calls this module
measures the working tree, while a commit SHA would describe neither a dirty
working tree nor a squash-merged contributor tree. The Rust and frontend counts
are still merged one field at a time because they come from different commands
and CI jobs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

VERSION = 2
COMMANDS = {
    "tests": "cargo nextest run --workspace --locked",
    "frontend_tests": "vitest run (apps/sysknife-shell)",
}
SUITE_FIELDS = tuple(COMMANDS)
ALLOWED_KEYS = frozenset(("commands", "version", *SUITE_FIELDS))
LEGACY_KEYS = ALLOWED_KEYS | {"commit", "measured_at"}


def validate_document(document: object, *, require_all_fields: bool) -> list[str]:
    """Return schema errors for a baseline document.

    A partial document is valid while the two independent recorders are being
    run. The committed evidence artifact must contain both suite counts.
    """
    if not isinstance(document, dict):
        return ["artifact root must be a JSON object"]

    problems: list[str] = []
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        problems.append(f"unsupported artifact version {version!r}; expected {VERSION}")

    unknown = sorted(str(key) for key in set(document) - ALLOWED_KEYS)
    if unknown:
        problems.append(
            "unsupported top-level fields: "
            + ", ".join(unknown)
            + "; schema 2 stores counts only"
        )

    commands = document.get("commands")
    if not isinstance(commands, dict):
        problems.append("commands must be an object")
    else:
        unknown_commands = sorted(str(key) for key in set(commands) - set(COMMANDS))
        if unknown_commands:
            problems.append(
                "unsupported command fields: " + ", ".join(unknown_commands)
            )
        for field, expected in COMMANDS.items():
            if field not in commands:
                if require_all_fields:
                    problems.append(f"commands is missing '{field}'")
            elif commands[field] != expected:
                problems.append(f"commands['{field}'] does not match the recorder")

    for field in SUITE_FIELDS:
        if field not in document:
            if require_all_fields:
                problems.append(f"artifact is missing '{field}'")
            continue
        value = document[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(f"'{field}' must be a non-negative integer")

    return problems


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not readable JSON: {exc}") from exc


def load_document(path: Path, *, migrate_legacy: bool) -> dict:
    if not path.exists():
        return {}

    document = _load_json(path)
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain a JSON object")

    version = document.get("version")
    if (
        migrate_legacy
        and isinstance(version, int)
        and not isinstance(version, bool)
        and version == 1
    ):
        unknown = sorted(str(key) for key in set(document) - LEGACY_KEYS)
        if unknown:
            raise ValueError(
                f"{path} has unsupported legacy fields: {', '.join(unknown)}"
            )
        document = {
            key: value
            for key, value in document.items()
            if key in ALLOWED_KEYS
        }
        document["version"] = VERSION

    problems = validate_document(document, require_all_fields=False)
    if problems:
        raise ValueError(f"{path} is invalid: {'; '.join(problems)}")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--field", required=True, choices=sorted(COMMANDS))
    parser.add_argument("--count", type=int)
    parser.add_argument(
        "--read",
        action="store_true",
        help="print the recorded count and exit; nothing is written",
    )
    args = parser.parse_args()

    try:
        doc = load_document(args.artifact, migrate_legacy=not args.read)
    except (OSError, ValueError) as exc:
        print(f"record_test_baseline: {exc}", file=sys.stderr)
        return 1

    if args.read:
        value = doc.get(args.field)
        if not isinstance(value, int) or isinstance(value, bool):
            return 1
        print(value)
        return 0

    if args.count is None:
        parser.error("--count is required unless --read is given")
    if args.count < 0:
        parser.error("--count must be non-negative")

    doc["version"] = VERSION
    doc[args.field] = args.count
    doc.setdefault("commands", {})[args.field] = COMMANDS[args.field]
    problems = validate_document(doc, require_all_fields=False)
    if problems:
        print(
            f"record_test_baseline: generated artifact is invalid: {'; '.join(problems)}",
            file=sys.stderr,
        )
        return 1

    args.artifact.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
