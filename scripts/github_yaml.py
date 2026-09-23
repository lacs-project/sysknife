#!/usr/bin/env python3
"""Discover workflow and local action metadata for the GitHub YAML gates."""

import argparse
import os
from pathlib import Path
import re
import sys


def discover(workflows, actions=None, templates=None):
    files = sorted(p for p in workflows.iterdir() if p.suffix in (".yml", ".yaml"))
    if not files:
        raise ValueError(f"no workflow files matched under {workflows}")
    if actions is not None and actions.exists():
        found = []

        def failed(error):
            raise error

        for directory, directories, names in os.walk(actions, onerror=failed):
            for name in directories:
                path = Path(directory) / name
                if path.is_symlink():
                    raise ValueError(f"cannot scan symlinked action directory {path}")
            found.extend(Path(directory) / name for name in names + directories
                         if name in ("action.yml", "action.yaml"))
        if not found:
            raise ValueError(f"no action metadata files matched under {actions}")
        files.extend(sorted(found))
    if templates is not None:
        found = sorted(p for p in templates.iterdir() if p.suffix in (".yml", ".yaml"))
        if not found:
            raise ValueError(f"no issue templates matched under {templates}")
        files.extend(found)
    return files


def check_local(reference):
    """Refuse a local `uses:` that points outside what discover() scans."""
    path = os.path.normpath(reference)
    if path == ".github/actions" or path.startswith(".github/actions/"):
        return
    if re.fullmatch(r"\.github/workflows/[^/]+\.ya?ml", path):
        return
    raise ValueError(f"local action outside .github/actions is never scanned: {reference}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflows", type=Path)
    parser.add_argument("actions", nargs="?", type=Path)
    parser.add_argument("--templates", type=Path)
    args = parser.parse_args()
    try:
        paths = discover(args.workflows, args.actions, args.templates)
        # Check before emitting so an unreadable input cannot yield a partial list.
        for path in paths:
            path.read_text(encoding="utf-8")
        sys.stdout.buffer.write(b"".join(os.fsencode(path) + b"\0" for path in paths))
    except (OSError, UnicodeError, ValueError) as error:
        sys.exit(f"FAIL: {error}")
