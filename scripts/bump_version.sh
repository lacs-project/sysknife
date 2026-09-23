#!/usr/bin/env bash
# Write one release version everywhere it belongs, then prove it landed.
#
#   scripts/bump_version.sh 0.18.0 [--date YYYY-MM-DD]
#
# The sites are declared in release-versions.json and written by
# scripts/release_versions.py, which scripts/check_release_versions.sh reads
# from as well. Nothing here knows a filename, so adding a crate means editing
# the registry and nothing else.
#
# Cargo.lock is never edited as text. cargo regenerates it, and the writer
# refuses if any package outside the workspace moved: a global substitution
# rewrites third-party crates that happen to share the version string.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ $# -lt 1 ]; then
    printf 'usage: %s <version> [--date YYYY-MM-DD]\n' "${0##*/}" >&2
    exit 64
fi

python3 "$repo_root/scripts/release_versions.py" bump "$@"

# The checker is the authority on whether this worked, so ask it rather than
# reporting success from the writer's own point of view.
bash "$repo_root/scripts/check_release_versions.sh" "${1#v}"
