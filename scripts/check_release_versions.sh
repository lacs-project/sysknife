#!/usr/bin/env bash
# Every place the release version lives must agree, and must match the tag.
#
# Where those places ARE is declared once, in release-versions.json and read
# by scripts/release_versions.py. The checker validates all registered manifests,
# JSON sites, generated workspace lockfiles and the latest changelog heading.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected="${1:-}"
expected="${expected#v}"

python3 "$repo_root/scripts/release_versions.py" check "$expected"
