#!/usr/bin/env bash
set -euo pipefail
root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
manifest="$(mktemp)"
trap 'rm -f "$manifest"' EXIT
python3 "$(dirname "${BASH_SOURCE[0]}")/github_yaml.py" \
    "$root/.github/workflows" "$root/.github/actions" \
    --templates "$root/.github/ISSUE_TEMPLATE" > "$manifest"
mapfile -d '' -t files < "$manifest"
yamllint "${files[@]}"
