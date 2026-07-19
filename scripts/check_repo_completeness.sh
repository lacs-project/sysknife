#!/usr/bin/env bash
set -euo pipefail

required=(
  "LICENSE"
  "README.md"
  "CONTRIBUTING.md"
  "SECURITY.md"
  "CODE_OF_CONDUCT.md"
  "ROADMAP.md"
  "docs/architecture.md"
  "docs/developer-guide.md"
  "docs/distro-support.md"
  "docs/release.md"
  "docs/release-readiness.md"
  "docs/storage-cloud.md"
  "docs/adr/0001-system-boundaries.md"
  ".github/PULL_REQUEST_TEMPLATE.md"
  ".github/ISSUE_TEMPLATE/bug_report.yml"
  ".github/ISSUE_TEMPLATE/feature_request.yml"
  ".github/workflows/ci.yml"
  ".github/workflows/e2e.yml"
  ".github/workflows/release-rehearsal.yml"
)

missing=()
for path in "${required[@]}"; do
  if [[ ! -e "$path" ]]; then
    missing+=("$path")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'Missing required files:\n' >&2
  printf ' - %s\n' "${missing[@]}" >&2
  exit 1
fi
