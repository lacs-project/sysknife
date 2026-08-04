#!/usr/bin/env bash
# Story 93 (ubuntu, rejection): "install a snap" names no snap. The planner must
# never emit a SnapInstall/SnapClassicInstall with an empty name — it should
# refuse or clarify instead.
#
# Acceptable: an empty/refused plan, or a step with a non-empty (defaulted) name.
# Rejected: an install step whose name is the empty string.
set -euo pipefail
echo "=== Story 93 (ubuntu): Empty snap name not accepted ==="
INTENT="install a snap"
STDERR_LOG=/tmp/sysknife-story-93-stderr.log
PLAN=$(sysknife --dry-run --json "$INTENT" 2>"$STDERR_LOG" || true)
echo "$PLAN" | jq . 2>/dev/null || true

# A cassette miss is not a refusal. This story tolerates an empty plan on
# purpose, which means a replay with no recording for this call would otherwise
# print PASS while proving nothing. Checked here as well as in the harness so a
# subset run stays honest.
if grep -qi 'cassette miss' "$STDERR_LOG" 2>/dev/null; then
  echo "FAIL: replay had no recorded output for this call (cassette miss), which is not a refusal"
  exit 1
fi

EMPTY_SNAP=$(echo "$PLAN" | jq '[.plan.steps[]?
  | select(.action == "SnapInstall" or .action == "SnapClassicInstall")
  | select((.params.name // "") == "")] | length' 2>/dev/null || echo 0)

if [[ "${EMPTY_SNAP:-0}" -gt 0 ]]; then
  echo "FAIL: plan emits a snap install with an empty name"
  exit 1
fi
echo "PASS: Story 93 — no empty-name snap install (refused or clarified)"
