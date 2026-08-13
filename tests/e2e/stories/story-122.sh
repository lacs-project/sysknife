#!/usr/bin/env bash
# Story 122 (ubuntu, medium-risk): Revert a snap
# Intent: "roll the firefox snap back to its previous revision"
# Distro: ubuntu
set -euo pipefail
INTENT="roll the firefox snap back to its previous revision"
echo "=== Story 122 (ubuntu): SnapRevert ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-122-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapRevert")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapRevert step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "firefox" ]]; then echo "FAIL: expected name=firefox, got $NAME"; exit 1; fi
echo "PASS: Story 122"
