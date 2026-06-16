#!/usr/bin/env bash
# Story 5: List layered packages
# Intent: "what packages have I layered on top of the base system?"
# Pass criteria:
#   - Plan has 1 step, GetLayeredPackages
set -euo pipefail

INTENT="what packages have I layered on top of the base system?"

echo "=== Story 5: List layered packages ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-5-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then
  echo "FAIL: expected 1 step, got $STEP_COUNT"
  exit 1
fi

ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "GetLayeredPackages" && "$ACTION" != "AptListInstalled" ]]; then
  echo "FAIL: expected GetLayeredPackages or AptListInstalled, got $ACTION"
  exit 1
fi

echo "PASS: Story 5 — plan has 1 ${ACTION} step"
