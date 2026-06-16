#!/usr/bin/env bash
# Story 1: Check disk usage
# Intent: "show me disk usage for all mounted filesystems"
# Pass criteria:
#   - Plan has exactly 1 step, GetDiskUsage, risk low, approvalRequired false
#   - (Execution output would contain /dev/ lines — tested via daemon, not here)
set -euo pipefail

INTENT="show me disk usage for all mounted filesystems"

echo "=== Story 1: Check disk usage ==="
echo "Intent: $INTENT"

# Get the plan from the LLM.
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-1-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

# 1. Exactly 1 step.
STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then
  echo "FAIL: expected 1 step, got $STEP_COUNT"
  exit 1
fi

# 2. Step action_name is GetDiskUsage.
ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "GetDiskUsage" ]]; then
  echo "FAIL: expected GetDiskUsage, got $ACTION"
  exit 1
fi

# 3. Risk level is low.
RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low, got $RISK"
  exit 1
fi

echo "PASS: Story 1 — plan has 1 GetDiskUsage step with low risk"
