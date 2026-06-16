#!/usr/bin/env bash
# Story 21: GetSystemState direct request
# Intent: "what operating system and hardware am I running on?"
# Pass criteria:
#   - Plan contains GetSystemState
#   - risk low
#
# Difficulty factor: "what am I running on" is vague enough that a naive model
# might want to query_* first. The correct response is to go straight to
# GetSystemState — it IS the state query.
set -euo pipefail

INTENT="what operating system and hardware am I running on?"

echo "=== Story 21: GetSystemState direct request ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-21-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "GetSystemState"; then
  echo "FAIL: GetSystemState not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

GET_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetSystemState")')
RISK=$(echo "$GET_STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected GetSystemState risk low, got $RISK"
  exit 1
fi

echo "PASS: Story 21 — plan has GetSystemState with low risk"
