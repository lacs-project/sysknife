#!/usr/bin/env bash
# Story 22: ListProcesses direct request
# Intent: "show me all running processes"
# Pass criteria:
#   - Plan has exactly 1 step: ListProcesses
#   - risk low
#
# Closes coverage gap: the processes domain was untested in stories 1-20.
set -euo pipefail

INTENT="show me all running processes"

echo "=== Story 22: ListProcesses ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-22-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then
  echo "FAIL: expected 1 step, got $STEP_COUNT"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "ListProcesses" ]]; then
  echo "FAIL: expected ListProcesses, got $ACTION"
  exit 1
fi

RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low, got $RISK"
  exit 1
fi

echo "PASS: Story 22 — plan has 1 ListProcesses step with low risk"
