#!/usr/bin/env bash
# Story 12: SysKnife activity log — today (history path)
# Intent: "show me the SysKnife activity log for today"
# Pass criteria:
#   - Plan has exactly 1 step: ListJobHistory
#   - risk_level low
#
# This story exercises Example C from the system prompt: the model must use
# query_job_history (a planning tool) to consult transaction history, then
# call propose_plan with ListJobHistory rather than GetSystemState or any
# state-inspection action.
set -euo pipefail

INTENT="show me the SysKnife activity log for today"

echo "=== Story 12: SysKnife activity log — today ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-12-stderr.log)
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
if [[ "$ACTION" != "ListJobHistory" ]]; then
  echo "FAIL: expected ListJobHistory, got $ACTION"
  echo "NOTE: model must use query_job_history to check history, then propose ListJobHistory"
  exit 1
fi

RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low, got $RISK"
  exit 1
fi

echo "PASS: Story 12 — plan has 1 ListJobHistory step with low risk"
