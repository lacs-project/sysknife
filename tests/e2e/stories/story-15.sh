#!/usr/bin/env bash
# Story 15: Rollback history (history path with action filter)
# Intent: "show me all rollback operations SysKnife has performed"
# Pass criteria:
#   - Plan has exactly 1 step: ListJobHistory
#   - risk_level low
#
# This story exercises the query_job_history path with an action_filter.
# The model must NOT use query_deployments or get_system_state — those show
# current system state, not SysKnife transaction history. The correct path is:
#   query_job_history(action_filter: "RollbackDeployment") → ListJobHistory.
#
# Whether the history is empty or not, the model must still propose
# ListJobHistory so the user sees the (possibly empty) log.
set -euo pipefail

INTENT="show me all rollback operations SysKnife has performed"

echo "=== Story 15: Rollback history ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-15-stderr.log)
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
  echo "NOTE: do NOT use query_deployments or get_system_state for SysKnife history"
  exit 1
fi

RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low, got $RISK"
  exit 1
fi

echo "PASS: Story 15 — plan has 1 ListJobHistory step with low risk"
