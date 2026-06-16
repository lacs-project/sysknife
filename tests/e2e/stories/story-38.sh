#!/usr/bin/env bash
# Story 38: 3-domain diagnostic compound under failure framing
# Intent: "nginx is unresponsive — show me running processes, nginx service logs, and what SysKnife did recently"
# Pass criteria:
#   - Plan contains ListProcesses, GetServiceLogs, and ListJobHistory
#   - GetServiceLogs params.unit matches "nginx" or "nginx.service"
#   - All steps risk low
#
# Difficulty factors:
#   - "nginx is unresponsive" is a failure statement — the strongest possible
#     lure to call get_system_state or query_system before planning. The model
#     must see "show me X, Y, Z" and go straight to propose_plan with all three.
#   - Three actions from three different domains: processes, services, job history.
#   - GetServiceLogs requires a unit param extracted from "nginx service logs".
#   - Model must not conflate "what SysKnife did recently" with GetSystemState —
#     that maps to ListJobHistory (SysKnife transaction history, not system state).
set -euo pipefail

INTENT="nginx is unresponsive — show me running processes, nginx service logs, and what SysKnife did recently"

echo "=== Story 38: ListProcesses + GetServiceLogs(nginx) + ListJobHistory ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-38-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "ListProcesses"; then
  echo "FAIL: ListProcesses not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

LOGS_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetServiceLogs")')
if [[ -z "$LOGS_STEP" || "$LOGS_STEP" == "null" ]]; then
  echo "FAIL: GetServiceLogs not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

UNIT=$(echo "$LOGS_STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "nginx" && "$UNIT" != "nginx.service" ]]; then
  echo "FAIL: expected GetServiceLogs unit=nginx or nginx.service, got '$UNIT'"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "ListJobHistory"; then
  echo "FAIL: ListJobHistory not found — 'what SysKnife did recently' maps to job history, not system state"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISKS=$(echo "$PLAN" | jq -r '.plan.steps[].risk')
while IFS= read -r risk; do
  if [[ "$risk" != "low" ]]; then
    echo "FAIL: expected all steps low risk, got '$risk'"
    exit 1
  fi
done <<< "$RISKS"

echo "PASS: Story 38 — plan has ListProcesses + GetServiceLogs(nginx) + ListJobHistory, all low risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
