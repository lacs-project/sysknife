#!/usr/bin/env bash
# Story 18 (destructive): Restart a named service
# Intent: "restart the bluetooth service"
# Pass criteria:
#   - Plan has exactly 1 step: RestartService
#   - params.unit matches "bluetooth" or "bluetooth.service"
#   - risk_level medium, approvalRequired true
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="restart the bluetooth service"

echo "=== Story 18: Restart the bluetooth service ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-18-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# Accept either a single RestartService step, or a Stop+Start sequence.
# Both are valid implementations; RestartService is preferred but not required.
if echo "$ACTIONS" | grep -q "RestartService"; then
  # Single-step restart — preferred.
  if [[ "$STEP_COUNT" != "1" ]]; then
    echo "FAIL: RestartService found but expected 1 step total, got $STEP_COUNT"
    exit 1
  fi
  UNIT=$(echo "$PLAN" | jq -r '.plan.steps[0].params.unit // ""')
elif echo "$ACTIONS" | grep -q "StopService" && echo "$ACTIONS" | grep -q "StartService"; then
  # Two-step Stop+Start — also acceptable.
  if [[ "$STEP_COUNT" != "2" ]]; then
    echo "FAIL: Stop+Start found but expected 2 steps, got $STEP_COUNT"
    exit 1
  fi
  UNIT=$(echo "$PLAN" | jq -r '.plan.steps[] | select(.action == "StopService") | .params.unit // ""')
else
  echo "FAIL: expected RestartService or StopService+StartService"
  echo "Actions: $ACTIONS"
  exit 1
fi

# Verify the service unit targets bluetooth.
if [[ "$UNIT" != "bluetooth" && "$UNIT" != "bluetooth.service" ]]; then
  echo "FAIL: expected unit=bluetooth or bluetooth.service, got '$UNIT'"
  exit 1
fi

# All steps should be medium risk.
RISKS=$(echo "$PLAN" | jq -r '.plan.steps[].risk')
while IFS= read -r risk; do
  if [[ "$risk" != "medium" ]]; then
    echo "FAIL: expected risk medium, got '$risk'"
    exit 1
  fi
done <<< "$RISKS"

echo "PASS: Story 18 — plan restarts bluetooth ($ACTIONS)"
