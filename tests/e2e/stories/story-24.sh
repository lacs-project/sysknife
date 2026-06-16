#!/usr/bin/env bash
# Story 24 (destructive): StopService — stop the cups service
# Intent: "stop the cups printing service"
# Pass criteria:
#   - Plan contains StopService (model may add a preliminary ListServices or
#     GetServiceLogs step, which is acceptable)
#   - params.unit matches "cups" or "cups.service"
#   - StopService risk medium
#
# Story 18 covers RestartService. This story specifically tests StopService,
# verifying the model does not conflate "stop" with "restart".
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="stop the cups printing service"

echo "=== Story 24: StopService — cups ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-24-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# Must not plan a Restart when the user asked to Stop.
if echo "$ACTIONS" | grep -q "RestartService"; then
  echo "FAIL: model proposed RestartService but intent says stop"
  echo "Actions: $ACTIONS"
  exit 1
fi

STOP_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "StopService")')
if [[ -z "$STOP_STEP" || "$STOP_STEP" == "null" ]]; then
  echo "FAIL: no StopService step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

UNIT=$(echo "$STOP_STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "cups" && "$UNIT" != "cups.service" ]]; then
  echo "FAIL: expected unit=cups or cups.service, got '$UNIT'"
  echo "Full params: $(echo "$STOP_STEP" | jq '.params')"
  exit 1
fi

RISK=$(echo "$STOP_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected StopService risk medium, got $RISK"
  exit 1
fi

echo "PASS: Story 24 — plan has StopService(unit=$UNIT) with medium risk"
