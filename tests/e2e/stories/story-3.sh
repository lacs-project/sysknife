#!/usr/bin/env bash
# Story 3: Service health check
# Intent: "is sshd running? show me its recent logs"
# Pass criteria:
#   - Plan includes GetServiceLogs with unit parameter set to sshd.service or sshd
set -euo pipefail

INTENT="is sshd running? show me its recent logs"

echo "=== Story 3: Service health check ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-3-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

# 1. At least one step with GetServiceLogs.
HAS_LOGS=$(echo "$PLAN" | jq '[.plan.steps[] | select(.action == "GetServiceLogs")] | length')
if [[ "$HAS_LOGS" == "0" ]]; then
  echo "FAIL: no GetServiceLogs step found"
  echo "Actions present: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

# 2. The GetServiceLogs step has a unit param mentioning sshd.
UNIT_PARAM=$(echo "$PLAN" | jq -r '
  .plan.steps[] | select(.action == "GetServiceLogs") |
  .params.unit // .params.service // .params.name // ""
')
if [[ "$UNIT_PARAM" != *"sshd"* ]]; then
  echo "FAIL: GetServiceLogs unit parameter does not contain 'sshd', got: '$UNIT_PARAM'"
  # Check if it is in a nested structure.
  FULL_PARAMS=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetServiceLogs") | .params')
  echo "Full params: $FULL_PARAMS"
  exit 1
fi

echo "PASS: Story 3 — plan includes GetServiceLogs for sshd"
