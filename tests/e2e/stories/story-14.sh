#!/usr/bin/env bash
# Story 14: Triple compound read-only (disk + memory + services)
# Intent: "I want to check disk usage, memory pressure, and see which services are active"
# Pass criteria:
#   - Plan has exactly 3 steps
#   - Steps contain GetDiskUsage, GetMemoryInfo, and ListServices (any order)
#   - All steps have risk_level low
#
# This is a difficult story because the model must handle three independent
# read-only intents in a single request and NOT call any query_* tools first.
# A common failure mode is querying state before proposing the triple plan.
set -euo pipefail

INTENT="I want to check disk usage, memory pressure, and see which services are active"

echo "=== Story 14: Triple compound — disk + memory + services ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-14-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "3" ]]; then
  echo "FAIL: expected 3 steps, got $STEP_COUNT"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "GetDiskUsage"; then
  echo "FAIL: GetDiskUsage not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "GetMemoryInfo"; then
  echo "FAIL: GetMemoryInfo not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "ListServices"; then
  echo "FAIL: ListServices not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

# All steps must be low risk.
RISKS=$(echo "$PLAN" | jq -r '.plan.steps[].risk')
while IFS= read -r risk; do
  if [[ "$risk" != "low" ]]; then
    echo "FAIL: expected all steps low risk, got '$risk'"
    exit 1
  fi
done <<< "$RISKS"

echo "PASS: Story 14 — plan has GetDiskUsage + GetMemoryInfo + ListServices, all low risk"
