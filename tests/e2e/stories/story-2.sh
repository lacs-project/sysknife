#!/usr/bin/env bash
# Story 2: Memory pressure diagnosis
# Intent: "is the system low on memory? show me what's using it"
# Pass criteria:
#   - Plan has 2 steps, both risk low
#   - One step is GetMemoryInfo, one is ListProcesses
set -euo pipefail

INTENT="is the system low on memory? show me what's using it"

echo "=== Story 2: Memory pressure diagnosis ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-2-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

# 1. Exactly 2 steps.
STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "2" ]]; then
  echo "FAIL: expected 2 steps, got $STEP_COUNT"
  exit 1
fi

# 2. Both steps are low risk.
RISK_0=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
RISK_1=$(echo "$PLAN" | jq -r '.plan.steps[1].risk')
if [[ "$RISK_0" != "low" ]] || [[ "$RISK_1" != "low" ]]; then
  echo "FAIL: expected both steps low risk, got $RISK_0 and $RISK_1"
  exit 1
fi

# 3. Contains GetMemoryInfo and ListProcesses (in either order).
ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action' | sort)
EXPECTED=$'GetMemoryInfo\nListProcesses'
if [[ "$ACTIONS" != "$EXPECTED" ]]; then
  echo "FAIL: expected GetMemoryInfo + ListProcesses, got:"
  echo "$ACTIONS"
  exit 1
fi

echo "PASS: Story 2 — plan has GetMemoryInfo + ListProcesses, both low risk"
