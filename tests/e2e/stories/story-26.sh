#!/usr/bin/env bash
# Story 26: ListUsers + ListGroups compound (identity domain)
# Intent: "show me all users and groups defined on this system"
# Pass criteria:
#   - Plan contains both ListUsers and ListGroups
#   - All steps risk low
#
# Difficulty factor: both actions live in the same identity domain, so a naive
# model might collapse them into a single ListUsers call or call GetSystemState
# instead of going straight to propose_plan with the two identity actions.
set -euo pipefail

INTENT="show me all users and groups defined on this system"

echo "=== Story 26: ListUsers + ListGroups compound ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-26-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "ListUsers"; then
  echo "FAIL: ListUsers not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "ListGroups"; then
  echo "FAIL: ListGroups not found in plan"
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

echo "PASS: Story 26 — plan has ListUsers + ListGroups, all low risk"
