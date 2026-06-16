#!/usr/bin/env bash
# Story 25: ListUsers direct request (identity domain coverage)
# Intent: "show me all local user accounts on this system"
# Pass criteria:
#   - Plan contains ListUsers
#   - risk low
#
# Closes coverage gap: the user/group identity domain was untested for read-only
# operations in stories 1-20 (story 20 only covered AddUserToGroup, destructive).
set -euo pipefail

INTENT="show me all local user accounts on this system"

echo "=== Story 25: ListUsers ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-25-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "ListUsers"; then
  echo "FAIL: ListUsers not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

LIST_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ListUsers")')
RISK=$(echo "$LIST_STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected ListUsers risk low, got $RISK"
  exit 1
fi

echo "PASS: Story 25 — plan has ListUsers with low risk"
