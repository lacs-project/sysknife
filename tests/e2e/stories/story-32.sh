#!/usr/bin/env bash
# Story 32: SSH + identity security audit compound (3 read-only)
# Intent: "security audit: show me root's authorized SSH keys, all local users, and all groups"
# Pass criteria:
#   - Plan contains GetAuthorizedKeys, ListUsers, and ListGroups
#   - All steps risk low
#
# Difficulty factors:
#   - "security audit" framing is the strongest lure toward get_system_state in
#     the entire story suite — this is specifically calibrated to test that.
#   - Three actions from the identity+SSH domain that a naive model collapses
#     into a single GetSystemState.
#   - GetAuthorizedKeys requires a username param; "root" is named explicitly so
#     the model can call it without inventing a query step.
#   - All three are independently low-risk reads; none justify a query step.
set -euo pipefail

INTENT="security audit: show me root's authorized SSH keys, all local users, and all groups"

echo "=== Story 32: Security audit — GetAuthorizedKeys + ListUsers + ListGroups ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-32-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "GetAuthorizedKeys"; then
  echo "FAIL: GetAuthorizedKeys not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

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

echo "PASS: Story 32 — security audit: GetAuthorizedKeys + ListUsers + ListGroups, all low risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
