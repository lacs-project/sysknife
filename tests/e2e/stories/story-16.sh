#!/usr/bin/env bash
# Story 16: Network status + firewall (compound read-only)
# Intent: "show me the network status and the current firewall rules"
# Pass criteria:
#   - Plan has exactly 2 steps
#   - Steps contain both GetNetworkStatus and GetFirewallState (any order)
#   - All steps have risk_level low
#
# This story enforces the rule: query errors during planning must NEVER cause
# the model to silently drop a plan action the user explicitly requested.
# The model must propose both actions regardless of what query tools return.
set -euo pipefail

INTENT="show me the network status and the current firewall rules"

echo "=== Story 16: Network status + firewall rules ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-16-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "GetNetworkStatus"; then
  echo "FAIL: GetNetworkStatus not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -qE "GetFirewallState|UfwStatus"; then
  echo "FAIL: GetFirewallState (Fedora) or UfwStatus (Ubuntu) not found in plan — query errors must not drop requested actions"
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

echo "PASS: Story 16 — plan has GetNetworkStatus + firewall action, all low risk"
