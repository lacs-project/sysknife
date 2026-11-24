#!/usr/bin/env bash
# Story 155 (ubuntu, low-risk, read-only): Ubuntu Pro package origins and security updates
# Intent: "how exposed is this Ubuntu Pro host to security updates?"
# Distro: ubuntu
# ProSecurityStatus answers both halves from the Pro API. This read-only query
# must not choose an upgrade or a detach action.
set -euo pipefail
INTENT="how exposed is this Ubuntu Pro host to security updates?"
echo "=== Story 155 (ubuntu): ProSecurityStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-155-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "ProSecurityStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected ProSecurityStatus"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAM_COUNT=$(echo "$STEP" | jq '.params // {} | length')
if [[ "$PARAM_COUNT" != "0" ]]; then echo "FAIL: expected no parameters, got $PARAM_COUNT"; exit 1; fi
for FORBIDDEN in AptUpgrade ProDetach; do
  if echo "$PLAN" | jq -e --arg a "$FORBIDDEN" '.plan.steps[] | select(.action == $a)' >/dev/null; then
    echo "FAIL: plan contains $FORBIDDEN instead of a read-only status query"; exit 1
  fi
done
echo "PASS: Story 155"
