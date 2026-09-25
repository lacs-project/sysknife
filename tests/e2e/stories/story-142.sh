#!/usr/bin/env bash
# Story 142 (ubuntu, medium-risk): Enable NTP time synchronisation
# Intent: "enable NTP time synchronisation on this machine"
# Distro: ubuntu
# The near miss is GetDateTime, which answers "is NTP enabled?" without changing
# anything. An imperative "enable NTP" must plan the mutating SetNtp step.
set -euo pipefail
INTENT="enable NTP time synchronisation on this machine"
echo "=== Story 142 (ubuntu): SetNtp ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-142-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "SetNtp")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected SetNtp"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
if ! echo "$STEP" | jq -e '.params.enabled == true' >/dev/null; then
  echo "FAIL: expected enabled=true, got $(echo "$STEP" | jq -c '.params.enabled // null')"; exit 1
fi
echo "PASS: Story 142"
