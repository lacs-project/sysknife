#!/usr/bin/env bash
# Story 137 (ubuntu, high-risk): Enable the sshd fail2ban jail
# Intent: "enable the sshd jail in fail2ban"
# Distro: ubuntu
set -euo pipefail
INTENT="enable the sshd jail in fail2ban"
echo "=== Story 137 (ubuntu): ConfigureFail2banJail ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-137-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "ConfigureFail2banJail")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected ConfigureFail2banJail"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "sshd" ]]; then echo "FAIL: expected name=sshd, got $NAME"; exit 1; fi
if ! echo "$STEP" | jq -e '.params.enabled == true' >/dev/null; then
  echo "FAIL: expected enabled=true, got $(echo "$STEP" | jq -c '.params.enabled // null')"; exit 1
fi
echo "PASS: Story 137"
