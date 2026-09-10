#!/usr/bin/env bash
# Story 134 (ubuntu, read-only): Active fail2ban jail status
# Intent: "show me which fail2ban jails are active"
# Distro: ubuntu
set -euo pipefail
INTENT="show me which fail2ban jails are active"
echo "=== Story 134 (ubuntu): Fail2banStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-134-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "Fail2banStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected Fail2banStatus"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAMS=$(echo "$STEP" | jq -c '.params')
if [[ "$PARAMS" != "{}" ]]; then echo "FAIL: expected no jail parameter, got $PARAMS"; exit 1; fi
echo "PASS: Story 134"
