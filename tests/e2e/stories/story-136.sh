#!/usr/bin/env bash
# Story 136 (ubuntu, high-risk): Ban a documented IP in sshd
# Intent: "ban 203.0.113.7 in the sshd fail2ban jail"
# Distro: ubuntu
set -euo pipefail
INTENT="ban 203.0.113.7 in the sshd fail2ban jail"
echo "=== Story 136 (ubuntu): Fail2banBanIp ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-136-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "Fail2banBanIp")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected Fail2banBanIp"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
JAIL=$(echo "$STEP" | jq -r '.params.jail // ""')
if [[ "$JAIL" != "sshd" ]]; then echo "FAIL: expected jail=sshd, got $JAIL"; exit 1; fi
IP=$(echo "$STEP" | jq -r '.params.ip // ""')
if [[ "$IP" != "203.0.113.7" ]]; then echo "FAIL: expected ip=203.0.113.7, got $IP"; exit 1; fi
echo "PASS: Story 136"
