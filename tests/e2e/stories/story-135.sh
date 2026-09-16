#!/usr/bin/env bash
# Story 135 (ubuntu, medium-risk): Unban a documented IP from sshd
# Intent: "unban 203.0.113.7 from the sshd fail2ban jail"
# Distro: ubuntu
set -euo pipefail
INTENT="unban 203.0.113.7 from the sshd fail2ban jail"
echo "=== Story 135 (ubuntu): Fail2banUnbanIp ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-135-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "Fail2banUnbanIp")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected Fail2banUnbanIp"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
JAIL=$(echo "$STEP" | jq -r '.params.jail // ""')
if [[ "$JAIL" != "sshd" ]]; then echo "FAIL: expected jail=sshd, got $JAIL"; exit 1; fi
IP=$(echo "$STEP" | jq -r '.params.ip // ""')
if [[ "$IP" != "203.0.113.7" ]]; then echo "FAIL: expected ip=203.0.113.7, got $IP"; exit 1; fi
echo "PASS: Story 135"
