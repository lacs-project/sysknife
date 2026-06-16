#!/usr/bin/env bash
# Story 84 (ubuntu, high-risk): Apply netplan config
# Intent: "apply the netplan network configuration"
# Distro: ubuntu
set -euo pipefail
INTENT="apply the netplan network configuration"
echo "=== Story 84 (ubuntu): Apply netplan config ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-84-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "NetplanApply")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no NetplanApply step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
echo "PASS: Story 84"
