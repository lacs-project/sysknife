#!/usr/bin/env bash
# Story 83 (ubuntu, read-only): Get netplan config
# Intent: "show me the netplan network configuration"
# Distro: ubuntu
set -euo pipefail
INTENT="show me the netplan network configuration"
echo "=== Story 83 (ubuntu): Get netplan config ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-83-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "NetplanGetConfig")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no NetplanGetConfig step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 83"
