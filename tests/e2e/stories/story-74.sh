#!/usr/bin/env bash
# Story 74 (ubuntu, high-risk): Enable ufw
# Intent: "turn on the ufw firewall"
# Distro: ubuntu
set -euo pipefail
INTENT="turn on the ufw firewall"
echo "=== Story 74 (ubuntu): Enable ufw ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-74-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwEnable")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwEnable step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
echo "PASS: Story 74"
