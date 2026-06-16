#!/usr/bin/env bash
# Story 104 (ubuntu, high-risk): Apply netplan after showing config
# Intent: "show me the network config and then apply it"
# Distro: ubuntu
set -euo pipefail
INTENT="show me the network config and then apply it"
echo "=== Story 104 (ubuntu): NetplanGetConfig + NetplanApply ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-104-stderr.log)
echo "$PLAN" | jq .
GET=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "NetplanGetConfig")')
APPLY=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "NetplanApply")')
if [[ -z "$GET" || "$GET" == "null" ]]; then echo "FAIL: missing NetplanGetConfig"; exit 1; fi
if [[ -z "$APPLY" || "$APPLY" == "null" ]]; then echo "FAIL: missing NetplanApply"; exit 1; fi
echo "PASS: Story 104"
