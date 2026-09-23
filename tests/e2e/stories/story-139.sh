#!/usr/bin/env bash
# Story 139 (ubuntu, read-only): General firewall backend status
# Intent: "show me the general firewall status across nftables, ufw and firewalld"
# Distro: ubuntu
set -euo pipefail
INTENT="show me the general firewall status across nftables, ufw and firewalld"
echo "=== Story 139 (ubuntu): GetFirewallBackendState ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-139-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "GetFirewallBackendState")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected GetFirewallBackendState"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAMS=$(echo "$STEP" | jq -c '.params')
if [[ "$PARAMS" != "{}" ]]; then echo "FAIL: expected no params, got $PARAMS"; exit 1; fi
echo "PASS: Story 139"
