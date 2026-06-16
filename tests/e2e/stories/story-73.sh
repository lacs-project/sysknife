#!/usr/bin/env bash
# Story 73 (ubuntu, read-only): Show ufw firewall status
# Intent: "show the current firewall rules on this Ubuntu server"
# Distro: ubuntu
set -euo pipefail
INTENT="show the current firewall rules on this Ubuntu server"
echo "=== Story 73 (ubuntu): Show ufw status ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-73-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwStatus step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 73"
