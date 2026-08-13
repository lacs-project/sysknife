#!/usr/bin/env bash
# Story 112 (ubuntu, low-risk): AppArmor profile inventory
# Intent: "show me every loaded apparmor profile and what mode it is in"
# Distro: ubuntu
set -euo pipefail
INTENT="show me every loaded apparmor profile and what mode it is in"
echo "=== Story 112 (ubuntu): AppArmorStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-112-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AppArmorStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AppArmorStatus step"; exit 1; fi
echo "PASS: Story 112"
