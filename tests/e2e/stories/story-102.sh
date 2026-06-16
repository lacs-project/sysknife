#!/usr/bin/env bash
# Story 102 (ubuntu, high-risk): System-wide upgrade with alt phrasing
# Intent: "bring all packages up to date on this Ubuntu server"
# Distro: ubuntu
set -euo pipefail
INTENT="bring all packages up to date on this Ubuntu server"
echo "=== Story 102 (ubuntu): AptUpgrade alt phrasing ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-102-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptUpgrade")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptUpgrade step"; exit 1; fi
echo "PASS: Story 102"
