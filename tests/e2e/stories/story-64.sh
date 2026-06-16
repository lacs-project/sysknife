#!/usr/bin/env bash
# Story 64 (ubuntu, read-only): List installed packages
# Intent: "show me all installed packages on this Ubuntu machine"
# Distro: ubuntu
set -euo pipefail
INTENT="show me all installed packages on this Ubuntu machine"
echo "=== Story 64 (ubuntu): List installed packages ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-64-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptListInstalled")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptListInstalled step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 64"
