#!/usr/bin/env bash
# Story 80 (ubuntu, read-only): List distrobox containers
# Intent: "show me my distrobox containers"
# Distro: ubuntu
set -euo pipefail
INTENT="show me my distrobox containers"
echo "=== Story 80 (ubuntu): List distrobox containers ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-80-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DistroboxList")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no DistroboxList step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 80"
