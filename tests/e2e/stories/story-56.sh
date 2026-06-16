#!/usr/bin/env bash
# Story 56 (ubuntu, high-risk): Upgrade all packages
# Intent: "upgrade all installed packages on this Ubuntu system"
# Distro: ubuntu
set -euo pipefail
INTENT="upgrade all installed packages on this Ubuntu system"
echo "=== Story 56 (ubuntu): Upgrade all packages ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-56-stderr.log)
echo "$PLAN" | jq .
ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "AptUpgrade" ]]; then echo "FAIL: expected AptUpgrade, got $ACTION"; exit 1; fi
RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
echo "PASS: Story 56"
