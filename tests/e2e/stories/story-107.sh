#!/usr/bin/env bash
# Story 107 (ubuntu, low-risk): Pending reboot check
# Intent: "does this machine need a reboot?"
# Distro: ubuntu
set -euo pipefail
INTENT="does this machine need a reboot?"
echo "=== Story 107 (ubuntu): CheckPendingReboot ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-107-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "CheckPendingReboot")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no CheckPendingReboot step"; exit 1; fi
echo "PASS: Story 107"
