#!/usr/bin/env bash
# Story 115 (ubuntu, low-risk): Ubuntu Pro subscription state
# Intent: "is Ubuntu Pro active on this machine?"
# Distro: ubuntu
set -euo pipefail
INTENT="is Ubuntu Pro active on this machine?"
echo "=== Story 115 (ubuntu): ProStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-115-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ProStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no ProStatus step"; exit 1; fi
echo "PASS: Story 115"
