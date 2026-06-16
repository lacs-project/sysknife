#!/usr/bin/env bash
# Story 72 (ubuntu, medium-risk): Refresh all snaps
# Intent: "update all snaps to their latest versions"
# Distro: ubuntu
set -euo pipefail
INTENT="update all snaps to their latest versions"
echo "=== Story 72 (ubuntu): Refresh all snaps ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-72-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapRefresh")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapRefresh step"; exit 1; fi
echo "PASS: Story 72"
