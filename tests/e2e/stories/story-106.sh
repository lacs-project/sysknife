#!/usr/bin/env bash
# Story 106 (ubuntu, low-risk): Recent apt transactions
# Intent: "what packages were installed or removed with apt recently?"
# Distro: ubuntu
set -euo pipefail
INTENT="what packages were installed or removed with apt recently?"
echo "=== Story 106 (ubuntu): AptHistoryList ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-106-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptHistoryList")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptHistoryList step"; exit 1; fi
echo "PASS: Story 106"
