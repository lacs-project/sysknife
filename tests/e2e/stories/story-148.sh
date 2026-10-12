#!/usr/bin/env bash
# Story 148 (ubuntu, high-risk): Remove a swap file and drop its fstab entry
# Intent: "remove the swap file at /swapfile"
# Distro: ubuntu
# The near miss is AddSwap, which creates a swap file instead of removing
# one. An imperative "remove the swap file ..." must plan RemoveSwap.
set -euo pipefail
INTENT="remove the swap file at /swapfile"
echo "=== Story 148 (ubuntu): RemoveSwap ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-148-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "RemoveSwap")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected RemoveSwap"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
FILE=$(echo "$STEP" | jq -r '.params.file // ""')
if [[ "$FILE" != "/swapfile" ]]; then echo "FAIL: expected file=/swapfile, got $FILE"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "AddSwap")' >/dev/null; then
  echo "FAIL: plan contains AddSwap instead of only RemoveSwap"; exit 1
fi
echo "PASS: Story 148"
