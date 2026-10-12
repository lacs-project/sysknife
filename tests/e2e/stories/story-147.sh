#!/usr/bin/env bash
# Story 147 (ubuntu, high-risk): Create a swap file and persist it to fstab
# Intent: "create a 2048 MB swap file at /swapfile"
# Distro: ubuntu
# The near miss is RemoveSwap, which tears a swap file down instead of
# creating one. An imperative "create a swap file ..." must plan AddSwap.
set -euo pipefail
INTENT="create a 2048 MB swap file at /swapfile"
echo "=== Story 147 (ubuntu): AddSwap ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-147-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "AddSwap")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected AddSwap"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
FILE=$(echo "$STEP" | jq -r '.params.file // ""')
if [[ "$FILE" != "/swapfile" ]]; then echo "FAIL: expected file=/swapfile, got $FILE"; exit 1; fi
SIZE=$(echo "$STEP" | jq -r '.params.size_mb // ""')
if [[ "$SIZE" != "2048" ]]; then echo "FAIL: expected size_mb=2048, got $SIZE"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "RemoveSwap")' >/dev/null; then
  echo "FAIL: plan contains RemoveSwap instead of only AddSwap"; exit 1
fi
echo "PASS: Story 147"
