#!/usr/bin/env bash
# Story 146 (ubuntu, high-risk): Unmount a mountpoint and drop its fstab entry
# Intent: "unmount /mnt/data and remove its fstab entry"
# Distro: ubuntu
# The near miss is AddMount, which creates a mount instead of tearing one
# down. An imperative "unmount ..." must plan the mutating RemoveMount step.
set -euo pipefail
INTENT="unmount /mnt/data and remove its fstab entry"
echo "=== Story 146 (ubuntu): RemoveMount ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-146-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "RemoveMount")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected RemoveMount"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
MOUNTPOINT=$(echo "$STEP" | jq -r '.params.mountpoint // ""')
if [[ "$MOUNTPOINT" != "/mnt/data" ]]; then echo "FAIL: expected mountpoint=/mnt/data, got $MOUNTPOINT"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "AddMount")' >/dev/null; then
  echo "FAIL: plan contains AddMount instead of only RemoveMount"; exit 1
fi
echo "PASS: Story 146"
