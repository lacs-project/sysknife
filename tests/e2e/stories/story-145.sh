#!/usr/bin/env bash
# Story 145 (ubuntu, high-risk): Mount a device and persist it to fstab
# Intent: "mount /dev/sdb1 at /mnt/data as ext4"
# Distro: ubuntu
# The near miss is RemoveMount, which tears a mount down instead of creating
# one. An imperative "mount ..." must plan the mutating AddMount step.
set -euo pipefail
INTENT="mount /dev/sdb1 at /mnt/data as ext4"
echo "=== Story 145 (ubuntu): AddMount ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-145-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "AddMount")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected AddMount"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
DEVICE=$(echo "$STEP" | jq -r '.params.device // ""')
if [[ "$DEVICE" != "/dev/sdb1" ]]; then echo "FAIL: expected device=/dev/sdb1, got $DEVICE"; exit 1; fi
MOUNTPOINT=$(echo "$STEP" | jq -r '.params.mountpoint // ""')
if [[ "$MOUNTPOINT" != "/mnt/data" ]]; then echo "FAIL: expected mountpoint=/mnt/data, got $MOUNTPOINT"; exit 1; fi
FSTYPE=$(echo "$STEP" | jq -r '.params.fstype // ""')
if [[ "$FSTYPE" != "ext4" ]]; then echo "FAIL: expected fstype=ext4, got $FSTYPE"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "RemoveMount")' >/dev/null; then
  echo "FAIL: plan contains RemoveMount instead of only AddMount"; exit 1
fi
echo "PASS: Story 145"
