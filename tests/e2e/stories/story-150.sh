#!/usr/bin/env bash
# Story 150 (ubuntu, high-risk): Delete an ordinary group
# Intent: "delete the group called devs"
# Distro: ubuntu
# The near miss is CreateGroup, which creates a group instead of removing
# one. An imperative "delete the group ..." must plan DeleteGroup. The target
# is the ordinary group devs, clear of the DeleteGroup critical-group denylist
# (root, sudo, wheel, adm, sys, daemon, bin, staff, shadow, disk).
set -euo pipefail
INTENT="delete the group called devs"
echo "=== Story 150 (ubuntu): DeleteGroup ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-150-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "DeleteGroup")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected DeleteGroup"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
GROUP=$(echo "$STEP" | jq -r '.params.group // ""')
if [[ "$GROUP" != "devs" ]]; then echo "FAIL: expected group=devs, got $GROUP"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "CreateGroup")' >/dev/null; then
  echo "FAIL: plan contains CreateGroup instead of only DeleteGroup"; exit 1
fi
echo "PASS: Story 150"
