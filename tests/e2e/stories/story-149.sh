#!/usr/bin/env bash
# Story 149 (ubuntu, medium-risk): Create a new group
# Intent: "create a new group called devs"
# Distro: ubuntu
# The near miss is DeleteGroup, which removes a group instead of creating
# one. An imperative "create a new group ..." must plan CreateGroup.
set -euo pipefail
INTENT="create a new group called devs"
echo "=== Story 149 (ubuntu): CreateGroup ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-149-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "CreateGroup")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected CreateGroup"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
GROUP=$(echo "$STEP" | jq -r '.params.group // ""')
if [[ "$GROUP" != "devs" ]]; then echo "FAIL: expected group=devs, got $GROUP"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "DeleteGroup")' >/dev/null; then
  echo "FAIL: plan contains DeleteGroup instead of only CreateGroup"; exit 1
fi
echo "PASS: Story 149"
