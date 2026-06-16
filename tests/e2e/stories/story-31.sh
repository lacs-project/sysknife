#!/usr/bin/env bash
# Story 31 (destructive): RemoveUserFromGroup — high-risk group membership removal
# Intent: "remove alice from the docker group, she no longer needs container access"
# Pass criteria:
#   - Plan contains RemoveUserFromGroup
#   - params.username or params.user == "alice"
#   - params.group == "docker"
#   - risk high
#
# Difficulty factors:
#   - "remove alice from the docker group" could be misread as DeleteUser
#   - "she no longer needs container access" is context, not a separate action —
#     model must not add a ListContainers or GetContainerInfo step
#   - Risk must be high: group membership is an access-control change
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="remove alice from the docker group, she no longer needs container access"

echo "=== Story 31: RemoveUserFromGroup(alice, docker) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-31-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# Must not be a DeleteUser — removing from a group ≠ deleting the account.
if echo "$ACTIONS" | grep -q "DeleteUser"; then
  echo "FAIL: model proposed DeleteUser but intent is to remove from group only"
  echo "Actions: $ACTIONS"
  exit 1
fi

REMOVE_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RemoveUserFromGroup")')
if [[ -z "$REMOVE_STEP" || "$REMOVE_STEP" == "null" ]]; then
  echo "FAIL: no RemoveUserFromGroup step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

USERNAME=$(echo "$REMOVE_STEP" | jq -r '.params.username // .params.user // ""')
if [[ "$USERNAME" != "alice" ]]; then
  echo "FAIL: expected username=alice, got '$USERNAME'"
  echo "Full params: $(echo "$REMOVE_STEP" | jq '.params')"
  exit 1
fi

GROUP=$(echo "$REMOVE_STEP" | jq -r '.params.group // ""')
if [[ "$GROUP" != "docker" ]]; then
  echo "FAIL: expected group=docker, got '$GROUP'"
  echo "Full params: $(echo "$REMOVE_STEP" | jq '.params')"
  exit 1
fi

RISK=$(echo "$REMOVE_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high (group membership is access-control), got $RISK"
  exit 1
fi

echo "PASS: Story 31 — plan has RemoveUserFromGroup(username=alice, group=docker) with high risk"
