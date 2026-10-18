#!/usr/bin/env bash
# Story 151 (ubuntu, read-only): List SysKnife-managed sudoers grants
# Intent: "list the sudo access rules managed by sysknife"
# Distro: ubuntu
# The near miss is GrantSudoAccess, which adds a sudoers.d drop-in instead of
# listing the existing ones. A "list ..." request must stay read-only and must
# not plan the mutating grant.
set -euo pipefail
INTENT="list the sudo access rules managed by sysknife"
echo "=== Story 151 (ubuntu): GetSudoGrants ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-151-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "GetSudoGrants")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected GetSudoGrants"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAMS=$(echo "$STEP" | jq -c '.params')
if [[ "$PARAMS" != "{}" ]]; then echo "FAIL: expected no params, got $PARAMS"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "GrantSudoAccess")' >/dev/null; then
  echo "FAIL: plan contains GrantSudoAccess instead of only GetSudoGrants"; exit 1
fi
echo "PASS: Story 151"
