#!/usr/bin/env bash
# Story 153 (ubuntu, high-risk): Revoke a scoped sudo rule
# Intent: "revoke the scoped sudo rule named deploy-restart"
# Distro: ubuntu
# The near miss is GrantSudoAccess, which creates a drop-in instead of removing
# one. An imperative "revoke ..." must plan RevokeSudoAccess, which is High risk
# because it edits the privilege-escalation configuration.
set -euo pipefail
INTENT="revoke the scoped sudo rule named deploy-restart"
echo "=== Story 153 (ubuntu): RevokeSudoAccess ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-153-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "RevokeSudoAccess")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected RevokeSudoAccess"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "deploy-restart" ]]; then echo "FAIL: expected name=deploy-restart, got $NAME"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "GrantSudoAccess")' >/dev/null; then
  echo "FAIL: plan contains GrantSudoAccess instead of only RevokeSudoAccess"; exit 1
fi
echo "PASS: Story 153"
