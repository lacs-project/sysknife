#!/usr/bin/env bash
# Story 46 (read-only): GetPendingUpdates — "check" must NOT apply updates
# Intent: "are there any OS updates available?"
# Pass criteria:
#   - Plan contains GetPendingUpdates
#   - risk low
#
# Difficulty factors:
#   - "updates available" superficially maps to UpdateSystem. The key
#     discriminator is "are there" (a query) vs "install/apply". The
#     user is asking for information, not requesting a mutation.
set -euo pipefail

INTENT="are there any OS updates available?"

echo "=== Story 46: GetPendingUpdates — check, NOT UpdateSystem ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-46-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if echo "$ACTIONS" | grep -q "UpdateSystem"; then
  echo "FAIL: model used UpdateSystem — query for available updates must use GetPendingUpdates, not apply them"
  echo "Actions: $ACTIONS"
  exit 1
fi

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetPendingUpdates" or .action == "AptUpdate")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no GetPendingUpdates (Fedora) or AptUpdate (Ubuntu) step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low for pending update check, got $RISK"
  exit 1
fi

echo "PASS: Story 46 — plan has GetPendingUpdates or AptUpdate with low risk, not UpdateSystem"
