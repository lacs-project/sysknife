#!/usr/bin/env bash
# Story 47 (read-only): ListInstalledFlatpaks — "what do I have" vs search
# Intent: "show me all my installed flatpak apps"
# Pass criteria:
#   - Plan contains ListInstalledFlatpaks
#   - risk low
#
# Difficulty factors:
#   - SearchFlatpakApps queries the remote catalog; ListInstalledFlatpaks
#     queries the local install state. "installed" is the discriminating word.
set -euo pipefail

INTENT="show me all my installed flatpak apps"

echo "=== Story 47: ListInstalledFlatpaks — local install state ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-47-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if echo "$ACTIONS" | grep -q "SearchFlatpakApps"; then
  echo "FAIL: model used SearchFlatpakApps — 'installed' means local query, not remote search"
  echo "Actions: $ACTIONS"
  exit 1
fi

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ListInstalledFlatpaks")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no ListInstalledFlatpaks step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low for listing installed flatpaks, got $RISK"
  exit 1
fi

echo "PASS: Story 47 — plan has ListInstalledFlatpaks with low risk"
