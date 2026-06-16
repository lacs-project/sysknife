#!/usr/bin/env bash
# Story 52 (destructive): UpdateFlatpak — update specific app
# Intent: "update Firefox flatpak"
# Pass criteria:
#   - Plan contains UpdateFlatpak
#   - params.app_id contains "firefox" (case-insensitive)
#   - risk medium
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="update Firefox flatpak"

echo "=== Story 52: UpdateFlatpak(firefox) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-52-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UpdateFlatpak")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no UpdateFlatpak step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

APP_ID=$(echo "$STEP" | jq -r '.params.app_id // ""')
if ! echo "$APP_ID" | grep -qi "firefox"; then
  echo "FAIL: expected app_id containing 'firefox', got '$APP_ID'"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for flatpak update, got $RISK"
  exit 1
fi

echo "PASS: Story 52 — plan has UpdateFlatpak(app_id=$APP_ID) with medium risk"
