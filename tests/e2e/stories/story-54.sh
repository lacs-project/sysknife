#!/usr/bin/env bash
# Story 54 (destructive): UpdateFlatpak — update all, no specific app_id
# Intent: "update all my flatpak apps"
# Pass criteria:
#   - Plan contains UpdateFlatpak
#   - params.app_id is absent or empty (update-all path)
#   - risk medium
#
# Difficulty factors:
#   - Story 52 covers the "update a specific Flatpak" case (Some app_id).
#   - This story covers the "update all" case — the model must NOT fabricate
#     an app_id parameter. If it emits app_id with any value, it has
#     invented a constraint that was not in the intent.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="update all my flatpak apps"

echo "=== Story 54: UpdateFlatpak — update all (no app_id) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-54-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UpdateFlatpak")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no UpdateFlatpak step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

# The model must NOT fabricate a specific app_id — the intent says "all"
APP_ID=$(echo "$STEP" | jq -r '.params.app_id // ""')
if [[ -n "$APP_ID" ]]; then
  echo "FAIL: model fabricated app_id='$APP_ID' — 'all my flatpak apps' means update-all, no specific app"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for flatpak update-all, got $RISK"
  exit 1
fi

echo "PASS: Story 54 — plan has UpdateFlatpak with no app_id (update-all path), medium risk"
