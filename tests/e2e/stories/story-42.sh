#!/usr/bin/env bash
# Story 42 (destructive): MaskService — semantic disambiguation vs SetServiceEnabled
# Intent: "completely disable cups so it can never be started, even manually"
# Pass criteria:
#   - Plan contains MaskService (NOT SetServiceEnabled)
#   - params.unit matches "cups" or "cups.service"
#   - risk medium
#
# Difficulty factors:
#   - "disable" superficially maps to SetServiceEnabled(enabled=false), which
#     prevents autostart but still allows manual start. The phrase "can never
#     be started, even manually" is the discriminating signal: that is
#     precisely what MaskService does (creates a /dev/null symlink).
#   - This is the hardest semantic disambiguation in the suite. The model must
#     know the operational difference between masking and disabling.
#   - If SetServiceEnabled appears instead of MaskService, the story fails.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="completely disable cups so it can never be started, even manually"

echo "=== Story 42: MaskService(cups) — NOT SetServiceEnabled(false) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-42-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# SetServiceEnabled(enabled=false) only prevents autostart; the unit can still
# be started manually with `systemctl start`. The phrase "can never be started,
# even manually" unambiguously requires MaskService. If the model includes
# SetServiceEnabled it has failed to understand the distinction.
if echo "$ACTIONS" | grep -q "SetServiceEnabled"; then
  echo "FAIL: model used SetServiceEnabled — but 'can never be started even manually' requires MaskService, not SetServiceEnabled"
  echo "Actions: $ACTIONS"
  exit 1
fi

MASK_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "MaskService")')
if [[ -z "$MASK_STEP" || "$MASK_STEP" == "null" ]]; then
  echo "FAIL: no MaskService step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

UNIT=$(echo "$MASK_STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "cups" && "$UNIT" != "cups.service" ]]; then
  echo "FAIL: expected unit=cups or cups.service, got '$UNIT'"
  exit 1
fi

RISK=$(echo "$MASK_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for service masking, got $RISK"
  exit 1
fi

echo "PASS: Story 42 — plan has MaskService(unit=$UNIT) with medium risk, not SetServiceEnabled"
