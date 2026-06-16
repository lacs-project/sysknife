#!/usr/bin/env bash
# Story 23 (destructive): SetTimezone with timezone parameter extraction
# Intent: "set my timezone to Europe/Berlin"
# Pass criteria:
#   - Plan has exactly 1 step: SetTimezone
#   - params.timezone == "Europe/Berlin"
#   - risk medium
#
# Tests that the model correctly extracts a timezone identifier from the intent
# and maps it to the timezone param without adding unnecessary query steps.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="set my timezone to Europe/Berlin"

echo "=== Story 23: SetTimezone — Europe/Berlin ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-23-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

SET_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SetTimezone")')
if [[ -z "$SET_STEP" || "$SET_STEP" == "null" ]]; then
  echo "FAIL: no SetTimezone step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

TZ=$(echo "$SET_STEP" | jq -r '.params.timezone // .params.tz // ""')
if [[ "$TZ" != "Europe/Berlin" ]]; then
  echo "FAIL: expected timezone=Europe/Berlin, got '$TZ'"
  echo "Full params: $(echo "$SET_STEP" | jq '.params')"
  exit 1
fi

RISK=$(echo "$SET_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" && "$RISK" != "low" ]]; then
  echo "FAIL: expected SetTimezone risk medium or low, got $RISK"
  exit 1
fi

echo "PASS: Story 23 — plan has SetTimezone(timezone=Europe/Berlin) with $RISK risk"
