#!/usr/bin/env bash
# Story 143 (ubuntu, medium-risk): Set the system locale
# Intent: "set the system locale to en_US.UTF-8"
# Distro: ubuntu
# The near misses are SetTimezone and SetHostname, the sibling identity actions.
# A locale request must plan SetLocale with the exact
# locale value, not a neighbouring identity change.
set -euo pipefail
INTENT="set the system locale to en_US.UTF-8"
echo "=== Story 143 (ubuntu): SetLocale ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-143-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "SetLocale")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected SetLocale"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
LOCALE=$(echo "$STEP" | jq -r '.params.locale // ""')
if [[ "$LOCALE" != "en_US.UTF-8" ]]; then echo "FAIL: expected locale=en_US.UTF-8, got $LOCALE"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "SetTimezone" or .action == "SetHostname" or .action == "SetNtp")' >/dev/null; then
  echo "FAIL: plan contains a sibling identity action instead of only SetLocale"; exit 1
fi
echo "PASS: Story 143"
