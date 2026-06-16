#!/usr/bin/env bash
# Story 49 (read-only): ListTimers — scheduled jobs query
# Intent: "what scheduled tasks are running on this system?"
# Pass criteria:
#   - Plan contains ListTimers
#   - risk low
set -euo pipefail

INTENT="what scheduled tasks are running on this system?"

echo "=== Story 49: ListTimers — systemd scheduled tasks ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-49-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ListTimers")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no ListTimers step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low for listing timers, got $RISK"
  exit 1
fi

echo "PASS: Story 49 — plan has ListTimers with low risk"
