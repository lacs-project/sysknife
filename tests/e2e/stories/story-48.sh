#!/usr/bin/env bash
# Story 48 (read-only): GetServiceStatus — single-unit detail vs ListServices
# Intent: "is nginx running?"
# Pass criteria:
#   - Plan contains GetServiceStatus
#   - params.unit matches "nginx" or "nginx.service"
#   - risk low
#
# Difficulty factors:
#   - ListServices lists all units; GetServiceStatus gives detail for one.
#     "is X running?" asks about a specific unit — GetServiceStatus is correct.
set -euo pipefail

INTENT="is nginx running?"

echo "=== Story 48: GetServiceStatus(nginx) — specific unit query ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-48-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

# ListServices lists all units — too broad; the intent names a specific unit
if echo "$PLAN" | jq -r '.plan.steps[].action' | grep -q "ListServices"; then
  echo "FAIL: model used ListServices — 'is nginx running?' asks about a specific unit, not all services"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetServiceStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no GetServiceStatus step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

UNIT=$(echo "$STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "nginx" && "$UNIT" != "nginx.service" ]]; then
  echo "FAIL: expected unit=nginx or nginx.service, got '$UNIT'"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low for service status query, got $RISK"
  exit 1
fi

echo "PASS: Story 48 — plan has GetServiceStatus(unit=$UNIT) with low risk"
