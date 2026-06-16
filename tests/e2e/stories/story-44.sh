#!/usr/bin/env bash
# Story 44 (destructive): SetHostname — rename-phrasing param extraction
# Intent: "rename this machine to workstation-42"
# Pass criteria:
#   - Plan contains SetHostname
#   - params.hostname or params.name == "workstation-42"
#   - risk medium
#
# Difficulty factors:
#   - "rename this machine" is indirect phrasing for SetHostname. The model
#     must map "machine" + "rename" → SetHostname.
#   - Hostname contains a hyphen — model must not split it or drop the suffix.
#   - Must not confuse with SetLocale or SetTimezone (other identity settings).
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="rename this machine to workstation-42"

echo "=== Story 44: SetHostname(workstation-42) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-44-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

HOST_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SetHostname")')
if [[ -z "$HOST_STEP" || "$HOST_STEP" == "null" ]]; then
  echo "FAIL: no SetHostname step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

HOSTNAME=$(echo "$HOST_STEP" | jq -r '.params.hostname // .params.name // .params.host // ""')
if [[ "$HOSTNAME" != "workstation-42" ]]; then
  echo "FAIL: expected hostname=workstation-42, got '$HOSTNAME'"
  echo "Full params: $(echo "$HOST_STEP" | jq '.params')"
  exit 1
fi

RISK=$(echo "$HOST_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for hostname change, got $RISK"
  exit 1
fi

echo "PASS: Story 44 — plan has SetHostname(workstation-42) with medium risk"
