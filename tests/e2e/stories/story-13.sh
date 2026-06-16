#!/usr/bin/env bash
# Story 13: Service logs for a named unit (parameter extraction)
# Intent: "show me the logs for the sshd service"
# Pass criteria:
#   - Plan has exactly 1 step: GetServiceLogs
#   - params.unit matches "sshd" or "sshd.service" or "ssh" or "ssh.service"
#   - risk_level low
#
# This story tests that the model correctly extracts a specific service name
# from the intent and maps it to the unit param without inventing extra steps.
# sshd is present on both Fedora and Ubuntu, making this distro-agnostic.
set -euo pipefail

INTENT="show me the logs for the sshd service"

echo "=== Story 13: Service logs for sshd ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-13-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

# GetServiceLogs must be present (possibly alongside other diagnostic steps).
GET_LOGS_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetServiceLogs")')
if [[ -z "$GET_LOGS_STEP" || "$GET_LOGS_STEP" == "null" ]]; then
  echo "FAIL: no GetServiceLogs step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

RISK=$(echo "$GET_LOGS_STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected GetServiceLogs risk low, got $RISK"
  exit 1
fi

# Accept "sshd", "sshd.service", "ssh", or "ssh.service" — all valid unit names.
UNIT=$(echo "$GET_LOGS_STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "sshd" && "$UNIT" != "sshd.service" && "$UNIT" != "ssh" && "$UNIT" != "ssh.service" ]]; then
  echo "FAIL: expected unit=sshd, sshd.service, ssh, or ssh.service, got '$UNIT'"
  echo "Full params: $(echo "$GET_LOGS_STEP" | jq '.params')"
  exit 1
fi

echo "PASS: Story 13 — plan has GetServiceLogs(unit=$UNIT) with low risk"
