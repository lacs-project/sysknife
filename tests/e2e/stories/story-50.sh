#!/usr/bin/env bash
# Story 50 (destructive): ReloadService — config reload without restart
# Intent: "reload nginx config without restarting it"
# Pass criteria:
#   - Plan contains ReloadService (NOT RestartService)
#   - params.unit matches "nginx" or "nginx.service"
#   - risk medium
#
# Difficulty factors:
#   - "reload" and "restart" are semantically different. RestartService
#     stops and starts the unit (briefly drops connections). ReloadService
#     sends SIGHUP — config is applied without downtime.
#   - "without restarting it" is the explicit discriminating phrase.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="reload nginx config without restarting it"

echo "=== Story 50: ReloadService(nginx) — NOT RestartService ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-50-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if echo "$ACTIONS" | grep -q "RestartService"; then
  echo "FAIL: model used RestartService — 'without restarting it' requires ReloadService"
  echo "Actions: $ACTIONS"
  exit 1
fi

if echo "$ACTIONS" | grep -q "StopService"; then
  echo "FAIL: model used StopService — 'reload nginx config' must not stop the unit"
  echo "Actions: $ACTIONS"
  exit 1
fi

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ReloadService")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no ReloadService step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

UNIT=$(echo "$STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "nginx" && "$UNIT" != "nginx.service" ]]; then
  echo "FAIL: expected unit=nginx or nginx.service, got '$UNIT'"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for service reload, got $RISK"
  exit 1
fi

echo "PASS: Story 50 — plan has ReloadService(unit=$UNIT) with medium risk, not RestartService"
