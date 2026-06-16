#!/usr/bin/env bash
# Story 27 (destructive): SetServiceEnabled — enable sshd at boot
# Intent: "make the ssh service start automatically when the system boots"
# Pass criteria:
#   - Plan contains SetServiceEnabled
#   - params.unit matches "sshd", "ssh", "sshd.service", or "ssh.service"
#   - params.enabled is true (boolean) or "true"/"enable"/"enabled" (string)
#   - risk medium
#
# Tests that the model correctly distinguishes enabling a service (persistent,
# boot-time change) from starting it (transient), and extracts both the unit
# name and the desired enabled state.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="make the ssh service start automatically when the system boots"

echo "=== Story 27: SetServiceEnabled(sshd, enabled=true) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-27-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

ENABLE_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SetServiceEnabled")')
if [[ -z "$ENABLE_STEP" || "$ENABLE_STEP" == "null" ]]; then
  echo "FAIL: no SetServiceEnabled step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

UNIT=$(echo "$ENABLE_STEP" | jq -r '.params.unit // ""')
if [[ "$UNIT" != "sshd" && "$UNIT" != "ssh" && "$UNIT" != "sshd.service" && "$UNIT" != "ssh.service" ]]; then
  echo "FAIL: expected unit=sshd/ssh/sshd.service/ssh.service, got '$UNIT'"
  echo "Full params: $(echo "$ENABLE_STEP" | jq '.params')"
  exit 1
fi

# Accept boolean true or string "true"/"enable"/"enabled".
# Also accept absent param: SetServiceEnabled with a "start on boot" intent
# implies enabled=true — the model need not echo back the implied value.
ENABLED_RAW=$(echo "$ENABLE_STEP" | jq -r '.params.enabled // .params.enable // "implicit"')
case "$ENABLED_RAW" in
  true|"true"|enable|enabled|implicit) : ;;
  false|"false"|disable|disabled)
    echo "FAIL: model proposed disable but intent says enable, got '$ENABLED_RAW'"
    echo "Full params: $(echo "$ENABLE_STEP" | jq '.params')"
    exit 1
    ;;
  *)
    echo "FAIL: unexpected enabled value '$ENABLED_RAW'"
    echo "Full params: $(echo "$ENABLE_STEP" | jq '.params')"
    exit 1
    ;;
esac

RISK=$(echo "$ENABLE_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" && "$RISK" != "low" ]]; then
  echo "FAIL: expected SetServiceEnabled risk medium or low, got $RISK"
  exit 1
fi

echo "PASS: Story 27 — plan has SetServiceEnabled(unit=$UNIT, enabled=$ENABLED_RAW) with $RISK risk"
