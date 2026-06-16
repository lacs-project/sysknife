#!/usr/bin/env bash
# Story 51 (destructive): ReloadDaemon — after unit file edit
# Intent: "I just created a new systemd unit file, reload the daemon"
# Pass criteria:
#   - Plan contains ReloadDaemon
#   - risk medium
#
# Difficulty factors:
#   - Model must know that after creating/editing unit files, daemon-reload
#     is needed before start/enable can pick up changes. This is an
#     admin workflow step, not a service reload.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="I just created a new systemd unit file, reload the daemon"

echo "=== Story 51: ReloadDaemon — systemctl daemon-reload ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-51-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ReloadDaemon")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no ReloadDaemon step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for daemon-reload, got $RISK"
  exit 1
fi

echo "PASS: Story 51 — plan has ReloadDaemon with medium risk"
