#!/usr/bin/env bash
# Story 45 (destructive): RebootSystem — indirect framing, must not be UpdateSystem
# Intent: "the new kernel was just installed, I need to reboot to activate it"
# Pass criteria:
#   - Plan contains RebootSystem
#   - risk high
#
# Difficulty factors:
#   - "new kernel was just installed" references a completed update — this
#     is strong temptation for UpdateSystem (model thinks it needs to install
#     first). But the user said "just installed" (past tense) and "need to
#     reboot" — the installation is done. Only the reboot is needed.
#   - "activate it" is indirect phrasing for reboot. The model must not add
#     an unnecessary UpdateSystem or SetKernelArguments step.
#   - Risk must be high: rebooting the system is a deployment lifecycle event.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="the new kernel was just installed, I need to reboot to activate it"

echo "=== Story 45: RebootSystem — not UpdateSystem ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-45-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# The update is already done; UpdateSystem must not appear.
if echo "$ACTIONS" | grep -qx "UpdateSystem"; then
  echo "FAIL: model added UpdateSystem but user said kernel 'was just installed' (past tense)"
  echo "Actions: $ACTIONS"
  exit 1
fi

REBOOT_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RebootSystem")')
if [[ -z "$REBOOT_STEP" || "$REBOOT_STEP" == "null" ]]; then
  echo "FAIL: no RebootSystem step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISK=$(echo "$REBOOT_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for system reboot, got $RISK"
  exit 1
fi

echo "PASS: Story 45 — plan has RebootSystem with high risk, no UpdateSystem"
