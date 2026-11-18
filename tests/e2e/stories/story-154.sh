#!/usr/bin/env bash
# Story 154 (ubuntu, low-risk, read-only): Check unattended-upgrades schedule
# Intent: "check whether unattended security updates run on schedule and when they last ran"
# Distro: ubuntu
# The schedule and last-run details come from UnattendedUpgradesStatus. This
# read-only query must not choose ConfigureUnattendedUpgrades or an upgrade action.
set -euo pipefail
INTENT="check whether unattended security updates run on schedule and when they last ran"
echo "=== Story 154 (ubuntu): UnattendedUpgradesStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-154-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "UnattendedUpgradesStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected UnattendedUpgradesStatus"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAM_COUNT=$(echo "$STEP" | jq '.params // {} | length')
if [[ "$PARAM_COUNT" != "0" ]]; then echo "FAIL: expected no parameters, got $PARAM_COUNT"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "ConfigureUnattendedUpgrades")' >/dev/null; then
  echo "FAIL: plan contains ConfigureUnattendedUpgrades instead of a read-only status query"; exit 1
fi
echo "PASS: Story 154"
