#!/usr/bin/env bash
# Story 141 (ubuntu, read-only): Current date, time and NTP status
# Intent: "what is the current date and time on this machine"
# Distro: ubuntu
set -euo pipefail
INTENT="what is the current date and time on this machine"
echo "=== Story 141 (ubuntu): GetDateTime ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-141-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "GetDateTime")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected GetDateTime"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAMS=$(echo "$STEP" | jq -c '.params')
if [[ "$PARAMS" != "{}" ]]; then echo "FAIL: expected no params, got $PARAMS"; exit 1; fi
echo "PASS: Story 141"
