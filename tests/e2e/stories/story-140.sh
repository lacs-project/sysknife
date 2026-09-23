#!/usr/bin/env bash
# Story 140 (ubuntu, read-only): Current nftables ruleset
# Intent: "show me the current nftables ruleset"
# Distro: ubuntu
set -euo pipefail
INTENT="show me the current nftables ruleset"
echo "=== Story 140 (ubuntu): GetNftablesRuleset ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-140-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "GetNftablesRuleset")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected GetNftablesRuleset"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
PARAMS=$(echo "$STEP" | jq -c '.params')
if [[ "$PARAMS" != "{}" ]]; then echo "FAIL: expected no params, got $PARAMS"; exit 1; fi
echo "PASS: Story 140"
