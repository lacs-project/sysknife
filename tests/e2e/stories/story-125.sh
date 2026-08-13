#!/usr/bin/env bash
# Story 125 (ubuntu, high-risk): Delete a numbered ufw rule
# Intent: "delete ufw rule number 3"
# Distro: ubuntu
set -euo pipefail
INTENT="delete ufw rule number 3"
echo "=== Story 125 (ubuntu): UfwDeleteRule ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-125-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwDeleteRule")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwDeleteRule step"; exit 1; fi
RULE_NUMBER=$(echo "$STEP" | jq -r '.params.rule_number|tostring // ""')
if [[ "$RULE_NUMBER" != "3" ]]; then echo "FAIL: expected rule_number=3, got $RULE_NUMBER"; exit 1; fi
echo "PASS: Story 125"
