#!/usr/bin/env bash
# Story 79 (ubuntu, high-risk): Reset ufw to defaults
# Intent: "reset all ufw rules back to default"
# Distro: ubuntu
set -euo pipefail
INTENT="reset all ufw rules back to default"
echo "=== Story 79 (ubuntu): Reset ufw ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-79-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwReset")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwReset step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
echo "PASS: Story 79"
