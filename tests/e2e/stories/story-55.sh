#!/usr/bin/env bash
# Story 55 (ubuntu, low-risk): Refresh apt package index
# Intent: "update the apt package list"
# Distro: ubuntu
set -euo pipefail
INTENT="update the apt package list"
echo "=== Story 55 (ubuntu): Refresh apt package index ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-55-stderr.log)
echo "$PLAN" | jq .
ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "AptUpdate" ]]; then echo "FAIL: expected AptUpdate, got $ACTION"; exit 1; fi
RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 55"
