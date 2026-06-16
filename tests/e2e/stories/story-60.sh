#!/usr/bin/env bash
# Story 60 (ubuntu, low-risk): Autoremove unused packages
# Intent: "clean up packages that are no longer needed"
# Distro: ubuntu
set -euo pipefail
INTENT="clean up packages that are no longer needed"
echo "=== Story 60 (ubuntu): Autoremove unused packages ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-60-stderr.log)
echo "$PLAN" | jq .
ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "AptAutoremove" ]]; then echo "FAIL: expected AptAutoremove, got $ACTION"; exit 1; fi
RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 60"
