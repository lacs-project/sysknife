#!/usr/bin/env bash
# Story 120 (ubuntu, low-risk): Livepatch state
# Intent: "is canonical livepatch applying kernel patches on this machine?"
# Distro: ubuntu
set -euo pipefail
INTENT="is canonical livepatch applying kernel patches on this machine?"
echo "=== Story 120 (ubuntu): LivepatchStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-120-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "LivepatchStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no LivepatchStatus step"; exit 1; fi
echo "PASS: Story 120"
