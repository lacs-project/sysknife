#!/usr/bin/env bash
# Story 70 (ubuntu, read-only): List installed snaps
# Intent: "what snaps are installed on this machine"
# Distro: ubuntu
set -euo pipefail
INTENT="what snaps are installed on this machine"
echo "=== Story 70 (ubuntu): List installed snaps ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-70-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapList")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapList step"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 70"
