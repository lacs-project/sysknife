#!/usr/bin/env bash
# Story 71 (ubuntu, read-only): Show snap info
# Intent: "show me details about the lxd snap"
# Distro: ubuntu
set -euo pipefail
INTENT="show me details about the lxd snap"
echo "=== Story 71 (ubuntu): Show snap info for lxd ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-71-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapInfo")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapInfo step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "lxd" ]]; then echo "FAIL: expected name=lxd, got $NAME"; exit 1; fi
echo "PASS: Story 71"
