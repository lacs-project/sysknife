#!/usr/bin/env bash
# Story 97 (ubuntu, low-risk): Show snap details alternative phrasing
# Intent: "what channel is the spotify snap on"
# Distro: ubuntu
set -euo pipefail
INTENT="what channel is the spotify snap on"
echo "=== Story 97 (ubuntu): Snap info for spotify ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-97-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapInfo")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapInfo step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "spotify" ]]; then echo "FAIL: expected name=spotify, got $NAME"; exit 1; fi
echo "PASS: Story 97"
