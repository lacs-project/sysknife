#!/usr/bin/env bash
# Story 68 (ubuntu, medium-risk): Hold a snap to pin its version
# Intent: "pin the chromium snap so it stops auto-updating"
# Distro: ubuntu
set -euo pipefail
INTENT="pin the chromium snap so it stops auto-updating"
echo "=== Story 68 (ubuntu): Hold chromium snap ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-68-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapHold")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapHold step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "chromium" ]]; then echo "FAIL: expected name=chromium, got $NAME"; exit 1; fi
echo "PASS: Story 68"
