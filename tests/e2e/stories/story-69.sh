#!/usr/bin/env bash
# Story 69 (ubuntu, medium-risk): Unhold a snap
# Intent: "allow the chromium snap to auto-update again"
# Distro: ubuntu
set -euo pipefail
INTENT="allow the chromium snap to auto-update again"
echo "=== Story 69 (ubuntu): Unhold chromium snap ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-69-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapUnhold")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapUnhold step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "chromium" ]]; then echo "FAIL: expected name=chromium, got $NAME"; exit 1; fi
echo "PASS: Story 69"
