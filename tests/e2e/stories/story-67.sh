#!/usr/bin/env bash
# Story 67 (ubuntu, medium-risk): Remove a snap
# Intent: "uninstall the firefox snap"
# Distro: ubuntu
set -euo pipefail
INTENT="uninstall the firefox snap"
echo "=== Story 67 (ubuntu): Remove firefox snap ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-67-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapRemove")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapRemove step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "firefox" ]]; then echo "FAIL: expected name=firefox, got $NAME"; exit 1; fi
echo "PASS: Story 67"
