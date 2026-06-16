#!/usr/bin/env bash
# Story 66 (ubuntu, medium-risk): Install a snap
# Intent: "install the vscode snap on this Ubuntu system"
# Distro: ubuntu
set -euo pipefail
INTENT="install the vscode snap on this Ubuntu system"
echo "=== Story 66 (ubuntu): Install vscode snap ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-66-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapInstall")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapInstall step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "code" && "$NAME" != "vscode" ]]; then echo "FAIL: expected snap name code/vscode, got $NAME"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
echo "PASS: Story 66"
