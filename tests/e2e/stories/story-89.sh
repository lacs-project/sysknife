#!/usr/bin/env bash
# Story 89 (ubuntu, medium-risk): Install snap on beta channel
# Intent: "install the code snap from the beta channel"
# Distro: ubuntu
set -euo pipefail
INTENT="install the code snap from the beta channel"
echo "=== Story 89 (ubuntu): Install code snap on beta channel ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-89-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapInstall")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no SnapInstall step"; exit 1; fi
CHANNEL=$(echo "$STEP" | jq -r '.params.channel // ""')
if [[ "$CHANNEL" != "beta" ]]; then echo "FAIL: expected channel=beta, got $CHANNEL"; exit 1; fi
echo "PASS: Story 89"
