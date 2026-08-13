#!/usr/bin/env bash
# Story 119 (ubuntu, high-risk): Disable one Pro service
# Intent: "turn off the livepatch Ubuntu Pro service"
# Distro: ubuntu
set -euo pipefail
INTENT="turn off the livepatch Ubuntu Pro service"
echo "=== Story 119 (ubuntu): DisableProService ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-119-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DisableProService")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no DisableProService step"; exit 1; fi
SERVICE=$(echo "$STEP" | jq -r '.params.service // ""')
if [[ "$SERVICE" != "livepatch" ]]; then echo "FAIL: expected service=livepatch, got $SERVICE"; exit 1; fi
echo "PASS: Story 119"
