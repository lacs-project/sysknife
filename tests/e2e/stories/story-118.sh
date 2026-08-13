#!/usr/bin/env bash
# Story 118 (ubuntu, high-risk): Enable one Pro service
# Intent: "enable the esm-apps Ubuntu Pro service"
# Distro: ubuntu
set -euo pipefail
INTENT="enable the esm-apps Ubuntu Pro service"
echo "=== Story 118 (ubuntu): EnableProService ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-118-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "EnableProService")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no EnableProService step"; exit 1; fi
SERVICE=$(echo "$STEP" | jq -r '.params.service // ""')
if [[ "$SERVICE" != "esm-apps" ]]; then echo "FAIL: expected service=esm-apps, got $SERVICE"; exit 1; fi
echo "PASS: Story 118"
