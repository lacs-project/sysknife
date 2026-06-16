#!/usr/bin/env bash
# Story 90 (ubuntu, read-only): Get netplan config with alternative phrasing
# Intent: "what does the server network config look like in netplan"
# Distro: ubuntu
set -euo pipefail
INTENT="what does the server network config look like in netplan"
echo "=== Story 90 (ubuntu): Get netplan config (alt phrasing) ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-90-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "NetplanGetConfig")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no NetplanGetConfig step"; exit 1; fi
echo "PASS: Story 90"
