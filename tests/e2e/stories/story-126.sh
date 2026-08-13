#!/usr/bin/env bash
# Story 126 (ubuntu, high-risk): Turn on automatic security updates
# Intent: "turn on automatic security updates on this machine"
# Distro: ubuntu
# This action is described in the tool schema but named nowhere in the Debian
# prose blocks, so the story measures whether the schema alone is enough.
set -euo pipefail
INTENT="turn on automatic security updates on this machine"
echo "=== Story 126 (ubuntu): ConfigureUnattendedUpgrades ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-126-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ConfigureUnattendedUpgrades")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no ConfigureUnattendedUpgrades step"; exit 1; fi
ENABLED=$(echo "$STEP" | jq -r '.params.enabled|tostring // ""')
if [[ "$ENABLED" != "true" ]]; then echo "FAIL: expected enabled=true, got $ENABLED"; exit 1; fi
echo "PASS: Story 126"
