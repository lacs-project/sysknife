#!/usr/bin/env bash
# Story 117 (ubuntu, high-risk): Detach from Ubuntu Pro
# Intent: "detach this machine from its Ubuntu Pro subscription"
# Distro: ubuntu
set -euo pipefail
INTENT="detach this machine from its Ubuntu Pro subscription"
echo "=== Story 117 (ubuntu): ProDetach ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-117-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ProDetach")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no ProDetach step"; exit 1; fi
echo "PASS: Story 117"
