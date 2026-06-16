#!/usr/bin/env bash
# Story 98 (ubuntu, high-risk): Allow a ufw app profile
# Intent: "allow the Nginx Full profile in ufw"
# Distro: ubuntu
set -euo pipefail
INTENT="allow the Nginx Full profile in ufw"
echo "=== Story 98 (ubuntu): UfwAllow Nginx Full ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-98-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwAllow")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwAllow step"; exit 1; fi
PORT=$(echo "$STEP" | jq -r '.params.port_or_service // ""')
if [[ -z "$PORT" ]]; then echo "FAIL: port_or_service is empty"; exit 1; fi
echo "PASS: Story 98 (port_or_service=$PORT)"
