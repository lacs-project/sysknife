#!/usr/bin/env bash
# Story 99 (ubuntu, read-only): Firewall status alternative phrasing
# Intent: "is the Ubuntu firewall enabled and what ports are open"
# Distro: ubuntu
set -euo pipefail
INTENT="is the Ubuntu firewall enabled and what ports are open"
echo "=== Story 99 (ubuntu): UfwStatus alt phrasing ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-99-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwStatus step"; exit 1; fi
echo "PASS: Story 99"
