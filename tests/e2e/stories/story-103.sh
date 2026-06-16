#!/usr/bin/env bash
# Story 103 (ubuntu, medium-risk): Hold then show info (compound read+mutate)
# Intent: "pin mysql-server and show me its details"
# Distro: ubuntu
set -euo pipefail
INTENT="pin mysql-server and show me its details"
echo "=== Story 103 (ubuntu): Hold + AptShow for mysql-server ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-103-stderr.log)
echo "$PLAN" | jq .
HOLD=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptHold")')
SHOW=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptShow")')
if [[ -z "$HOLD" || "$HOLD" == "null" ]]; then echo "FAIL: missing AptHold step"; exit 1; fi
if [[ -z "$SHOW" || "$SHOW" == "null" ]]; then echo "FAIL: missing AptShow step"; exit 1; fi
echo "PASS: Story 103"
