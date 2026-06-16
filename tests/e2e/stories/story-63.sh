#!/usr/bin/env bash
# Story 63 (ubuntu, read-only): Search apt for a package
# Intent: "search for docker packages in apt"
# Distro: ubuntu
set -euo pipefail
INTENT="search for docker packages in apt"
echo "=== Story 63 (ubuntu): Search apt for docker ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-63-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptSearch")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptSearch step"; exit 1; fi
TERM=$(echo "$STEP" | jq -r '.params.term // ""')
if [[ "$TERM" != "docker" ]]; then echo "FAIL: expected term=docker, got $TERM"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then echo "FAIL: expected risk low, got $RISK"; exit 1; fi
echo "PASS: Story 63"
