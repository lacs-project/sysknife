#!/usr/bin/env bash
# Story 94 (ubuntu, low-risk): Search apt with different phrasing
# Intent: "find me all Redis-related packages"
# Distro: ubuntu
set -euo pipefail
INTENT="find me all Redis-related packages"
echo "=== Story 94 (ubuntu): Search apt for redis ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-94-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptSearch")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptSearch step"; exit 1; fi
TERM=$(echo "$STEP" | jq -r '.params.term // ""')
if [[ -z "$TERM" ]]; then echo "FAIL: term is empty"; exit 1; fi
echo "PASS: Story 94 (term=$TERM)"
