#!/usr/bin/env bash
# Story 88 (ubuntu, read-only): Check package info with natural phrasing
# Intent: "is openssh-server installed? what version?"
# Distro: ubuntu
set -euo pipefail
INTENT="is openssh-server installed? what version?"
echo "=== Story 88 (ubuntu): Check openssh-server info ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-88-stderr.log)
echo "$PLAN" | jq .
# Accept either AptShow (version check) or AptListInstalled (check if installed)
SHOW=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptShow" or .action == "AptListInstalled")')
if [[ -z "$SHOW" || "$SHOW" == "null" ]]; then echo "FAIL: expected AptShow or AptListInstalled"; exit 1; fi
echo "PASS: Story 88"
