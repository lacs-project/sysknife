#!/usr/bin/env bash
# Story 105 (ubuntu, low-risk): Identify the host
# Intent: "what OS release, kernel version and architecture is this machine running?"
# Distro: ubuntu
# The Debian counterpart to Fedora's GetSystemState, and the action the
# per-distro prompt split (#181) was built around: naming GetSystemState on an
# apt host is exactly what the family fence forbids, so something had to answer
# "what is this host?" on Ubuntu. Nothing exercised it end to end until now.
set -euo pipefail
INTENT="what OS release, kernel version and architecture is this machine running?"
echo "=== Story 105 (ubuntu): GetHostState ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-105-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetHostState")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no GetHostState step"; exit 1; fi
echo "PASS: Story 105"
