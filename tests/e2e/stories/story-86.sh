#!/usr/bin/env bash
# Story 86 (ubuntu, read-only): List installed packages and snaps together
# Intent: "show me what packages and snaps are installed"
# Distro: ubuntu
set -euo pipefail
INTENT="show me what packages and snaps are installed"
echo "=== Story 86 (ubuntu): List packages and snaps ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-86-stderr.log)
echo "$PLAN" | jq .
APT=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptListInstalled")')
SNAP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SnapList")')
if [[ -z "$APT" || "$APT" == "null" ]]; then echo "FAIL: missing AptListInstalled"; exit 1; fi
if [[ -z "$SNAP" || "$SNAP" == "null" ]]; then echo "FAIL: missing SnapList"; exit 1; fi
echo "PASS: Story 86"
