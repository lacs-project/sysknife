#!/usr/bin/env bash
# Story 101 (ubuntu, read-only): Distrobox list alt phrasing
# Intent: "what development containers do I have running"
# Distro: ubuntu
set -euo pipefail
INTENT="what development containers do I have running"
echo "=== Story 101 (ubuntu): DistroboxList alt phrasing ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-101-stderr.log)
echo "$PLAN" | jq .
# Accept DistroboxList or ListContainers (both are valid for this intent)
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DistroboxList" or .action == "ListContainers")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected DistroboxList or ListContainers"; exit 1; fi
echo "PASS: Story 101"
