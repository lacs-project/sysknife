#!/usr/bin/env bash
# Story 65 (ubuntu, read-only): Show package info
# Intent: "what version of curl is available in apt"
# Distro: ubuntu
set -euo pipefail
INTENT="what version of curl is available in apt"
echo "=== Story 65 (ubuntu): Show package info for curl ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-65-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptShow")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptShow step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "curl" ]]; then echo "FAIL: expected package=curl, got $PKG"; exit 1; fi
echo "PASS: Story 65"
