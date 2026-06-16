#!/usr/bin/env bash
# Story 96 (ubuntu, medium-risk): Purge alternative phrasing
# Intent: "fully wipe apache2 including its config files"
# Distro: ubuntu
set -euo pipefail
INTENT="fully wipe apache2 including its config files"
echo "=== Story 96 (ubuntu): Purge apache2 ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-96-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptPurge")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptPurge step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "apache2" ]]; then echo "FAIL: expected package=apache2, got $PKG"; exit 1; fi
echo "PASS: Story 96"
