#!/usr/bin/env bash
# Story 57 (ubuntu, medium-risk): Install a package
# Intent: "install nginx on this Ubuntu box"
# Distro: ubuntu
set -euo pipefail
INTENT="install nginx on this Ubuntu box"
echo "=== Story 57 (ubuntu): Install nginx ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-57-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptInstall")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptInstall step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "nginx" ]]; then echo "FAIL: expected package=nginx, got $PKG"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
echo "PASS: Story 57"
