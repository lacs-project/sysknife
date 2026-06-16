#!/usr/bin/env bash
# Story 61 (ubuntu, medium-risk): Hold a package at current version
# Intent: "freeze the postgresql package so it doesn't get upgraded"
# Distro: ubuntu
set -euo pipefail
INTENT="freeze the postgresql package so it doesn'''t get upgraded"
echo "=== Story 61 (ubuntu): Hold postgresql ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-61-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptHold")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptHold step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "postgresql" ]]; then echo "FAIL: expected package=postgresql, got $PKG"; exit 1; fi
echo "PASS: Story 61"
