#!/usr/bin/env bash
# Story 62 (ubuntu, medium-risk): Unhold a package
# Intent: "let the nginx package be upgraded again"
# Distro: ubuntu
set -euo pipefail
INTENT="let the nginx package be upgraded again"
echo "=== Story 62 (ubuntu): Unhold nginx ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-62-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptUnhold")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptUnhold step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "nginx" ]]; then echo "FAIL: expected package=nginx, got $PKG"; exit 1; fi
echo "PASS: Story 62"
