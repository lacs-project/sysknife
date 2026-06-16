#!/usr/bin/env bash
# Story 58 (ubuntu, medium-risk): Remove a package
# Intent: "remove the telnet package from this server"
# Distro: ubuntu
set -euo pipefail
INTENT="remove the telnet package from this server"
echo "=== Story 58 (ubuntu): Remove telnet ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-58-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptRemove")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptRemove step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "telnet" ]]; then echo "FAIL: expected package=telnet, got $PKG"; exit 1; fi
echo "PASS: Story 58"
