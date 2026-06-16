#!/usr/bin/env bash
# Story 85 (ubuntu, compound): Update apt index then install a package
# Intent: "refresh the package list and then install htop"
# Distro: ubuntu
set -euo pipefail
INTENT="refresh the package list and then install htop"
echo "=== Story 85 (ubuntu): Update + install ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-85-stderr.log)
echo "$PLAN" | jq .
UPDATE=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptUpdate")')
INSTALL=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptInstall")')
if [[ -z "$UPDATE" || "$UPDATE" == "null" ]]; then echo "FAIL: missing AptUpdate step"; exit 1; fi
if [[ -z "$INSTALL" || "$INSTALL" == "null" ]]; then echo "FAIL: missing AptInstall step"; exit 1; fi
PKG=$(echo "$INSTALL" | jq -r '.params.package // ""')
if [[ "$PKG" != "htop" ]]; then echo "FAIL: expected package=htop, got $PKG"; exit 1; fi
echo "PASS: Story 85"
