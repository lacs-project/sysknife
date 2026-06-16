#!/usr/bin/env bash
# Story 59 (ubuntu, medium-risk): Purge a package including config
# Intent: "completely remove postfix and delete its configuration"
# Distro: ubuntu
set -euo pipefail
INTENT="completely remove postfix and delete its configuration"
echo "=== Story 59 (ubuntu): Purge postfix ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-59-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptPurge")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AptPurge step"; exit 1; fi
PKG=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PKG" != "postfix" ]]; then echo "FAIL: expected package=postfix, got $PKG"; exit 1; fi
echo "PASS: Story 59"
