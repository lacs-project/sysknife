#!/usr/bin/env bash
# Story 110 (ubuntu, low-risk): Apt pin priority for one package
# Intent: "show me the apt pin priority for the nginx package"
# Distro: ubuntu
set -euo pipefail
INTENT="show me the apt pin priority for the nginx package"
echo "=== Story 110 (ubuntu): GetAptPins ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-110-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetAptPins")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no GetAptPins step"; exit 1; fi
PACKAGE=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PACKAGE" != "nginx" ]]; then echo "FAIL: expected package=nginx, got $PACKAGE"; exit 1; fi
echo "PASS: Story 110"
