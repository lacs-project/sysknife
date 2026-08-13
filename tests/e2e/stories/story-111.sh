#!/usr/bin/env bash
# Story 111 (ubuntu, medium-risk): Remove a named apt pin
# Intent: "remove the apt pin named freeze-nginx"
# Distro: ubuntu
set -euo pipefail
INTENT="remove the apt pin named freeze-nginx"
echo "=== Story 111 (ubuntu): RemoveAptPin ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-111-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RemoveAptPin")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no RemoveAptPin step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "freeze-nginx" ]]; then echo "FAIL: expected name=freeze-nginx, got $NAME"; exit 1; fi
echo "PASS: Story 111"
