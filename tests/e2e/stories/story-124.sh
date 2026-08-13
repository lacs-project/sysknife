#!/usr/bin/env bash
# Story 124 (ubuntu, medium-risk): Remove a Launchpad PPA
# Intent: "remove the deadsnakes/ppa launchpad PPA from this machine"
# Distro: ubuntu
set -euo pipefail
INTENT="remove the deadsnakes/ppa launchpad PPA from this machine"
echo "=== Story 124 (ubuntu): RemovePpa ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-124-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RemovePpa")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no RemovePpa step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "deadsnakes/ppa" ]]; then echo "FAIL: expected name=deadsnakes/ppa, got $NAME"; exit 1; fi
echo "PASS: Story 124"
