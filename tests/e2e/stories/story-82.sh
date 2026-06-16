#!/usr/bin/env bash
# Story 82 (ubuntu, medium-risk): Remove a distrobox container
# Intent: "delete the distrobox container called old-dev"
# Distro: ubuntu
set -euo pipefail
INTENT="delete the distrobox container called old-dev"
echo "=== Story 82 (ubuntu): Remove distrobox container ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-82-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DistroboxRemove")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no DistroboxRemove step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "old-dev" ]]; then echo "FAIL: expected name=old-dev, got $NAME"; exit 1; fi
echo "PASS: Story 82"
