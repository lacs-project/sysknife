#!/usr/bin/env bash
# Story 81 (ubuntu, medium-risk): Create a distrobox container
# Intent: "create a distrobox container named dev using ubuntu:24.04"
# Distro: ubuntu
set -euo pipefail
INTENT="create a distrobox container named dev using ubuntu:24.04"
echo "=== Story 81 (ubuntu): Create distrobox container ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-81-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DistroboxCreate")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no DistroboxCreate step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "dev" ]]; then echo "FAIL: expected name=dev, got $NAME"; exit 1; fi
IMAGE=$(echo "$STEP" | jq -r '.params.image // ""')
if [[ "$IMAGE" != "ubuntu:24.04" ]]; then echo "FAIL: expected image=ubuntu:24.04, got $IMAGE"; exit 1; fi
echo "PASS: Story 81"
