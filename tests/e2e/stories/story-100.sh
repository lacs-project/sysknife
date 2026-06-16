#!/usr/bin/env bash
# Story 100 (ubuntu, medium-risk): Create a distrobox from Fedora image
# Intent: "create a distrobox container named fedora-dev using fedora:41"
# Distro: ubuntu
set -euo pipefail
INTENT="create a distrobox container named fedora-dev using fedora:41"
echo "=== Story 100 (ubuntu): Create fedora distrobox ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-100-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DistroboxCreate")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no DistroboxCreate step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "fedora-dev" ]]; then echo "FAIL: expected name=fedora-dev, got $NAME"; exit 1; fi
IMAGE=$(echo "$STEP" | jq -r '.params.image // ""')
if [[ "$IMAGE" != "fedora:41" ]]; then echo "FAIL: expected image=fedora:41, got $IMAGE"; exit 1; fi
echo "PASS: Story 100"
