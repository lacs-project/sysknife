#!/usr/bin/env bash
# Story 130 (ubuntu, low-risk): List a user's flatpaks on Ubuntu
# Intent: "list the flatpak apps installed for user alice"
# Distro: ubuntu
# UbuntuListFlatpaks and ListInstalledFlatpaks build byte-identical argv (both delegate to `flatpak_as`) at the
# same risk, so which name the planner picks has no effect on the host. Either
# passes; the run log records which one was chosen, so the Debian prompt's steer
# toward the Ubuntu-prefixed name stays measurable without a cosmetic FAIL.
set -euo pipefail
INTENT="list the flatpak apps installed for user alice"
echo "=== Story 130 (ubuntu): UbuntuListFlatpaks or ListInstalledFlatpaks ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-130-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UbuntuListFlatpaks" or .action == "ListInstalledFlatpaks")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UbuntuListFlatpaks or ListInstalledFlatpaks step"; exit 1; fi
echo "chose: $(echo "$STEP" | jq -r .action)"
USERNAME=$(echo "$STEP" | jq -r '.params.username // ""')
if [[ "$USERNAME" != "alice" ]]; then echo "FAIL: expected username=alice, got $USERNAME"; exit 1; fi
echo "PASS: Story 130"
