#!/usr/bin/env bash
# Story 133 (ubuntu, medium-risk): Update every flatpak for a user on Ubuntu
# Intent: "update all the flatpak apps for user alice"
# Distro: ubuntu
# UbuntuUpdateFlatpak and UpdateFlatpak build byte-identical argv (both delegate to `flatpak_as`) at the
# same risk, so which name the planner picks has no effect on the host. Either
# passes; the run log records which one was chosen, so the Debian prompt's steer
# toward the Ubuntu-prefixed name stays measurable without a cosmetic FAIL.
set -euo pipefail
INTENT="update all the flatpak apps for user alice"
echo "=== Story 133 (ubuntu): UbuntuUpdateFlatpak or UpdateFlatpak ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-133-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UbuntuUpdateFlatpak" or .action == "UpdateFlatpak")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UbuntuUpdateFlatpak or UpdateFlatpak step"; exit 1; fi
echo "chose: $(echo "$STEP" | jq -r .action)"
USERNAME=$(echo "$STEP" | jq -r '.params.username // ""')
if [[ "$USERNAME" != "alice" ]]; then echo "FAIL: expected username=alice, got $USERNAME"; exit 1; fi
echo "PASS: Story 133"
