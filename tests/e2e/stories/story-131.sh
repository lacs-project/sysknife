#!/usr/bin/env bash
# Story 131 (ubuntu, medium-risk): Install a flatpak on Ubuntu
# Intent: "install the org.mozilla.firefox flatpak from flathub for user alice"
# Distro: ubuntu
# UbuntuInstallFlatpak and InstallFlatpak build byte-identical argv (both delegate to `flatpak_as`) at the
# same risk, so which name the planner picks has no effect on the host. Either
# passes; the run log records which one was chosen, so the Debian prompt's steer
# toward the Ubuntu-prefixed name stays measurable without a cosmetic FAIL.
set -euo pipefail
INTENT="install the org.mozilla.firefox flatpak from flathub for user alice"
echo "=== Story 131 (ubuntu): UbuntuInstallFlatpak or InstallFlatpak ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-131-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UbuntuInstallFlatpak" or .action == "InstallFlatpak")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UbuntuInstallFlatpak or InstallFlatpak step"; exit 1; fi
echo "chose: $(echo "$STEP" | jq -r .action)"
USERNAME=$(echo "$STEP" | jq -r '.params.username // ""')
if [[ "$USERNAME" != "alice" ]]; then echo "FAIL: expected username=alice, got $USERNAME"; exit 1; fi
APP_ID=$(echo "$STEP" | jq -r '.params.app_id // ""')
if [[ "$APP_ID" != "org.mozilla.firefox" ]]; then echo "FAIL: expected app_id=org.mozilla.firefox, got $APP_ID"; exit 1; fi
echo "PASS: Story 131"
