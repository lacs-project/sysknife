#!/usr/bin/env bash
# Story 113 (ubuntu, high-risk): Enforce an AppArmor profile
# Intent: "put the apparmor profile /etc/apparmor.d/usr.bin.firefox into enforce mode"
# Distro: ubuntu
set -euo pipefail
INTENT="put the apparmor profile /etc/apparmor.d/usr.bin.firefox into enforce mode"
echo "=== Story 113 (ubuntu): AppArmorEnforce ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-113-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AppArmorEnforce")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AppArmorEnforce step"; exit 1; fi
PROFILE_PATH=$(echo "$STEP" | jq -r '.params.profile_path // ""')
if [[ "$PROFILE_PATH" != "/etc/apparmor.d/usr.bin.firefox" ]]; then echo "FAIL: expected profile_path=/etc/apparmor.d/usr.bin.firefox, got $PROFILE_PATH"; exit 1; fi
echo "PASS: Story 113"
