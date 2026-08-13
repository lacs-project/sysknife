#!/usr/bin/env bash
# Story 114 (ubuntu, high-risk): Put an AppArmor profile in complain mode
# Intent: "switch /etc/apparmor.d/usr.sbin.nginx to complain mode so violations are logged but not blocked"
# Distro: ubuntu
# High, not Medium: complain mode disables MAC enforcement for the profile.
# The prompt taught Medium here until #205 corrected the table.
set -euo pipefail
INTENT="switch /etc/apparmor.d/usr.sbin.nginx to complain mode so violations are logged but not blocked"
echo "=== Story 114 (ubuntu): AppArmorComplain ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-114-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AppArmorComplain")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AppArmorComplain step"; exit 1; fi
PROFILE_PATH=$(echo "$STEP" | jq -r '.params.profile_path // ""')
if [[ "$PROFILE_PATH" != "/etc/apparmor.d/usr.sbin.nginx" ]]; then echo "FAIL: expected profile_path=/etc/apparmor.d/usr.sbin.nginx, got $PROFILE_PATH"; exit 1; fi
echo "PASS: Story 114"
