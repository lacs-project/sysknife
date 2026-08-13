#!/usr/bin/env bash
# Story 129 (ubuntu, high-risk): Distribution upgrade, not apt upgrade
# Intent: "upgrade this machine to the next Ubuntu release"
# Distro: ubuntu
# AptUpgrade is the near miss and the prompt forbids it here: a release upgrade
# is 20-45 minutes and a reboot, so confusing the two is not a cosmetic slip.
set -euo pipefail
INTENT="upgrade this machine to the next Ubuntu release"
echo "=== Story 129 (ubuntu): UbuntuReleaseUpgrade ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-129-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UbuntuReleaseUpgrade")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UbuntuReleaseUpgrade step"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "AptUpgrade")' >/dev/null; then
  echo "FAIL: planned AptUpgrade for a release upgrade"; exit 1
fi
echo "PASS: Story 129"
