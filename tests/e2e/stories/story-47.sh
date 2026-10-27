#!/usr/bin/env bash
# Story 47 (read-only): ListInstalledFlatpaks — "what do I have" vs search
# Intent: "show me all my installed flatpak apps"
# Pass criteria:
#   - Plan contains ListInstalledFlatpaks (or, on a Debian-family host,
#     UbuntuListFlatpaks)
#   - risk low
#
# UbuntuListFlatpaks and ListInstalledFlatpaks build the same argv at the same
# risk, and the Debian prompt steers toward the Ubuntu-prefixed name (story 130
# accepts either for the same reason). Fedora prompts never contain the Ubuntu
# name, so on a Fedora host only ListInstalledFlatpaks passes.
#
# Difficulty factors:
#   - SearchFlatpakApps queries the remote catalog; ListInstalledFlatpaks
#     queries the local install state. "installed" is the discriminating word.
set -euo pipefail

DISTRO_FAMILY="${SYSKNIFE_DISTRO_FAMILY:-$(. /etc/os-release && echo "${ID_LIKE:-$ID}" | tr ' ' '\n' | head -1)}"
case "$DISTRO_FAMILY" in
  debian|ubuntu) LIST_FILTER='.action == "ListInstalledFlatpaks" or .action == "UbuntuListFlatpaks"' ;;
  *) LIST_FILTER='.action == "ListInstalledFlatpaks"' ;;
esac

INTENT="show me all my installed flatpak apps"

echo "=== Story 47: ListInstalledFlatpaks — local install state ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-47-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if echo "$ACTIONS" | grep -q "SearchFlatpakApps"; then
  echo "FAIL: model used SearchFlatpakApps — 'installed' means local query, not remote search"
  echo "Actions: $ACTIONS"
  exit 1
fi

STEP=$(echo "$PLAN" | jq ".plan.steps[] | select($LIST_FILTER)")
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no installed-flatpak listing step found ($DISTRO_FAMILY host)"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "low" ]]; then
  echo "FAIL: expected risk low for listing installed flatpaks, got $RISK"
  exit 1
fi

echo "PASS: Story 47 — plan has $(echo "$STEP" | jq -r .action) with low risk"
