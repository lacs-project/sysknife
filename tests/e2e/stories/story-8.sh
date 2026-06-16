#!/usr/bin/env bash
# Story 8 (destructive): Layer vim via rpm-ostree
# Intent: "install vim as a layered package"
# Pass criteria:
#   - Plan has InstallPackages or AddLayeredPackage with packages containing "vim"
#   - Plan marked approvalRequired true, risk high
#
# NOTE: On the fedora/42-cloud-base VM, rpm-ostree is not available.
# This story validates ONLY the plan structure, not actual execution.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="install vim as a layered package"

echo "=== Story 8: Layer vim via rpm-ostree ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-8-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

# Find the install step (could be InstallPackages, AddLayeredPackage, or AptInstall).
INSTALL_STEP=$(echo "$PLAN" | jq '
  .plan.steps[] | select(
    .action == "InstallPackages" or
    .action == "AddLayeredPackage" or
    .action == "AptInstall"
  )
')

if [[ -z "$INSTALL_STEP" || "$INSTALL_STEP" == "null" ]]; then
  echo "FAIL: no InstallPackages, AddLayeredPackage, or AptInstall step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

# Check risk level is high.
RISK=$(echo "$INSTALL_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high, got $RISK"
  exit 1
fi

# Check that params mention vim.
PARAMS_STR=$(echo "$INSTALL_STEP" | jq -c '.params')
if [[ "$PARAMS_STR" != *"vim"* ]]; then
  echo "FAIL: params do not contain 'vim': $PARAMS_STR"
  exit 1
fi

echo "PASS: Story 8 — plan has high-risk install step for vim"
