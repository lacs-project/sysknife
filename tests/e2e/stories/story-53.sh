#!/usr/bin/env bash
# Story 53 (destructive): RemoveBasePackage — override-remove a base package
# Intent: "remove gedit from the base image, I don't need it"
# Pass criteria:
#   - Plan contains RemoveBasePackage (NOT RemoveLayeredPackage, NOT RemovePackages)
#   - params.package contains "gedit"
#   - risk high
#
# Difficulty factors:
#   - "base image" signals this is an rpm-ostree override, not a layered
#     package operation. RemoveLayeredPackage uninstalls user-added packages;
#     RemoveBasePackage hides base OS packages.
#   - RemovePackages is the Atomic equivalent of `rpm-ostree uninstall` for
#     layered packages — also wrong here.
set -euo pipefail

DISTRO_FAMILY="${SYSKNIFE_DISTRO_FAMILY:-$(. /etc/os-release && echo "${ID_LIKE:-$ID}" | tr ' ' '\n' | head -1)}"
case "$DISTRO_FAMILY" in
  fedora|rhel|centos) ;;
  *)
    echo "SKIP: $0 requires a Fedora-family host (got: $DISTRO_FAMILY)"
    exit 0
    ;;
esac

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="remove gedit from the base image, I don't need it"

echo "=== Story 53: RemoveBasePackage(gedit) — base image override ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-53-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# RemoveLayeredPackage is for user-added layered packages, not base OS packages
if echo "$ACTIONS" | grep -q "RemoveLayeredPackage"; then
  echo "FAIL: model used RemoveLayeredPackage — base image removal requires RemoveBasePackage (rpm-ostree override remove)"
  echo "Actions: $ACTIONS"
  exit 1
fi

# RemovePackages (rpm-ostree uninstall) also fails for base OS packages at runtime
# and signals the model misunderstood the "base image" context
if echo "$ACTIONS" | grep -q "RemovePackages"; then
  echo "FAIL: model used RemovePackages — base image removal requires RemoveBasePackage, not rpm-ostree uninstall"
  echo "Actions: $ACTIONS"
  exit 1
fi

STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RemoveBasePackage")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then
  echo "FAIL: no RemoveBasePackage step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

PACKAGE=$(echo "$STEP" | jq -r '.params.package // ""')
if [[ "$PACKAGE" != "gedit" ]]; then
  echo "FAIL: expected package=gedit, got '$PACKAGE'"
  exit 1
fi

RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for base package removal (requires reboot), got $RISK"
  exit 1
fi

echo "PASS: Story 53 — plan has RemoveBasePackage(package=gedit) with high risk"
