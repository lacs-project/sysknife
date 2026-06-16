#!/usr/bin/env bash
# Story 43 (destructive): CleanupDeployments — "free disk space" must not trigger GetDiskUsage
# Intent: "free up disk space by removing old system deployments I'm not using"
# Pass criteria:
#   - Plan contains CleanupDeployments
#   - risk high
#
# Difficulty factors:
#   - "free up disk space" is the canonical lure for GetDiskUsage. A naive
#     model reads "disk space" and routes to the disk-usage read action.
#   - "removing old system deployments" is explicit — CleanupDeployments is
#     the right action, not GetDiskUsage, RollbackDeployment, or ListDeployments.
#   - Risk must be high: removing deployments is an irreversible OSTree operation
#     (old deployment roots are deleted from /ostree/repo).
#   - Model must go straight to propose_plan — this is an explicit mutation
#     request, not an ambiguous diagnostic.
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

INTENT="free up disk space by removing old system deployments I'm not using"

echo "=== Story 43: CleanupDeployments — not GetDiskUsage ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-43-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

CLEANUP_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "CleanupDeployments")')
if [[ -z "$CLEANUP_STEP" || "$CLEANUP_STEP" == "null" ]]; then
  echo "FAIL: no CleanupDeployments step found — 'removing old deployments' maps to CleanupDeployments, not GetDiskUsage"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISK=$(echo "$CLEANUP_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for deployment cleanup (irreversible OSTree operation), got $RISK"
  exit 1
fi

echo "PASS: Story 43 — plan has CleanupDeployments with high risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
