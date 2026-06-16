#!/usr/bin/env bash
# Story 11 (hard compound): Post-update diagnostic — 4 Atomic actions
#
# Intent: complaint/diagnostic framing with four distinct read-only actions.
# The model must resist calling get_system_state or any query_* tool and go
# straight to propose_plan with all four actions.
#
# Difficulty factors:
#   - "acting weird since yesterday's update" → diagnostic framing lures the
#     model toward get_system_state or query_system
#   - "in a failed state" qualifier on services → tempts query_services first
#   - "layered on top of the base" → OSTree-specific phrasing for GetLayeredPackages
#   - 4-action compound spanning Atomic-specific + generic actions
#   - None of these phrasing patterns appear verbatim in the prompt examples
#
# Pass criteria:
#   - Plan contains ALL FOUR of: a deployment action, GetLayeredPackages,
#     ListServices, GetDiskUsage
#   - Deployment action is ListDeployments OR GetDeploymentHistory
#   - All steps are low risk
set -euo pipefail

DISTRO_FAMILY="${SYSKNIFE_DISTRO_FAMILY:-$(. /etc/os-release && echo "${ID_LIKE:-$ID}" | tr ' ' '\n' | head -1)}"

INTENT="My system has been acting weird since yesterday's rpm-ostree update — show me the full deployment history, what packages I've layered on top of the base, whether any systemd services are currently in a failed state, and how much disk space is left"

echo "=== Story 11: Post-update diagnostic (4-action compound) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-11-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

HAS_DEPLOY=$(echo "$ACTIONS" | grep -cE "ListDeployments|GetDeploymentHistory" || true)
HAS_LAYERED=$(echo "$ACTIONS" | grep -cE "GetLayeredPackages|AptListInstalled" || true)
HAS_SERVICES=$(echo "$ACTIONS" | grep -c "ListServices" || true)
HAS_DISK=$(echo "$ACTIONS" | grep -c "GetDiskUsage" || true)

# Deployment history is Fedora/OSTree-specific — only assert on Fedora-family hosts.
case "$DISTRO_FAMILY" in
  fedora|rhel|centos)
    if [[ "$HAS_DEPLOY" -lt 1 ]]; then
      echo "FAIL: expected ListDeployments or GetDeploymentHistory"
      echo "Actions: $ACTIONS"
      exit 1
    fi
    ;;
esac

if [[ "$HAS_LAYERED" -lt 1 ]]; then
  echo "FAIL: expected GetLayeredPackages or AptListInstalled"
  echo "Actions: $ACTIONS"
  exit 1
fi

if [[ "$HAS_SERVICES" -lt 1 ]]; then
  echo "FAIL: expected ListServices"
  echo "Actions: $ACTIONS"
  exit 1
fi

if [[ "$HAS_DISK" -lt 1 ]]; then
  echo "FAIL: expected GetDiskUsage"
  echo "Actions: $ACTIONS"
  exit 1
fi

# All steps must be low risk — these are all read-only.
RISKS=$(echo "$PLAN" | jq -r '.plan.steps[].risk')
while IFS= read -r risk; do
  if [[ "$risk" != "low" ]]; then
    echo "FAIL: expected all steps low risk, got '$risk'"
    echo "Full risks: $RISKS"
    exit 1
  fi
done <<< "$RISKS"

echo "PASS: Story 11 — 4-action post-update diagnostic plan, all low risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
