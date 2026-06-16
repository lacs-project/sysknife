#!/usr/bin/env bash
# Story 34 (destructive): RollbackDeployment — resist query temptation
# Intent: "my system broke after the last rpm-ostree update, roll it back"
# Pass criteria:
#   - Plan contains RollbackDeployment
#   - risk high
#
# Difficulty factors:
#   - "broke after the last update" is one of the strongest diagnostic lures
#     in the suite. A naive model almost always calls get_system_state or
#     query_deployment_history to "understand the situation" before acting.
#   - The user explicitly said "roll it back" — this is an unambiguous direct
#     mutation request. The model must go straight to propose_plan.
#   - Risk must be high: deployment lifecycle changes require reboot.
#
# Note: the model may include a preliminary ListDeployments step to identify
# which deployment to target. That compound is acceptable (RollbackDeployment
# must still be present).
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

INTENT="my system broke after the last rpm-ostree update, roll it back"

echo "=== Story 34: RollbackDeployment — resist query-first temptation ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-34-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

ROLLBACK_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RollbackDeployment")')
if [[ -z "$ROLLBACK_STEP" || "$ROLLBACK_STEP" == "null" ]]; then
  echo "FAIL: no RollbackDeployment step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISK=$(echo "$ROLLBACK_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for deployment lifecycle change, got $RISK"
  exit 1
fi

echo "PASS: Story 34 — plan has RollbackDeployment with high risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
