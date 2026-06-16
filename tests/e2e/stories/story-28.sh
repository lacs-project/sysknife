#!/usr/bin/env bash
# Story 28: GetKernelArguments + ListDeployments compound (kernel + Atomic)
# Intent: "show me the current kernel boot arguments and list all my deployments"
# Pass criteria:
#   - Plan contains GetKernelArguments
#   - Plan contains ListDeployments or GetDeploymentHistory
#   - All steps risk low
#
# Difficulty factor: these two actions span the kernel-args and Atomic-deployment
# domains. Story 11 covers deployment in a 4-action compound. This story
# isolates the kernel-args action, which has zero coverage in stories 1-20.
set -euo pipefail

DISTRO_FAMILY="${SYSKNIFE_DISTRO_FAMILY:-$(. /etc/os-release && echo "${ID_LIKE:-$ID}" | tr ' ' '\n' | head -1)}"
case "$DISTRO_FAMILY" in
  fedora|rhel|centos) ;;
  *)
    echo "SKIP: $0 requires a Fedora-family host (got: $DISTRO_FAMILY)"
    exit 0
    ;;
esac

INTENT="show me the current kernel boot arguments and list all my deployments"

echo "=== Story 28: GetKernelArguments + ListDeployments compound ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-28-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "GetKernelArguments"; then
  echo "FAIL: GetKernelArguments not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

HAS_DEPLOY=$(echo "$ACTIONS" | grep -cE "ListDeployments|GetDeploymentHistory" || true)
if [[ "$HAS_DEPLOY" -lt 1 ]]; then
  echo "FAIL: neither ListDeployments nor GetDeploymentHistory found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

RISKS=$(echo "$PLAN" | jq -r '.plan.steps[].risk')
while IFS= read -r risk; do
  if [[ "$risk" != "low" ]]; then
    echo "FAIL: expected all steps low risk, got '$risk'"
    exit 1
  fi
done <<< "$RISKS"

echo "PASS: Story 28 — plan has GetKernelArguments + deployment action, all low risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
