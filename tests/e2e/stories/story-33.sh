#!/usr/bin/env bash
# Story 33 (destructive): SetKernelArguments — kernel arg with key=value syntax
# Intent: "add rd.driver.blacklist=nouveau to the kernel arguments to stop the nouveau driver loading"
# Pass criteria:
#   - Plan contains SetKernelArguments (NOT GetKernelArguments)
#   - params contain "rd.driver.blacklist=nouveau" (or equivalent representation)
#   - risk high
#
# Difficulty factors:
#   - Kernel argument contains dots and equals signs — complex param that must
#     be preserved verbatim, not split or mangled.
#   - "add ... to the kernel arguments" could lure GetKernelArguments first;
#     the model must skip the read and go straight to propose_plan.
#   - Risk must be high: kernel arg changes persist across deployments.
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

INTENT="add rd.driver.blacklist=nouveau to the kernel arguments to stop the nouveau driver loading"

echo "=== Story 33: SetKernelArguments(rd.driver.blacklist=nouveau) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-33-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

SET_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SetKernelArguments")')
if [[ -z "$SET_STEP" || "$SET_STEP" == "null" ]]; then
  echo "FAIL: no SetKernelArguments step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

# The kernel arg must appear somewhere in the params (may be in .args, .add, .arguments, etc.)
PARAMS_STR=$(echo "$SET_STEP" | jq -c '.params')
if ! echo "$PARAMS_STR" | grep -q "nouveau"; then
  echo "FAIL: 'nouveau' not found in SetKernelArguments params"
  echo "Full params: $PARAMS_STR"
  exit 1
fi

RISK=$(echo "$SET_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for kernel argument changes, got $RISK"
  exit 1
fi

echo "PASS: Story 33 — plan has SetKernelArguments with nouveau arg, high risk"
echo "  Params: $PARAMS_STR"
