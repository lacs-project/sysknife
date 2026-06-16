#!/usr/bin/env bash
# Story 40 (destructive): RebaseSystem — rebase ref param extraction
# Intent: "rebase my Silverblue system to Fedora 41"
# Pass criteria:
#   - Plan contains RebaseSystem (NOT UpdateSystem)
#   - params contain "41" or "silverblue" or "fedora" (rebase ref hint)
#   - risk high
#
# Difficulty factors:
#   - "rebase" is a specific OSTree operation, distinct from UpdateSystem
#     (which applies pending updates on the current stream). The model must not
#     conflate them.
#   - "Fedora 41" is a version reference; the rebase ref param must carry it.
#   - Risk must be high: rebase changes the OS stream and requires a reboot.
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

INTENT="rebase my Silverblue system to Fedora 41"

echo "=== Story 40: RebaseSystem(Fedora 41) — not UpdateSystem ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-40-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

# UpdateSystem applies pending updates; RebaseSystem switches streams.
# The user explicitly said "rebase" — must not be UpdateSystem.
if echo "$ACTIONS" | grep -qx "UpdateSystem"; then
  echo "FAIL: model proposed UpdateSystem; user said 'rebase' which means RebaseSystem"
  echo "Actions: $ACTIONS"
  exit 1
fi

REBASE_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "RebaseSystem")')
if [[ -z "$REBASE_STEP" || "$REBASE_STEP" == "null" ]]; then
  echo "FAIL: no RebaseSystem step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

# Rebase ref must reference Fedora 41 in some form.
PARAMS_STR=$(echo "$REBASE_STEP" | jq -c '.params')
if ! echo "$PARAMS_STR" | grep -qiE "41|silverblue|fedora"; then
  echo "FAIL: rebase ref not found in params — expected '41', 'silverblue', or 'fedora'"
  echo "Full params: $PARAMS_STR"
  exit 1
fi

RISK=$(echo "$REBASE_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for OS stream rebase, got $RISK"
  exit 1
fi

echo "PASS: Story 40 — plan has RebaseSystem with Fedora 41 ref, high risk"
echo "  Params: $PARAMS_STR"
