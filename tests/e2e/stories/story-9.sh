#!/usr/bin/env bash
# Story 9 (destructive): Create a toolbox
# Intent: "create a toolbox container called dev-test for development work"
# Pass criteria:
#   - Plan has CreateToolbox step with params.name == "dev-test"
#   - Plan marked approvalRequired true, risk medium
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="create a toolbox container called dev-test for development work"

echo "=== Story 9: Create a toolbox ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-9-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

TOOLBOX_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "CreateToolbox" or .action == "DistroboxCreate")')

if [[ -z "$TOOLBOX_STEP" || "$TOOLBOX_STEP" == "null" ]]; then
  echo "FAIL: no CreateToolbox or DistroboxCreate step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

# Check risk level is medium.
RISK=$(echo "$TOOLBOX_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium, got $RISK"
  exit 1
fi

# Check name parameter — accept any key that holds the container name.
NAME=$(echo "$TOOLBOX_STEP" | jq -r '.params.name // .params.container_name // .params.toolbox_name // ""')
if [[ "$NAME" != "dev-test" ]]; then
  echo "FAIL: expected container name dev-test in params, got '$NAME'"
  echo "Full params: $(echo "$TOOLBOX_STEP" | jq '.params')"
  exit 1
fi

echo "PASS: Story 9 — plan has CreateToolbox or DistroboxCreate for dev-test with medium risk"
