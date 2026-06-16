#!/usr/bin/env bash
# Story 29: Triple compound — processes + network + memory (cross-domain)
# Intent: "show me running processes, current network status, and memory usage"
# Pass criteria:
#   - Plan contains ListProcesses, GetNetworkStatus, and GetMemoryInfo
#   - All steps risk low
#
# Difficulty factors:
#   - Three actions from three different domains: processes, network, memory
#   - None of these phrasing patterns appear verbatim in the prompt examples
#   - Model must NOT call get_system_state or any query_* tool first
#   - Cross-domain compound tests that the model batches unrelated read-only
#     actions into a single plan rather than serialising them
#
# Differs from story 14 (disk + memory + services) and story 16 (network +
# firewall): this is the first compound that includes the processes domain.
set -euo pipefail

INTENT="show me running processes, current network status, and memory usage"

echo "=== Story 29: Triple compound — processes + network + memory ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-29-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "ListProcesses"; then
  echo "FAIL: ListProcesses not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "GetNetworkStatus"; then
  echo "FAIL: GetNetworkStatus not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "GetMemoryInfo"; then
  echo "FAIL: GetMemoryInfo not found in plan"
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

echo "PASS: Story 29 — plan has ListProcesses + GetNetworkStatus + GetMemoryInfo, all low risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
