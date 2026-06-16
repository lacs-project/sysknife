#!/usr/bin/env bash
# Story 17: Container list + specific container info (compound + param extraction)
# Intent: "list all running containers and give me detailed info on the container named 'postgres'"
# Pass criteria:
#   - Plan has exactly 2 steps
#   - Steps contain ListContainers and GetContainerInfo (any order)
#   - GetContainerInfo has params.name == "postgres"
#   - All steps have risk_level low
#
# This story is difficult because the model must:
#   1. Recognise a compound request (list + single-item detail)
#   2. Correctly extract the container name "postgres" into params
#   3. NOT call query_containers first — this is a direct read-only request
set -euo pipefail

INTENT="list all running containers and give me detailed info on the container named 'postgres'"

echo "=== Story 17: Container list + postgres info ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-17-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "2" ]]; then
  echo "FAIL: expected 2 steps, got $STEP_COUNT"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "ListContainers"; then
  echo "FAIL: ListContainers not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "GetContainerInfo"; then
  echo "FAIL: GetContainerInfo not found in plan"
  echo "Actions: $ACTIONS"
  exit 1
fi

# GetContainerInfo must have name=postgres.
CONTAINER_NAME=$(echo "$PLAN" | jq -r '.plan.steps[] | select(.action == "GetContainerInfo") | .params.name // ""')
if [[ "$CONTAINER_NAME" != "postgres" ]]; then
  echo "FAIL: expected GetContainerInfo params.name=postgres, got '$CONTAINER_NAME'"
  echo "Full params: $(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GetContainerInfo") | .params')"
  exit 1
fi

RISKS=$(echo "$PLAN" | jq -r '.plan.steps[].risk')
while IFS= read -r risk; do
  if [[ "$risk" != "low" ]]; then
    echo "FAIL: expected all steps low risk, got '$risk'"
    exit 1
  fi
done <<< "$RISKS"

echo "PASS: Story 17 — plan has ListContainers + GetContainerInfo(name=postgres), all low risk"
