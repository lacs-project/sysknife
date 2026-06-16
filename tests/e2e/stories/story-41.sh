#!/usr/bin/env bash
# Story 41: 3-domain read-only compound — repos + containers + network
# Intent: "show me the configured package repositories, what containers are running, and network status"
# Pass criteria:
#   - Plan contains ListPackageRepositories, ListContainers, GetNetworkStatus
#   - All steps risk low
#
# Difficulty factors:
#   - Three actions from three entirely unrelated domains: package management,
#     containers, network. The model must resist collapsing them into
#     GetSystemState or querying each domain before proposing.
#   - ListPackageRepositories has zero coverage in stories 1-30 — this is its
#     first appearance.
#   - None of the phrasing cues appear verbatim in the prompt examples.
set -euo pipefail

INTENT="show me the configured package repositories, what containers are running, and network status"

echo "=== Story 41: ListPackageRepositories + ListContainers + GetNetworkStatus ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-41-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

if ! echo "$ACTIONS" | grep -q "ListPackageRepositories"; then
  echo "FAIL: ListPackageRepositories not found"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "ListContainers"; then
  echo "FAIL: ListContainers not found"
  echo "Actions: $ACTIONS"
  exit 1
fi

if ! echo "$ACTIONS" | grep -q "GetNetworkStatus"; then
  echo "FAIL: GetNetworkStatus not found"
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

echo "PASS: Story 41 — plan has ListPackageRepositories + ListContainers + GetNetworkStatus, all low risk"
echo "  Actions: $(echo "$ACTIONS" | tr '\n' ' ')"
