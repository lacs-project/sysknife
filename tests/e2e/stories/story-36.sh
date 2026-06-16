#!/usr/bin/env bash
# Story 36 (destructive): CreateUser — must not confuse with AddUserToGroup
# Intent: "create a new user account called devteam for the development team"
# Pass criteria:
#   - Plan contains CreateUser
#   - params.username or params.name or params.user == "devteam"
#   - risk medium
#
# Difficulty factors:
#   - "create a new user account" should map to CreateUser.
#   - "for the development team" is context; model must not invent an
#     AddUserToGroup step for a group that was not specified.
#   - Risk must be medium, not high (creating the account doesn't change group
#     memberships or access control — that requires a separate step).
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="create a new user account called devteam for the development team"

echo "=== Story 36: CreateUser(devteam) — not AddUserToGroup ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-36-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

CREATE_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "CreateUser")')
if [[ -z "$CREATE_STEP" || "$CREATE_STEP" == "null" ]]; then
  echo "FAIL: no CreateUser step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

USERNAME=$(echo "$CREATE_STEP" | jq -r '.params.username // .params.name // .params.user // ""')
if [[ "$USERNAME" != "devteam" ]]; then
  echo "FAIL: expected username=devteam in CreateUser params, got '$USERNAME'"
  echo "Full params: $(echo "$CREATE_STEP" | jq '.params')"
  exit 1
fi

RISK=$(echo "$CREATE_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for user creation, got $RISK"
  exit 1
fi

echo "PASS: Story 36 — plan has CreateUser(username=devteam) with medium risk"
