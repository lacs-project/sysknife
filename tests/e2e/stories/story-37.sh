#!/usr/bin/env bash
# Story 37 (destructive): DeleteUser — "remove account" must not map to RemoveUserFromGroup
# Intent: "remove the user account oldstaff from the system, they left the company"
# Pass criteria:
#   - Plan contains DeleteUser
#   - params.username or params.user or params.name == "oldstaff"
#   - risk medium
#
# Difficulty factors:
#   - "remove the user" is semantically ambiguous: it could mean DeleteUser
#     (remove the account) or RemoveUserFromGroup (remove from a group). The
#     phrase "user account" and "from the system" disambiguate toward DeleteUser.
#   - "they left the company" is context justification, not a second action.
#   - Risk must be high: deleting an account permanently removes login access —
#     the same class as RemoveUserFromGroup and RemoveAuthorizedKey.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="remove the user account oldstaff from the system, they left the company"

echo "=== Story 37: DeleteUser(oldstaff) — not RemoveUserFromGroup ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-37-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

DELETE_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "DeleteUser")')
if [[ -z "$DELETE_STEP" || "$DELETE_STEP" == "null" ]]; then
  echo "FAIL: no DeleteUser step found (remove account ≠ remove from group)"
  echo "Actions: $ACTIONS"
  exit 1
fi

USERNAME=$(echo "$DELETE_STEP" | jq -r '.params.username // .params.user // .params.name // ""')
if [[ "$USERNAME" != "oldstaff" ]]; then
  echo "FAIL: expected username=oldstaff in DeleteUser params, got '$USERNAME'"
  echo "Full params: $(echo "$DELETE_STEP" | jq '.params')"
  exit 1
fi

RISK=$(echo "$DELETE_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high for user account deletion (access-control removal), got $RISK"
  exit 1
fi

echo "PASS: Story 37 — plan has DeleteUser(username=oldstaff) with high risk"
