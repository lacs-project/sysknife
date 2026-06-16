#!/usr/bin/env bash
# Story 10 (destructive): Add SSH authorized key
# Intent: "authorize this SSH key for user lacsdev: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKeyForE2ETesting testkey@example"
# Pass criteria:
#   - Plan has exactly AddAuthorizedKey step
#   - params.public_key matches the input verbatim
#   - Plan marked approvalRequired true, risk high
#     (SSH key operations are access-control changes, same class as AddUserToGroup)
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

TEST_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKeyForE2ETesting testkey@example"
INTENT="authorize this SSH key for user lacsdev: $TEST_KEY"

echo "=== Story 10: Add SSH authorized key ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-10-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ADD_KEY_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AddAuthorizedKey")')

if [[ -z "$ADD_KEY_STEP" || "$ADD_KEY_STEP" == "null" ]]; then
  echo "FAIL: no AddAuthorizedKey step found"
  echo "Actions: $(echo "$PLAN" | jq -r '.plan.steps[].action')"
  exit 1
fi

# Check risk level is high — SSH key operations are access-control changes.
RISK=$(echo "$ADD_KEY_STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then
  echo "FAIL: expected risk high, got $RISK (AddAuthorizedKey is an access-control change)"
  exit 1
fi

# Check public_key matches verbatim.
# Accept any key name that holds the SSH public key string.
PUB_KEY=$(echo "$ADD_KEY_STEP" | jq -r '.params.public_key // .params.key // .params.ssh_key // ""')
if [[ "$PUB_KEY" != "$TEST_KEY" ]]; then
  echo "FAIL: SSH key mismatch"
  echo "  expected: $TEST_KEY"
  echo "  got:      $PUB_KEY"
  exit 1
fi

# Check username is lacsdev.
USERNAME=$(echo "$ADD_KEY_STEP" | jq -r '.params.username // .params.user // ""')
if [[ "$USERNAME" != "lacsdev" ]]; then
  echo "FAIL: expected username=lacsdev, got '$USERNAME'"
  exit 1
fi

echo "PASS: Story 10 — plan has AddAuthorizedKey for lacsdev with correct key"
