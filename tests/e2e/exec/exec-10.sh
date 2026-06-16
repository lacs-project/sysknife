#!/usr/bin/env bash
# Exec story 10 (destructive): Group membership cycle — AddUserToGroup + RemoveUserFromGroup
# Intent: add lacsdev to audio group, assert membership, then remove and assert absence.
# Pass criteria:
#   - getent group audio contains lacsdev after add
#   - getent group audio does NOT contain lacsdev after remove
# Risk: High (group membership changes are Admin-level) — uses printf 'y\n' | sysknife.
# `audio` group is always present on Fedora Atomic (PipeWire/PulseAudio).
# getent merges OSTree /usr/lib/group + /etc/group layers correctly.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run group membership stories"
  exit 0
fi

TEST_USER="lacsdev"
GROUP="audio"

# Helper: check if TEST_USER is a member of GROUP via getent.
user_in_group() {
  getent group "$GROUP" 2>/dev/null \
    | cut -d: -f4 \
    | tr ',' '\n' \
    | grep -qx "$TEST_USER"
}

# Cleanup trap: remove from group if story fails mid-way.
cleanup() {
  if user_in_group 2>/dev/null; then
    gpasswd -d "$TEST_USER" "$GROUP" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "=== Exec 10: Group membership cycle (AddUserToGroup + RemoveUserFromGroup) ==="

# Pre-condition: ensure lacsdev is NOT already in audio (idempotency guard).
if user_in_group; then
  echo "Pre-condition: $TEST_USER already in $GROUP — removing first"
  gpasswd -d "$TEST_USER" "$GROUP" 2>/dev/null || true
fi

# --- Phase 1: Add ---
INTENT_ADD="add $TEST_USER to the $GROUP group"
echo "Intent (add): $INTENT_ADD"

OUTPUT_ADD=$(printf 'y\n' | sysknife "$INTENT_ADD" 2>/tmp/sysknife-exec-10-add-stderr.log)
echo "--- Add output ---"
echo "$OUTPUT_ADD"

if ! user_in_group; then
  echo "FAIL: $TEST_USER not found in $GROUP group after AddUserToGroup"
  cat /tmp/sysknife-exec-10-add-stderr.log || true
  exit 1
fi
echo "add: $TEST_USER present in $GROUP [OK]"

# --- Phase 2: Remove ---
INTENT_REMOVE="remove $TEST_USER from the $GROUP group"
echo "Intent (remove): $INTENT_REMOVE"

OUTPUT_REMOVE=$(printf 'y\n' | sysknife "$INTENT_REMOVE" 2>/tmp/sysknife-exec-10-remove-stderr.log)
echo "--- Remove output ---"
echo "$OUTPUT_REMOVE"

if user_in_group; then
  echo "FAIL: $TEST_USER still in $GROUP group after RemoveUserFromGroup"
  cat /tmp/sysknife-exec-10-remove-stderr.log || true
  exit 1
fi
echo "remove: $TEST_USER absent from $GROUP [OK]"

trap - EXIT
echo "PASS: Exec 10 — AddUserToGroup→assert→RemoveUserFromGroup→assert cycle succeeded"
