#!/usr/bin/env bash
# Exec story 4 (destructive): SSH key round-trip — AddAuthorizedKey then RemoveAuthorizedKey
# Pass criteria:
#   - After add: key appears verbatim in /home/lacsdev/.ssh/authorized_keys
#   - After remove: key is absent from /home/lacsdev/.ssh/authorized_keys
# Risk: Medium — uses `printf 'y\n' | sysknife` for interactive approval.
# Self-cleaning: trap removes the key if the test fails mid-way.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run the SSH key round-trip"
  exit 0
fi

AUTHORIZED_KEYS="/home/lacsdev/.ssh/authorized_keys"
# Unique key to distinguish from the seed key in authorized_keys.
TEST_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExec4RoundTripTestKeyDoNotUseInProduction exec-4@sysknife-e2e"

# Cleanup trap — remove the key on exit regardless of outcome.
cleanup() {
  if grep -qF "$TEST_KEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
    sed -i "\|${TEST_KEY}|d" "$AUTHORIZED_KEYS" || true
  fi
}
trap cleanup EXIT

echo "=== Exec 4: SSH key round-trip ==="

# --- Phase 1: Add ---
INTENT_ADD="add SSH authorized key for user lacsdev: $TEST_KEY"
echo "Intent (add): $INTENT_ADD"

OUTPUT_ADD=$(printf 'y\n' | sysknife "$INTENT_ADD" 2>/tmp/sysknife-exec-4-add-stderr.log)
echo "--- Add output ---"
echo "$OUTPUT_ADD"

if ! grep -qF "$TEST_KEY" "$AUTHORIZED_KEYS"; then
  echo "FAIL: key not found in $AUTHORIZED_KEYS after AddAuthorizedKey"
  echo "--- add stderr ---"
  cat /tmp/sysknife-exec-4-add-stderr.log || true
  exit 1
fi
echo "add: key present in authorized_keys [OK]"

# --- Phase 2: Remove ---
INTENT_REMOVE="remove SSH authorized key from user lacsdev: $TEST_KEY"
echo "Intent (remove): $INTENT_REMOVE"

OUTPUT_REMOVE=$(printf 'y\n' | sysknife "$INTENT_REMOVE" 2>/tmp/sysknife-exec-4-remove-stderr.log)
echo "--- Remove output ---"
echo "$OUTPUT_REMOVE"

if grep -qF "$TEST_KEY" "$AUTHORIZED_KEYS" 2>/dev/null; then
  echo "FAIL: key still present in $AUTHORIZED_KEYS after RemoveAuthorizedKey"
  echo "--- remove stderr ---"
  cat /tmp/sysknife-exec-4-remove-stderr.log || true
  exit 1
fi
echo "remove: key absent from authorized_keys [OK]"

# Disarm trap (key already gone, cleanup would be a no-op).
trap - EXIT

echo "PASS: Exec 4 — SSH key add→assert→remove→assert round-trip succeeded"
