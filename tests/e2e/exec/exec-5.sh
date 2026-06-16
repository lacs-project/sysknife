#!/usr/bin/env bash
# Exec story 5 (destructive): User round-trip — CreateUser then DeleteUser
# Pass criteria:
#   - After create: user entry present in /etc/passwd
#   - After delete: user entry absent from /etc/passwd
# Risk: High — High risk ALWAYS requires interactive approval; uses `printf 'y\n' | sysknife`.
# Self-cleaning: trap runs userdel if test fails mid-way.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run the user creation round-trip"
  exit 0
fi

TEST_USER="skexectest"

# Cleanup trap — delete the user on exit regardless of outcome.
cleanup() {
  if id "$TEST_USER" &>/dev/null; then
    sudo userdel --remove "$TEST_USER" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "=== Exec 5: User round-trip ==="

# Verify we're starting clean.
if id "$TEST_USER" &>/dev/null; then
  echo "Pre-condition: $TEST_USER already exists — removing first"
  sudo userdel --remove "$TEST_USER" 2>/dev/null || true
fi

# --- Phase 1: Create ---
INTENT_CREATE="create a new user account named $TEST_USER"
echo "Intent (create): $INTENT_CREATE"

OUTPUT_CREATE=$(printf 'y\n' | sysknife "$INTENT_CREATE" 2>/tmp/sysknife-exec-5-create-stderr.log)
echo "--- Create output ---"
echo "$OUTPUT_CREATE"

if ! grep -qP "^${TEST_USER}:" /etc/passwd; then
  echo "FAIL: $TEST_USER not found in /etc/passwd after CreateUser"
  echo "--- create stderr ---"
  cat /tmp/sysknife-exec-5-create-stderr.log || true
  exit 1
fi
echo "create: $TEST_USER present in /etc/passwd [OK]"

# --- Phase 2: Delete ---
INTENT_DELETE="delete the user account $TEST_USER"
echo "Intent (delete): $INTENT_DELETE"

OUTPUT_DELETE=$(printf 'y\n' | sysknife "$INTENT_DELETE" 2>/tmp/sysknife-exec-5-delete-stderr.log)
echo "--- Delete output ---"
echo "$OUTPUT_DELETE"

if grep -qP "^${TEST_USER}:" /etc/passwd; then
  echo "FAIL: $TEST_USER still present in /etc/passwd after DeleteUser"
  echo "--- delete stderr ---"
  cat /tmp/sysknife-exec-5-delete-stderr.log || true
  exit 1
fi
echo "delete: $TEST_USER absent from /etc/passwd [OK]"

# Disarm trap (user already gone).
trap - EXIT

echo "PASS: Exec 5 — user create→assert→delete→assert round-trip succeeded"
