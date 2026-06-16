#!/usr/bin/env bash
# Exec story 8 (destructive): SetHostname cycle — identity mutation
# Intent: change hostname to "sysknife-exec-test", assert, then restore original.
# Pass criteria:
#   - hostnamectl hostname reflects new hostname after set
#   - hostnamectl hostname restored to original after restore
# Risk: Medium — uses printf 'y\n' | sysknife.
# Note: uses hostnamectl hostname (not /etc/hostname) because Fedora Atomic may
# have a transient hostname from DHCP with no static hostname file on disk.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run identity mutation stories"
  exit 0
fi

TEST_HOSTNAME="sysknife-exec-test"
# Read current hostname via hostnamectl; works whether static or transient.
ORIGINAL_HOSTNAME=$(hostnamectl hostname 2>/dev/null || echo "localhost")

# Restore original hostname on exit regardless of outcome.
cleanup() {
  local current
  current=$(hostnamectl hostname 2>/dev/null || echo "")
  if [[ "$current" != "$ORIGINAL_HOSTNAME" ]]; then
    sudo hostnamectl set-hostname "$ORIGINAL_HOSTNAME" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "=== Exec 8: SetHostname cycle ==="
echo "Original hostname: $ORIGINAL_HOSTNAME"

# --- Phase 1: Set test hostname ---
INTENT_SET="change the hostname to $TEST_HOSTNAME"
echo "Intent (set): $INTENT_SET"

OUTPUT_SET=$(printf 'y\n' | sysknife "$INTENT_SET" 2>/tmp/sysknife-exec-8-set-stderr.log)
echo "--- Set output ---"
echo "$OUTPUT_SET"

CURRENT=$(hostnamectl hostname 2>/dev/null || echo "")
if [[ "$CURRENT" != "$TEST_HOSTNAME" ]]; then
  echo "FAIL: hostname is '$CURRENT', expected '$TEST_HOSTNAME'"
  cat /tmp/sysknife-exec-8-set-stderr.log || true
  exit 1
fi
echo "set: hostname == $TEST_HOSTNAME [OK]"

# --- Phase 2: Restore original hostname ---
INTENT_RESTORE="change the hostname to $ORIGINAL_HOSTNAME"
echo "Intent (restore): $INTENT_RESTORE"

OUTPUT_RESTORE=$(printf 'y\n' | sysknife "$INTENT_RESTORE" 2>/tmp/sysknife-exec-8-restore-stderr.log)
echo "--- Restore output ---"
echo "$OUTPUT_RESTORE"

CURRENT=$(hostnamectl hostname 2>/dev/null || echo "")
if [[ "$CURRENT" != "$ORIGINAL_HOSTNAME" ]]; then
  echo "FAIL: hostname is '$CURRENT' after restore, expected '$ORIGINAL_HOSTNAME'"
  cat /tmp/sysknife-exec-8-restore-stderr.log || true
  exit 1
fi
echo "restore: hostname == $ORIGINAL_HOSTNAME [OK]"

trap - EXIT
echo "PASS: Exec 8 — SetHostname set→assert→restore→assert cycle succeeded"
