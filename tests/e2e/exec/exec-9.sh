#!/usr/bin/env bash
# Exec story 9 (destructive): SetTimezone cycle — identity mutation
# Intent: change timezone to America/Chicago, assert, then restore to UTC.
# Pass criteria:
#   - timedatectl shows America/Chicago after set
#   - timedatectl shows UTC after restore
# Risk: Medium — uses printf 'y\n' | sysknife.
# timedatectl writes /etc/localtime symlink — mutable on Fedora Atomic.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run identity mutation stories"
  exit 0
fi

TEST_TZ="America/Chicago"
ORIGINAL_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")

# Restore original timezone on exit regardless of outcome.
cleanup() {
  local current
  current=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "")
  if [[ "$current" != "$ORIGINAL_TZ" ]]; then
    sudo timedatectl set-timezone "$ORIGINAL_TZ" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "=== Exec 9: SetTimezone cycle ==="
echo "Original timezone: $ORIGINAL_TZ"

# --- Phase 1: Set test timezone ---
INTENT_SET="set the timezone to $TEST_TZ"
echo "Intent (set): $INTENT_SET"

OUTPUT_SET=$(printf 'y\n' | sysknife "$INTENT_SET" 2>/tmp/sysknife-exec-9-set-stderr.log)
echo "--- Set output ---"
echo "$OUTPUT_SET"

CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "")
if [[ "$CURRENT_TZ" != "$TEST_TZ" ]]; then
  echo "FAIL: timezone is '$CURRENT_TZ', expected '$TEST_TZ'"
  cat /tmp/sysknife-exec-9-set-stderr.log || true
  exit 1
fi
echo "set: timezone == $TEST_TZ [OK]"

# --- Phase 2: Restore original timezone ---
INTENT_RESTORE="set the timezone to $ORIGINAL_TZ"
echo "Intent (restore): $INTENT_RESTORE"

OUTPUT_RESTORE=$(printf 'y\n' | sysknife "$INTENT_RESTORE" 2>/tmp/sysknife-exec-9-restore-stderr.log)
echo "--- Restore output ---"
echo "$OUTPUT_RESTORE"

CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "")
if [[ "$CURRENT_TZ" != "$ORIGINAL_TZ" ]]; then
  echo "FAIL: timezone is '$CURRENT_TZ' after restore, expected '$ORIGINAL_TZ'"
  cat /tmp/sysknife-exec-9-restore-stderr.log || true
  exit 1
fi
echo "restore: timezone == $ORIGINAL_TZ [OK]"

trap - EXIT
echo "PASS: Exec 9 — SetTimezone set→assert→restore→assert cycle succeeded"
