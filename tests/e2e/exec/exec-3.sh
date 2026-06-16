#!/usr/bin/env bash
# Exec story 3 (safe): GetServiceStatus
# Intent: "show status of sysknife-daemon"
# Pass criteria:
#   - sysknife executes successfully (exit 0)
#   - stdout contains "active" — systemctl status output for a running unit
# Risk: Low — auto-approved with --yes, no system changes.
set -euo pipefail

INTENT="show status of sysknife-daemon"

echo "=== Exec 3: GetServiceStatus(sysknife-daemon) ==="
echo "Intent: $INTENT"

OUTPUT=$(sysknife --yes "$INTENT" 2>/tmp/sysknife-exec-3-stderr.log)

echo "--- Output ---"
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "active"; then
  echo "PASS: Exec 3 — GetServiceStatus output contains 'active'"
else
  echo "FAIL: output does not contain 'active' — expected systemctl status output for running daemon"
  echo "--- stderr ---"
  cat /tmp/sysknife-exec-3-stderr.log || true
  exit 1
fi
