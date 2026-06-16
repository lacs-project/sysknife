#!/usr/bin/env bash
# Exec story 1 (safe): GetDiskUsage
# Intent: "show disk usage"
# Pass criteria:
#   - sysknife executes successfully (exit 0)
#   - stdout contains "/" — root filesystem line from df output
# Risk: Low — auto-approved with --yes, no system changes.
set -euo pipefail

INTENT="show disk usage"

echo "=== Exec 1: GetDiskUsage ==="
echo "Intent: $INTENT"

OUTPUT=$(sysknife --yes "$INTENT" 2>/tmp/sysknife-exec-1-stderr.log)

echo "--- Output ---"
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "/"; then
  echo "PASS: Exec 1 — GetDiskUsage output contains root filesystem '/'"
else
  echo "FAIL: output does not contain '/' — expected df output with root filesystem"
  echo "--- stderr ---"
  cat /tmp/sysknife-exec-1-stderr.log || true
  exit 1
fi
