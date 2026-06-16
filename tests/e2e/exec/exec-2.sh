#!/usr/bin/env bash
# Exec story 2 (safe): GetMemoryInfo
# Intent: "show memory information"
# Pass criteria:
#   - sysknife executes successfully (exit 0)
#   - stdout contains "Mem:" — from `free -h` output
# Risk: Low — auto-approved with --yes, no system changes.
set -euo pipefail

INTENT="show memory information"

echo "=== Exec 2: GetMemoryInfo ==="
echo "Intent: $INTENT"

OUTPUT=$(sysknife --yes "$INTENT" 2>/tmp/sysknife-exec-2-stderr.log)

echo "--- Output ---"
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Mem:"; then
  echo "PASS: Exec 2 — GetMemoryInfo output contains 'Mem:' line"
else
  echo "FAIL: output does not contain 'Mem:' — expected 'free -h' style output"
  echo "--- stderr ---"
  cat /tmp/sysknife-exec-2-stderr.log || true
  exit 1
fi
