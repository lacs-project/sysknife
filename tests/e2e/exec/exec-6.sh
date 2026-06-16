#!/usr/bin/env bash
# Exec story 6 (safe): ListServices
# Intent: "list all running services"
# Pass criteria:
#   - sysknife executes successfully (exit 0)
#   - stdout is non-empty (at least one service line)
#   - stdout contains "sysknife-daemon" — it must be running for this story to run
# Risk: Low — auto-approved with --yes, no system changes.
set -euo pipefail

INTENT="list all running services"

echo "=== Exec 6: ListServices ==="
echo "Intent: $INTENT"

OUTPUT=$(sysknife --yes "$INTENT" 2>/tmp/sysknife-exec-6-stderr.log)

echo "--- Output (first 20 lines) ---"
echo "$OUTPUT" | head -20

if [[ -z "$OUTPUT" ]]; then
  echo "FAIL: empty output from ListServices"
  cat /tmp/sysknife-exec-6-stderr.log || true
  exit 1
fi

if echo "$OUTPUT" | grep -q "sysknife-daemon"; then
  echo "PASS: Exec 6 — ListServices output is non-empty and contains sysknife-daemon"
else
  # sysknife-daemon must be running (preflight checks it), so if it's missing
  # from the output something is wrong with the action or output parsing.
  echo "FAIL: output does not contain 'sysknife-daemon' — daemon is running but absent from service list"
  echo "--- stderr ---"
  cat /tmp/sysknife-exec-6-stderr.log || true
  exit 1
fi
