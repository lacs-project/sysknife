#!/usr/bin/env bash
# Exec story 7 (destructive): RestartService — service control mutation
# Intent: "restart ssh"
# Pass criteria:
#   - sysknife executes successfully (exit 0)
#   - ssh is still active after restart (restart is idempotent)
# Risk: Medium — uses printf 'y\n' | sysknife (no --yes: Medium needs explicit confirmation).
# ssh/sshd is present on both Fedora and Ubuntu hosts.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIP: set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run service mutation stories"
  exit 0
fi

INTENT="restart ssh"

echo "=== Exec 7: RestartService(ssh) ==="
echo "Intent: $INTENT"

OUTPUT=$(printf 'y\n' | sysknife "$INTENT" 2>/tmp/sysknife-exec-7-stderr.log)
echo "--- Output ---"
echo "$OUTPUT"

# Verify ssh is still active after restart.
# Accept either "ssh" (Ubuntu service name) or "sshd" (Fedora service name).
if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
  echo "PASS: Exec 7 — RestartService(ssh) executed and service is still active"
else
  echo "FAIL: ssh/sshd is not active after restart"
  echo "--- stderr ---"
  cat /tmp/sysknife-exec-7-stderr.log || true
  exit 1
fi
