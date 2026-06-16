#!/usr/bin/env bash
# Story 78 (ubuntu, high-risk): Deny a port
# Intent: "block port 23 telnet in the ufw firewall"
# Distro: ubuntu
set -euo pipefail
INTENT="block port 23 telnet in the ufw firewall"
echo "=== Story 78 (ubuntu): Deny telnet port in ufw ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-78-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwDeny")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwDeny step"; exit 1; fi
PORT=$(echo "$STEP" | jq -r '.params.port_or_service // ""')
if [[ "$PORT" != "23" && "$PORT" != "23/tcp" ]]; then
  echo "FAIL: expected port_or_service 23, got $PORT"
  exit 1
fi
echo "PASS: Story 78"
