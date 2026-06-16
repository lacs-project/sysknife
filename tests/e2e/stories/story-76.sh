#!/usr/bin/env bash
# Story 76 (ubuntu, high-risk): Allow SSH through ufw
# Intent: "open port 22 in the firewall so SSH works"
# Distro: ubuntu
set -euo pipefail
INTENT="open port 22 in the firewall so SSH works"
echo "=== Story 76 (ubuntu): Allow SSH in ufw ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-76-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwAllow")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no UfwAllow step"; exit 1; fi
PORT=$(echo "$STEP" | jq -r '.params.port_or_service // ""')
if [[ "$PORT" != "22" && "$PORT" != "22/tcp" && "$PORT" != "OpenSSH" ]]; then
  echo "FAIL: expected port_or_service 22 or OpenSSH, got $PORT"
  exit 1
fi
echo "PASS: Story 76"
