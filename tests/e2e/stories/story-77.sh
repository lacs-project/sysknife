#!/usr/bin/env bash
# Story 77 (ubuntu, high-risk): Allow HTTP and HTTPS
# Intent: "allow web traffic on ports 80 and 443 through ufw"
# Distro: ubuntu
set -euo pipefail
INTENT="allow web traffic on ports 80 and 443 through ufw"
echo "=== Story 77 (ubuntu): Allow HTTP+HTTPS in ufw ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-77-stderr.log)
echo "$PLAN" | jq .
# Expect two UfwAllow steps
ALLOW_STEPS=$(echo "$PLAN" | jq '[.plan.steps[] | select(.action == "UfwAllow")] | length')
if [[ "$ALLOW_STEPS" -lt 2 ]]; then
  echo "FAIL: expected at least 2 UfwAllow steps for 80+443, got $ALLOW_STEPS"
  exit 1
fi
echo "PASS: Story 77"
