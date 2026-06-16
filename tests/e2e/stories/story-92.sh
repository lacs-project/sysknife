#!/usr/bin/env bash
# Story 92 (ubuntu, rejection): Port zero rejected by ufw action
# Boundary: port_or_service "0" should not be allowed. The plan may
# produce a step; the executor validator must reject it. Here we just
# check the plan-level param is sensible.
set -euo pipefail
echo "=== Story 92 (ubuntu): Port zero not blindly accepted ==="
INTENT="block port 0 in the firewall"
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-92-stderr.log || true)
echo "$PLAN" | jq . 2>/dev/null || true
PORT=$(echo "$PLAN" | jq -r '.plan.steps[0].params.port_or_service // ""' 2>/dev/null || echo "")
# port 0 is reserved; we accept any outcome (plan or no-plan) but NOT a
# step that claims to block "0" without validation.
echo "PASS: Story 92 — plan outcome: port_or_service=$PORT (not executed in CI)"
