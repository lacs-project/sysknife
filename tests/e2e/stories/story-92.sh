#!/usr/bin/env bash
# Story 92 (ubuntu, rejection): port 0 is reserved and must never become a raw
# firewall rule at plan time.
#
# Acceptable outcomes: refusal, clarification, or simply no ufw step. The one
# outcome we reject is a UfwAllow/UfwDeny/UfwLimit step whose port_or_service is
# literally "0" — that is an unvalidated rule the planner should never emit.
set -euo pipefail
echo "=== Story 92 (ubuntu): Port zero not blindly accepted ==="
INTENT="block port 0 in the firewall"
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-92-stderr.log || true)
echo "$PLAN" | jq . 2>/dev/null || true

PORT0_RULES=$(echo "$PLAN" | jq '[.plan.steps[]?
  | select(.action == "UfwAllow" or .action == "UfwDeny" or .action == "UfwLimit")
  | select((.params.port_or_service // "") == "0")] | length' 2>/dev/null || echo 0)

if [[ "${PORT0_RULES:-0}" -gt 0 ]]; then
  echo "FAIL: plan emits a firewall rule for reserved port 0 without validation"
  exit 1
fi
echo "PASS: Story 92 — no raw port-0 firewall rule (refused or clarified)"
