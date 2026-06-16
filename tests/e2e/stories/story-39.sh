#!/usr/bin/env bash
# Story 39 (destructive): SetDnsServers — two-IP param extraction
# Intent: "switch to Cloudflare DNS, use 1.1.1.1 and 1.0.0.1"
# Pass criteria:
#   - Plan contains SetDnsServers
#   - params contain both "1.1.1.1" and "1.0.0.1"
#   - risk medium
#
# Difficulty factors:
#   - Two DNS server IPs must both appear in params, not just the first.
#   - "Cloudflare DNS" is a brand hint, not a param — model must extract the
#     actual IP addresses, not the brand name.
#   - Must not confuse with ConfigureWifi (different network domain).
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="switch to Cloudflare DNS, use 1.1.1.1 and 1.0.0.1"

echo "=== Story 39: SetDnsServers(1.1.1.1, 1.0.0.1) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-39-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

DNS_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "SetDnsServers")')
if [[ -z "$DNS_STEP" || "$DNS_STEP" == "null" ]]; then
  echo "FAIL: no SetDnsServers step found"
  echo "Actions: $ACTIONS"
  exit 1
fi

PARAMS_STR=$(echo "$DNS_STEP" | jq -c '.params')

if ! echo "$PARAMS_STR" | grep -q "1.1.1.1"; then
  echo "FAIL: primary DNS 1.1.1.1 not found in params"
  echo "Full params: $PARAMS_STR"
  exit 1
fi

if ! echo "$PARAMS_STR" | grep -q "1.0.0.1"; then
  echo "FAIL: secondary DNS 1.0.0.1 not found in params"
  echo "Full params: $PARAMS_STR"
  exit 1
fi

RISK=$(echo "$DNS_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for DNS configuration, got $RISK"
  exit 1
fi

echo "PASS: Story 39 — plan has SetDnsServers(1.1.1.1, 1.0.0.1) with medium risk"
