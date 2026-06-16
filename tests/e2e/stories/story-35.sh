#!/usr/bin/env bash
# Story 35 (destructive): ConfigureFirewall — port param extraction, must mutate not read
# Intent: "open port 8080 on the firewall for my web app"
# Pass criteria:
#   - Plan contains ConfigureFirewall (NOT GetFirewallState)
#   - params contain "8080" somewhere (port, ports, rules, etc.)
#   - risk medium
#
# Difficulty factors:
#   - "firewall" keyword could lure GetFirewallState (read) instead of the
#     mutating ConfigureFirewall. The user said "open", which is a mutation.
#   - Port param extraction from natural language.
#   - Model must not add a preliminary GetFirewallState read step — the intent
#     is an unambiguous direct mutation request.
set -euo pipefail

if [[ "${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}" != "1" ]]; then
  echo "SKIPPED (set SYSKNIFE_ALLOW_DESTRUCTIVE=1 to run)"
  exit 0
fi

INTENT="open port 8080 on the firewall for my web app"

echo "=== Story 35: ConfigureFirewall(port=8080) ==="
echo "Intent: $INTENT"

PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-35-stderr.log)
echo "Plan JSON:"
echo "$PLAN" | jq .

# --- Assertions ---

ACTIONS=$(echo "$PLAN" | jq -r '.plan.steps[].action')

CFW_STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "ConfigureFirewall" or .action == "UfwAllow")')
if [[ -z "$CFW_STEP" || "$CFW_STEP" == "null" ]]; then
  echo "FAIL: no ConfigureFirewall (Fedora) or UfwAllow (Ubuntu) step found (mutation required, not a read)"
  echo "Actions: $ACTIONS"
  exit 1
fi

PARAMS_STR=$(echo "$CFW_STEP" | jq -c '.params')
if ! echo "$PARAMS_STR" | grep -q "8080"; then
  echo "FAIL: port 8080 not found in firewall step params"
  echo "Full params: $PARAMS_STR"
  exit 1
fi

RISK=$(echo "$CFW_STEP" | jq -r '.risk')
if [[ "$RISK" != "medium" ]]; then
  echo "FAIL: expected risk medium for firewall configuration, got $RISK"
  exit 1
fi

echo "PASS: Story 35 — plan has ConfigureFirewall or UfwAllow with port 8080, medium risk"
echo "  Params: $PARAMS_STR"
