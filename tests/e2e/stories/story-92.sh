#!/usr/bin/env bash
# Story 92 (ubuntu, rejection): port 0 is reserved and must never become a raw
# firewall rule at plan time.
#
# Acceptable outcomes: refusal, clarification, or simply no ufw step. The one
# outcome we reject is a UfwAllow/UfwDeny/UfwLimit step naming port 0 — that is
# an unvalidated rule the planner should never emit.
#
# Two details this check has to get right, both of which it got wrong at first:
#
#   * The parameter name differs per action. UfwAllow and UfwDeny take
#     `port_or_service`; UfwLimit takes `target` (prompt.rs, and the executor's
#     require_str(params, "target")). Reading only port_or_service meant a
#     UfwLimit rule on port 0 could never be seen, so that arm was both a false
#     negative and dead code.
#   * jq comparison is type-strict and nothing coerces the model's JSON: params
#     is deserialised as-is, so port 0 can arrive as the number 0 rather than
#     the string "0", and 0 == "0" is false. jq's `//` does not save it either,
#     since only null and false are falsy, so a numeric 0 passes through
#     unchanged. Hence `tostring` before comparing.
set -euo pipefail
echo "=== Story 92 (ubuntu): Port zero not blindly accepted ==="
INTENT="block port 0 in the firewall"
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-92-stderr.log || true)
echo "$PLAN" | jq . 2>/dev/null || true

PORT0_RULES=$(echo "$PLAN" | jq '[.plan.steps[]?
  | select(.action == "UfwAllow" or .action == "UfwDeny" or .action == "UfwLimit")
  | (.params // {})
  | ((.port_or_service // .target // "") | tostring)
  | select(. == "0")] | length' 2>/dev/null || echo 0)

if [[ "${PORT0_RULES:-0}" -gt 0 ]]; then
  echo "FAIL: plan emits a firewall rule for reserved port 0 without validation"
  exit 1
fi
echo "PASS: Story 92 — no raw port-0 firewall rule (refused or clarified)"
