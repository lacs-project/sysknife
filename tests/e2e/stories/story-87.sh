#!/usr/bin/env bash
# Story 87 (ubuntu, high-risk): Enable firewall and allow SSH
# Intent: "enable ufw and allow SSH connections"
# Distro: ubuntu
set -euo pipefail
INTENT="enable ufw and allow SSH connections"
echo "=== Story 87 (ubuntu): Enable ufw and allow SSH ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-87-stderr.log)
echo "$PLAN" | jq .
ENABLE=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwEnable")')
ALLOW=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "UfwAllow")')
if [[ -z "$ENABLE" || "$ENABLE" == "null" ]]; then echo "FAIL: missing UfwEnable"; exit 1; fi
if [[ -z "$ALLOW" || "$ALLOW" == "null" ]]; then echo "FAIL: missing UfwAllow for SSH"; exit 1; fi
echo "PASS: Story 87"
