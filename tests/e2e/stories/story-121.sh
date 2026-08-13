#!/usr/bin/env bash
# Story 121 (ubuntu, low-risk): Multipass VM inventory
# Intent: "list the multipass VMs on this machine and their state"
# Distro: ubuntu
set -euo pipefail
INTENT="list the multipass VMs on this machine and their state"
echo "=== Story 121 (ubuntu): MultipassList ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-121-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "MultipassList")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no MultipassList step"; exit 1; fi
echo "PASS: Story 121"
