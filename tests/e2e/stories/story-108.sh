#!/usr/bin/env bash
# Story 108 (ubuntu, low-risk): cloud-init provisioning result
# Intent: "did cloud-init finish provisioning this machine without errors?"
# Distro: ubuntu
set -euo pipefail
INTENT="did cloud-init finish provisioning this machine without errors?"
echo "=== Story 108 (ubuntu): CloudInitStatus ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-108-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "CloudInitStatus")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no CloudInitStatus step"; exit 1; fi
echo "PASS: Story 108"
