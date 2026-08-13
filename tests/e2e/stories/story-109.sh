#!/usr/bin/env bash
# Story 109 (ubuntu, low-risk): GRUB kernel command line
# Intent: "what kernel command line does grub boot this machine with?"
# Distro: ubuntu
# GetKernelArguments is the Fedora reading of the same question and is fenced
# off an apt host, so on Ubuntu this is unambiguous.
set -euo pipefail
INTENT="what kernel command line does grub boot this machine with?"
echo "=== Story 109 (ubuntu): GrubGetKargs ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-109-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "GrubGetKargs")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no GrubGetKargs step"; exit 1; fi
echo "PASS: Story 109"
