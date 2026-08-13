#!/usr/bin/env bash
# Story 128 (ubuntu, high-risk): Set a netplan key without applying
# Intent: "make eth0 use DHCP in netplan, but do not apply it yet"
# Distro: ubuntu
# The key is asserted to mention dhcp4 rather than matched exactly: 'ethernets.eth0.dhcp4'
# and 'network.ethernets.eth0.dhcp4' are both faithful renderings of the request.
set -euo pipefail
INTENT="make eth0 use DHCP in netplan, but do not apply it yet"
echo "=== Story 128 (ubuntu): NetplanSet ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-128-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "NetplanSet")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no NetplanSet step"; exit 1; fi
KEY=$(echo "$STEP" | jq -r '.params.key // ""')
if [[ "$KEY" != *dhcp4* ]]; then echo "FAIL: expected a dhcp4 key, got $KEY"; exit 1; fi
echo "PASS: Story 128"
