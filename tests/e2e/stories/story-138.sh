#!/usr/bin/env bash
# Story 138 (ubuntu, high-risk): Append quiet and remove splash in GRUB
# Intent: "in GRUB, append quiet to the kernel command line and delete splash"
# Distro: ubuntu
set -euo pipefail
INTENT="in GRUB, append quiet to the kernel command line and delete splash"
echo "=== Story 138 (ubuntu): GrubSetKargs ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-138-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "GrubSetKargs")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected GrubSetKargs"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
APPEND=$(echo "$STEP" | jq -c '.params.append')
if [[ "$APPEND" != '["quiet"]' ]]; then echo "FAIL: expected append=[\"quiet\"], got $APPEND"; exit 1; fi
DELETE=$(echo "$STEP" | jq -c '.params.delete')
if [[ "$DELETE" != '["splash"]' ]]; then echo "FAIL: expected delete=[\"splash\"], got $DELETE"; exit 1; fi
echo "PASS: Story 138"
