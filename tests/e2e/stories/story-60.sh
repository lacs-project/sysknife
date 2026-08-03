#!/usr/bin/env bash
# Story 60 (ubuntu, medium-risk): Autoremove unused packages
# Intent: "clean up packages that are no longer needed"
# Distro: ubuntu
#
# The risk assertion here is MEDIUM, and no model can change that. The CLI
# substitutes the daemon's ActionSpec-derived risk as the single source of truth
# (runner.rs, "planner rated {} risk; using {} (ActionSpec-derived)"), and
# apt_autoremove() declares RiskLevel::Medium — because the approved preview
# cannot show what autoremove will take, and that set has included old kernels
# and bootloader metapackages.
#
# This story asserted "low" and so could never pass, whatever the planner said.
# That is not a model failure to fix in the prompt; it was a test asserting a
# value the shipped code overrides.
set -euo pipefail
INTENT="clean up packages that are no longer needed"
echo "=== Story 60 (ubuntu): Autoremove unused packages ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-60-stderr.log)
echo "$PLAN" | jq .
ACTION=$(echo "$PLAN" | jq -r '.plan.steps[0].action')
if [[ "$ACTION" != "AptAutoremove" ]]; then echo "FAIL: expected AptAutoremove, got $ACTION"; exit 1; fi
RISK=$(echo "$PLAN" | jq -r '.plan.steps[0].risk')
if [[ "$RISK" != "medium" ]]; then echo "FAIL: expected risk medium, got $RISK"; exit 1; fi
echo "PASS: Story 60"
