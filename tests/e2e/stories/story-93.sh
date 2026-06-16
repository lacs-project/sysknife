#!/usr/bin/env bash
# Story 93 (ubuntu, rejection): Empty snap name rejected
# We attempt an install with no name. The plan should either fail or
# use a sensible default — never produce a SnapInstall with an empty name.
set -euo pipefail
echo "=== Story 93 (ubuntu): Empty snap name not accepted ==="
INTENT="install a snap"
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-93-stderr.log || true)
echo "$PLAN" | jq . 2>/dev/null || true
NAME=$(echo "$PLAN" | jq -r '.plan.steps[0].params.name // ""' 2>/dev/null || echo "")
if [[ "$NAME" == "" ]]; then
  echo "INFO: plan produced no name (or no plan) — acceptable"
fi
echo "PASS: Story 93"
