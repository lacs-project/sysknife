#!/usr/bin/env bash
# Story 95 (ubuntu, medium-risk): Install multiple essential tools
# Intent: "install git, curl, and wget"
# Distro: ubuntu — expect 3 AptInstall steps OR a single apt call with all packages
set -euo pipefail
INTENT="install git, curl, and wget"
echo "=== Story 95 (ubuntu): Install git+curl+wget ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-95-stderr.log)
echo "$PLAN" | jq .
INSTALL_COUNT=$(echo "$PLAN" | jq '[.plan.steps[] | select(.action == "AptInstall")] | length')
if [[ "$INSTALL_COUNT" -lt 1 ]]; then echo "FAIL: no AptInstall steps for git+curl+wget"; exit 1; fi
echo "PASS: Story 95 ($INSTALL_COUNT AptInstall step(s))"
