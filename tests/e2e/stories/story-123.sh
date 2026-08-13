#!/usr/bin/env bash
# Story 123 (ubuntu, high-risk): Add a Launchpad PPA
# Intent: "add the deadsnakes/ppa launchpad PPA to this machine"
# Distro: ubuntu
# High: a PPA is a third-party signing key plus package source, so everything
# installed afterwards is trusted from it.
set -euo pipefail
INTENT="add the deadsnakes/ppa launchpad PPA to this machine"
echo "=== Story 123 (ubuntu): AddPpa ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-123-stderr.log)
echo "$PLAN" | jq .
STEP=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AddPpa")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: no AddPpa step"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "deadsnakes/ppa" ]]; then echo "FAIL: expected name=deadsnakes/ppa, got $NAME"; exit 1; fi
echo "PASS: Story 123"
