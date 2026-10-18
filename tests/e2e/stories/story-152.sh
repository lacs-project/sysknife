#!/usr/bin/env bash
# Story 152 (ubuntu, high-risk): Grant a scoped sudo rule
# Intent: "grant the user deploy a sudo rule named deploy-restart to run /usr/bin/systemctl"
# Distro: ubuntu
# The near miss is RevokeSudoAccess, which removes a drop-in instead of creating
# one. An imperative "grant ..." must plan GrantSudoAccess. This action
# configures privilege escalation, so it is High risk. The grant stays
# password-protected (no nopasswd), which the daemon also requires when the
# command is a program that can spawn other programs.
set -euo pipefail
INTENT="grant the user deploy a sudo rule named deploy-restart to run /usr/bin/systemctl"
echo "=== Story 152 (ubuntu): GrantSudoAccess ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-152-stderr.log)
echo "$PLAN" | jq .

STEP_COUNT=$(echo "$PLAN" | jq '.plan.steps | length')
if [[ "$STEP_COUNT" != "1" ]]; then echo "FAIL: expected 1 step, got $STEP_COUNT"; exit 1; fi
STEP=$(echo "$PLAN" | jq '.plan.steps[0] | select(.action == "GrantSudoAccess")')
if [[ -z "$STEP" || "$STEP" == "null" ]]; then echo "FAIL: expected GrantSudoAccess"; exit 1; fi
RISK=$(echo "$STEP" | jq -r '.risk')
if [[ "$RISK" != "high" ]]; then echo "FAIL: expected risk high, got $RISK"; exit 1; fi
NAME=$(echo "$STEP" | jq -r '.params.name // ""')
if [[ "$NAME" != "deploy-restart" ]]; then echo "FAIL: expected name=deploy-restart, got $NAME"; exit 1; fi
USER=$(echo "$STEP" | jq -r '.params.user // ""')
if [[ "$USER" != "deploy" ]]; then echo "FAIL: expected user=deploy, got $USER"; exit 1; fi
COMMANDS=$(echo "$STEP" | jq -r '.params.commands // ""')
if [[ "$COMMANDS" != "/usr/bin/systemctl" ]]; then echo "FAIL: expected commands=/usr/bin/systemctl, got $COMMANDS"; exit 1; fi
if echo "$PLAN" | jq -e '.plan.steps[] | select(.action == "RevokeSudoAccess")' >/dev/null; then
  echo "FAIL: plan contains RevokeSudoAccess instead of only GrantSudoAccess"; exit 1
fi
echo "PASS: Story 152"
