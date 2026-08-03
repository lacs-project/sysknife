#!/usr/bin/env bash
# Story 103 (ubuntu, medium-risk): Pin then show info (compound read+mutate)
# Intent: "pin mysql-server and show me its details"
# Distro: ubuntu
#
# Two actions legitimately answer "pin", and this story accepts either:
#
#   AptHold    — `apt-mark hold`, marks the package so apt refuses to change it
#   SetAptPin  — an apt preferences entry in /etc/apt/preferences.d
#
# In apt's own vocabulary "pin" *is* the preferences mechanism, so SetAptPin is
# the more literal reading of the word the user typed; hold is what story 61
# covers, where the user says "freeze". Demanding AptHold here would assert a
# distinction the prompt never draws and the intent does not carry.
#
# This is not the broadening CLAUDE.md warns about: both actions exist, both are
# the right shape of answer, and the story stays strict on everything that
# matters — the pin must name mysql-server, and the details step must be there.
set -euo pipefail
INTENT="pin mysql-server and show me its details"
echo "=== Story 103 (ubuntu): Pin + AptShow for mysql-server ==="
PLAN=$(sysknife --dry-run --json "$INTENT" 2>/tmp/sysknife-story-103-stderr.log)
echo "$PLAN" | jq .
PIN=$(echo "$PLAN" | jq '[.plan.steps[]
  | select(.action == "AptHold" or .action == "SetAptPin")] | length')
SHOW=$(echo "$PLAN" | jq '.plan.steps[] | select(.action == "AptShow")')
if [[ "${PIN:-0}" -lt 1 ]]; then echo "FAIL: no AptHold or SetAptPin step"; exit 1; fi
if [[ -z "$SHOW" || "$SHOW" == "null" ]]; then echo "FAIL: missing AptShow step"; exit 1; fi

# Whichever action was chosen, it has to pin the package that was asked for.
PINNED=$(echo "$PLAN" | jq -r '[.plan.steps[]
  | select(.action == "AptHold" or .action == "SetAptPin")
  | ((.params.package // "") | tostring)] | unique | join(",")')
if [[ "$PINNED" != "mysql-server" ]]; then
  echo "FAIL: pin step names package '$PINNED', expected mysql-server"
  exit 1
fi
echo "PASS: Story 103 (pinned via $(echo "$PLAN" | jq -r '[.plan.steps[] | select(.action == "AptHold" or .action == "SetAptPin") | .action] | join(",")'))"
