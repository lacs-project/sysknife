#!/usr/bin/env bash
# Deterministic, offline reproduction of a Claude Code MCP session on Ubuntu
# using SysKnife tools: sysknife_plan + sysknife_execute.
#
# Used solely to render assets/demo/ubuntu-flow.gif via VHS.
# No live LLM calls, no daemon, no network — fully reproducible.
#
# Ubuntu counterpart to mcp-flow-mock.sh. Every action name, risk level and
# underlying command below is the one the catalogue actually carries:
#
#   UfwAllow    `sudo ufw allow 22`                          High    Ubuntu
#   AptInstall  `sudo env DEBIAN_FRONTEND=noninteractive …`   Medium  Ubuntu
#   UfwStatus   `sudo ufw status verbose`                     Low     Ubuntu
#
# `GetFirewallState` is deliberately absent: it runs firewall-cmd, which is
# firewalld, so it has no meaning on an Ubuntu host. Kept short on purpose —
# under 400 frames so the GIF animates in a LinkedIn post rather than freezing
# on frame one.
set -u

COAT=$'\033[38;2;255;167;38m'    # vivid orange (Material Orange 400)
MINT=$'\033[38;2;0;229;176m'     # vivid teal
DIM=$'\033[2m'
BOLD=$'\033[1m'
GREEN=$'\033[38;2;105;240;174m'
YELLOW=$'\033[38;2;255;213;79m'
RED=$'\033[38;2;255;107;107m'
PURPLE=$'\033[38;2;179;136;255m'
RESET=$'\033[0m'

sleep_ms() { sleep "$(awk -v ms="$1" 'BEGIN{printf "%.3f", ms/1000}')"; }

# ── header bar — mimics `claude` startup ─────────────────────────────────
clear
printf '%s╭─────────────────────────────────────────────────────────────────╮%s\n' "$DIM" "$RESET"
printf '%s│%s  %s✦ claude%s%s                                                        │%s\n' \
    "$DIM" "$RESET" "$COAT$BOLD" "$RESET" "$DIM" "$RESET"
printf '%s│%s  %sSysKnife MCP connected%s%s  ·  Ubuntu 24.04 LTS  ·  sysknife_plan   │%s\n' \
    "$DIM" "$RESET" "$MINT" "$RESET" "$DIM" "$RESET"
printf '%s╰─────────────────────────────────────────────────────────────────╯%s\n' "$DIM" "$RESET"
sleep_ms 500

# ── user turn ────────────────────────────────────────────────────────────
echo
printf '%s> %sopen port 22, install curl, and show me the firewall%s\n' "$BOLD" "" "$RESET"
sleep_ms 500

# ── tool call: sysknife_plan — spinner ───────────────────────────────────
echo
spinner_chars=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
for i in $(seq 1 10); do
    idx=$(( (i - 1) % 10 ))
    printf '\r%s⏺%s %ssysknife_plan%s(intent="open port 22, install curl, and show me the firewall") %s%s%s' \
        "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "${spinner_chars[$idx]}" "$RESET"
    sleep_ms 110
done
printf '\r\033[K'
printf '%s⏺%s %ssysknife_plan%s(intent="open port 22, install curl, and show me the firewall")\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET"
sleep_ms 200

# ── tool result block — plan card ────────────────────────────────────────
printf '%s┌─ Result ──────────────────────────────────────────────────────────┐%s\n' "$DIM" "$RESET"
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s1%s  %sUfwAllow%s                      %s● high%s    %sapproval required%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$BOLD" "$RESET" "$RED" "$RESET" "$YELLOW" "$RESET"
printf '%s│%s     %stx_4e81b3 · allow 22/tcp through ufw%s\n' "$DIM" "$RESET" "$PURPLE" "$RESET"
printf '%s│%s  %s2%s  %sAptInstall%s                    %s● medium%s  %sapproval required%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
printf '%s│%s     %stx_c07a29 · apt-get install -y curl%s\n' "$DIM" "$RESET" "$PURPLE" "$RESET"
printf '%s│%s  %s3%s  %sUfwStatus%s                     %s● low%s     %sreceipt required%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$BOLD" "$RESET" "$GREEN" "$RESET" "$YELLOW" "$RESET"
printf '%s│%s     %stx_9b6f14 · ufw status verbose%s\n' "$DIM" "$RESET" "$PURPLE" "$RESET"
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s└───────────────────────────────────────────────────────────────────┘%s\n' "$DIM" "$RESET"
sleep_ms 2600

# ── the approval boundary ────────────────────────────────────────────────
echo
printf '%sChat approval is not enough.%s Approve each transaction in a terminal:\n' "$YELLOW" "$RESET"
sleep_ms 400
printf '%s$%s sysknife approve tx_4e81b3\n' "$MINT" "$RESET"; sleep_ms 260
printf '  receipt  %srcpt_4e81…c7d5%s\n' "$PURPLE" "$RESET"; sleep_ms 200
printf '%s$%s sysknife approve tx_c07a29\n' "$MINT" "$RESET"; sleep_ms 260
printf '  receipt  %srcpt_c07a…19be%s\n' "$PURPLE" "$RESET"; sleep_ms 200
printf '%s$%s sysknife approve tx_9b6f14\n' "$MINT" "$RESET"; sleep_ms 260
printf '  receipt  %srcpt_9b6f…8a03%s\n' "$PURPLE" "$RESET"; sleep_ms 400
printf '%sPreview-bound, single use, 15 minutes.%s\n' "$DIM" "$RESET"
sleep_ms 700

# ── tool call: sysknife_execute ──────────────────────────────────────────
echo
for i in $(seq 1 8); do
    idx=$(( (i - 1) % 10 ))
    printf '\r%s⏺%s %ssysknife_execute%s(steps=[tx_4e81b3, tx_c07a29, tx_9b6f14] + receipts) %s%s%s' \
        "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "${spinner_chars[$idx]}" "$RESET"
    sleep_ms 110
done
printf '\r\033[K'
printf '%s⏺%s %ssysknife_execute%s(steps=[transaction_id + approval_receipt] × 3)\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET"
sleep_ms 200

printf '%s┌─ Streaming ────────────────────────────────────────────────────────┐%s\n' "$DIM" "$RESET"
printf '%s│%s  %s▶%s %sUfwAllow%s  %ssudo ufw allow 22%s\n' \
    "$DIM" "$RESET" "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 300
printf '%s│%s  › Rule added\n' "$DIM" "$RESET";                                sleep_ms 260
printf '%s│%s  › Rule added (v6)\n' "$DIM" "$RESET";                           sleep_ms 260
printf '%s│%s  %s✓%s  22/tcp allowed — succeeded\n' "$DIM" "$RESET" "$GREEN" "$RESET"
sleep_ms 600

printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s▶%s %sAptInstall%s  %sapt-get install -y curl%s\n' \
    "$DIM" "$RESET" "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 300
printf '%s│%s  › Reading package lists... Done\n' "$DIM" "$RESET";             sleep_ms 260
printf '%s│%s  › Setting up curl (8.5.0-2ubuntu10.6)\n' "$DIM" "$RESET";       sleep_ms 260
printf '%s│%s  › Processing triggers for man-db\n' "$DIM" "$RESET";            sleep_ms 260
printf '%s│%s  %s✓%s  curl installed — succeeded\n' "$DIM" "$RESET" "$GREEN" "$RESET"
sleep_ms 600

printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s▶%s %sUfwStatus%s  %ssudo ufw status verbose%s\n' \
    "$DIM" "$RESET" "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 300
printf '%s│%s  › Status: active\n' "$DIM" "$RESET";                            sleep_ms 240
printf '%s│%s  › Default: deny (incoming), allow (outgoing)\n' "$DIM" "$RESET"; sleep_ms 240
printf '%s│%s  › 22/tcp  ALLOW IN  Anywhere\n' "$DIM" "$RESET";                sleep_ms 240
printf '%s│%s  %s✓%s  firewall read — succeeded\n' "$DIM" "$RESET" "$GREEN" "$RESET"
sleep_ms 500
printf '%s└───────────────────────────────────────────────────────────────────┘%s\n' "$DIM" "$RESET"
sleep_ms 500

echo
printf '%sReceipts consumed — replay now returns stale_approval.%s\n' "$DIM" "$RESET"
sleep_ms 300
printf '%saudit  3 entries  hash 7c1e…9fa4%s\n' "$DIM" "$RESET"
sleep_ms 2200
