#!/usr/bin/env bash
# Deterministic, offline reproduction of a Claude Code MCP session using
# SysKnife tools: sysknife_plan + sysknife_execute.
#
# Used solely to render assets/demo/mcp-flow.gif via VHS.
# No live LLM calls, no daemon, no network — fully reproducible.
#
# Styling mimics Claude Code's TUI: ⏺ tool-call bullets, bordered result
# blocks, bold user turns, dim assistant text.
set -u

# Brand palette (24-bit ANSI):
COAT=$'\033[38;2;255;167;38m'    # vivid orange (Material Orange 400)
MINT=$'\033[38;2;0;229;176m'     # vivid teal (Material Teal A400-ish)
DIM=$'\033[2m'
BOLD=$'\033[1m'
GREEN=$'\033[38;2;105;240;174m'  # bright spring green (Material Green A200)
YELLOW=$'\033[38;2;255;213;79m'  # vivid amber-yellow (Material Amber 300)
RED=$'\033[38;2;255;82;82m'      # vivid red (Material Red A200)
PURPLE=$'\033[38;2;179;136;255m' # accent purple (for plan_id)
RESET=$'\033[0m'
ITALIC=$'\033[3m'

cprint() { printf '%s%s%s\n' "$1" "$2" "$RESET"; }
sleep_ms() { sleep "$(awk -v ms="$1" 'BEGIN{printf "%.3f", ms/1000}')"; }

# ── header bar — mimics `claude` startup ─────────────────────────────────
clear
printf '%s╭─────────────────────────────────────────────────────────────────╮%s\n' "$DIM" "$RESET"
printf '%s│%s  %s✦ claude%s%s                                                        │%s\n' \
    "$DIM" "$RESET" "$COAT$BOLD" "$RESET" "$DIM" "$RESET"
printf '%s│%s  %sSysKnife MCP connected%s%s  ·  sysknife_plan  sysknife_execute     │%s\n' \
    "$DIM" "$RESET" "$MINT" "$RESET" "$DIM" "$RESET"
printf '%s╰─────────────────────────────────────────────────────────────────╯%s\n' "$DIM" "$RESET"
sleep_ms 600

# ── user turn ────────────────────────────────────────────────────────────
echo
printf '%s> %s%s\n' "$BOLD" \
    'install vim, restart sshd, and show me the firewall state' "$RESET"
sleep_ms 600

# ── assistant acknowledges ───────────────────────────────────────────────
echo
printf '%sI'\''ll plan those three actions through SysKnife.%s\n' "$DIM" "$RESET"
sleep_ms 450

# ── tool call: sysknife_plan — spinner ───────────────────────────────────
echo
spinner_chars=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
# ~2 seconds total at 120ms per tick = ~17 ticks
for i in $(seq 1 17); do
    idx=$(( (i - 1) % 10 ))
    printf '\r%s⏺%s %ssysknife_plan%s(intent="install vim, restart sshd, and show me the firewall state") %s%s%s' \
        "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "${spinner_chars[$idx]}" "$RESET"
    sleep_ms 120
done
printf '\r\033[K'

printf '%s⏺%s %ssysknife_plan%s(intent="install vim, restart sshd, and show me the firewall state")\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET"
sleep_ms 300

# ── tool result block — plan card ────────────────────────────────────────
printf '%s┌─ Result ──────────────────────────────────────────────────────────┐%s\n' "$DIM" "$RESET"
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %splan_id%s  %sp_8a3d1f9c%s\n' "$DIM" "$RESET" "$DIM" "$RESET" "$PURPLE" "$RESET"
printf '%s│%s  %sintent%s   %s"install vim, restart sshd, and show me the firewall state"%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$ITALIC" "$RESET"
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s1%s  %sAddLayeredPackage%s             %s● medium%s  %sapproval required%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
printf '%s│%s     %slayer vim into next deployment via rpm-ostree%s\n' "$DIM" "$RESET" "$DIM" "$RESET"
printf '%s│%s  %s2%s  %sRestartService%s                %s● medium%s  %sapproval required%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
printf '%s│%s     %srestart sshd and verify it comes back active%s\n' "$DIM" "$RESET" "$DIM" "$RESET"
printf '%s│%s  %s3%s  %sGetFirewallState%s              %s● low%s     %sauto%s\n' \
    "$DIM" "$RESET" "$DIM" "$RESET" "$BOLD" "$RESET" "$GREEN" "$RESET" "$DIM" "$RESET"
printf '%s│%s     %sread firewalld zones and active services%s\n' "$DIM" "$RESET" "$DIM" "$RESET"
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s└───────────────────────────────────────────────────────────────────┘%s\n' "$DIM" "$RESET"
sleep_ms 700

# ── assistant presents plan + approval ───────────────────────────────────
echo
printf 'SysKnife has a 3-step plan ready:\n'
sleep_ms 300
printf '  %s1.%s Layer vim (medium risk — triggers a pending reboot)\n' "$BOLD" "$RESET"
sleep_ms 225
printf '  %s2.%s Restart sshd (medium risk — brief connection drop)\n' "$BOLD" "$RESET"
sleep_ms 225
printf '  %s3.%s Read firewall state (low risk — read-only, runs automatically)\n' "$BOLD" "$RESET"
sleep_ms 525
echo
printf '%sShould I run sysknife_execute on these 3 steps? (y/n)%s ' "$BOLD" "$RESET"
sleep_ms 525
printf '%sy%s\n' "$COAT" "$RESET"
sleep_ms 450

# ── tool call: sysknife_execute — spinner ────────────────────────────────
echo
for i in $(seq 1 17); do
    idx=$(( (i - 1) % 10 ))
    printf '\r%s⏺%s %ssysknife_execute%s(plan_id="p_8a3d1f9c") %s%s%s' \
        "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "${spinner_chars[$idx]}" "$RESET"
    sleep_ms 120
done
printf '\r\033[K'

printf '%s⏺%s %ssysknife_execute%s(plan_id="p_8a3d1f9c")\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET"
sleep_ms 300

# ── streaming execution output ────────────────────────────────────────────
printf '%s┌─ Streaming ────────────────────────────────────────────────────────┐%s\n' "$DIM" "$RESET"

# Step 1
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s▶%s %sAddLayeredPackage%s  %slayering vim into next deployment%s\n' \
    "$DIM" "$RESET" "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 450
printf '%s│%s  › Checking out tree dabb04b... done\n' "$DIM" "$RESET";          sleep_ms 375
printf '%s│%s  › Resolving dependencies... done\n' "$DIM" "$RESET";            sleep_ms 375
printf '%s│%s  › Adding layer: vim-9.1.0-2.fc41.x86_64\n' "$DIM" "$RESET";    sleep_ms 375
printf '%s│%s  › Writing objects: 100%% (37/37) done\n' "$DIM" "$RESET";      sleep_ms 450
printf '%s│%s  %s✓%s  layered vim — succeeded\n' "$DIM" "$RESET" "$GREEN" "$RESET"
printf '%s│%s    %s⚠ reboot required for layered packages%s\n' "$DIM" "$RESET" "$YELLOW" "$RESET"
printf '%s│%s    job  abf7c8d2-4a91-43e0-9b21-7c0f17ad7f3e\n' "$DIM" "$RESET"
sleep_ms 1500

# Step 2
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s▶%s %sRestartService%s  %srestart sshd, verify post-state%s\n' \
    "$DIM" "$RESET" "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 375
printf '%s│%s  › systemctl restart sshd.service\n' "$DIM" "$RESET";           sleep_ms 375
printf '%s│%s  › Waiting for unit to enter active... ok (0.31s)\n' "$DIM" "$RESET"; sleep_ms 375
printf '%s│%s  › sshd.service: active (running) since 19:42:08\n' "$DIM" "$RESET"; sleep_ms 300
printf '%s│%s  %s✓%s  sshd active — succeeded\n' "$DIM" "$RESET" "$GREEN" "$RESET"
printf '%s│%s    job  3e1b9aa5-d8e2-4f30-8e7c-1062c4517e91\n' "$DIM" "$RESET"
sleep_ms 1500

# Step 3
printf '%s│%s\n' "$DIM" "$RESET"
printf '%s│%s  %s▶%s %sGetFirewallState%s  %sread firewalld zones%s\n' \
    "$DIM" "$RESET" "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 375
printf '%s│%s  › active zones: FedoraWorkstation\n' "$DIM" "$RESET";          sleep_ms 300
printf '%s│%s  › services: dhcpv6-client mdns samba-client ssh\n' "$DIM" "$RESET"; sleep_ms 300
printf '%s│%s  › default zone: FedoraWorkstation\n' "$DIM" "$RESET";          sleep_ms 300
printf '%s│%s  %s✓%s  firewall read — succeeded\n' "$DIM" "$RESET" "$GREEN" "$RESET"
printf '%s│%s    job  9c44f7be-2f88-49a4-b0a2-3df4e6c1d2ab\n' "$DIM" "$RESET"
sleep_ms 1500

printf '%s│%s\n' "$DIM" "$RESET"
printf '%s└───────────────────────────────────────────────────────────────────┘%s\n' "$DIM" "$RESET"
sleep_ms 700

# ── final assistant summary ───────────────────────────────────────────────
echo
printf '%sDone.%s vim is layered, sshd is restarted and active, firewall is on\n' "$BOLD" "$RESET"
printf 'FedoraWorkstation zone with ssh open.\n'
sleep_ms 450
printf '%sNote:%s a reboot is pending to activate the layered vim package.\n' "$YELLOW" "$RESET"
sleep_ms 600
echo
printf '%saudit  3 entries  hash a31f…cb02%s\n' "$DIM" "$RESET"
sleep_ms 3000
