#!/usr/bin/env bash
# Deterministic, offline reproduction of a real `sysknife` planning + execution
# session, used solely to render assets/demo/demo.gif via VHS.
#
# Why a mock and not the live CLI?
#   - LLM calls are slow, costly, and nondeterministic — a recording must be
#     reproducible from a fresh checkout.
#   - The .tape needs to render without any daemon/socket/provider configured.
#
# Output styling matches apps/sysknife-cli/src/render.rs (risk badges, ▶ step
# header, › output line, ✓ success summary).
set -u

# Brand palette (24-bit ANSI):
COAT=$'\033[38;2;255;167;38m'    # vivid orange (Material Orange 400)
SADDLE=$'\033[38;2;0;229;176m'   # vivid teal (Material Teal A400-ish)
DIM=$'\033[2m'
BOLD=$'\033[1m'
GREEN=$'\033[38;2;105;240;174m'  # bright spring green (Material Green A200)
YELLOW=$'\033[38;2;255;213;79m'  # vivid amber-yellow (Material Amber 300)
RED=$'\033[38;2;255;82;82m'      # vivid red (Material Red A200)
CYAN=$'\033[38;2;0;229;176m'     # vivid teal for step headers
RESET=$'\033[0m'

cprint() { printf '%s%s%s\n' "$1" "$2" "$RESET"; }
sleep_ms() { sleep "$(awk -v ms="$1" 'BEGIN{printf "%.3f", ms/1000}')"; }

# ── Render a fake prompt + invocation so the recording reads as one session.
# We do this in-script (rather than typing it via the .tape) to avoid the
# `command not found` line that a real shell would emit when sysknife is not
# installed on the recording host.
clear
printf '%s$%s sysknife "install vim, restart sshd, and show me the firewall state"\n' \
    "$DIM" "$RESET"
sleep_ms 1200

# 1. Planning spinner — ~2s, ~17 frames at 120 ms each.
spinner_chars=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
for i in $(seq 1 17); do
    idx=$(( (i - 1) % 10 ))
    printf '\r%s%s%s planning...' "$COAT" "${spinner_chars[$idx]}" "$RESET"
    sleep_ms 120
done
printf '\r\033[K'  # clear spinner line

# 2. Plan card — matches print_plan() format.
echo
printf '  %sinstall vim, restart sshd, and show the firewall state%s\n' "$BOLD" "$RESET"
printf '  %s──────────────────────────────────────────────────%s\n' "$DIM" "$RESET"
printf '  %s1%s  %sAddLayeredPackage%s             %s● medium%s  %sapproval required%s\n' \
    "$DIM" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
printf '     %slayer vim into the next deployment via rpm-ostree%s\n' "$DIM" "$RESET"
printf '  %s2%s  %sRestartService%s                %s● medium%s  %sapproval required%s\n' \
    "$DIM" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$RESET" "$YELLOW" "$RESET"
printf '     %srestart sshd and verify it comes back active%s\n' "$DIM" "$RESET"
printf '  %s3%s  %sGetFirewallState%s              %s● low%s     %sauto%s\n' \
    "$DIM" "$RESET" "$BOLD" "$RESET" "$GREEN" "$RESET" "$DIM" "$RESET"
printf '     %sread firewalld zones and active services%s\n' "$DIM" "$RESET"
echo

# 3. Approval prompt — the .tape types "y" before this resolves.
printf '%sapprove plan? [y/N]: y%s\n' "$BOLD" "$RESET"
sleep_ms 525

# 4. Step 1 execution.
printf '\n  %s▶%s %sAddLayeredPackage%s  %slayering vim into next deployment%s\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 900
printf '  › Checking out tree dabb04b... done\n';            sleep_ms 525
printf '  › Importing rpm sig 0x12c944d0\n';                 sleep_ms 525
printf '  › Resolving dependencies... done\n';               sleep_ms 525
printf '  › Adding layer: vim-9.1.0-2.fc41.x86_64\n';        sleep_ms 525
printf '  › Writing objects: 100%% (37/37) done\n';          sleep_ms 600
printf '  %s✓%s  layered vim — succeeded\n' "$GREEN" "$RESET"
printf '    %s⚠ reboot required for layered packages%s\n' "$YELLOW" "$RESET"
printf '    job  abf7c8d2-4a91-43e0-9b21-7c0f17ad7f3e\n'
sleep_ms 1500

# 5. Step 2 execution.
printf '\n  %s▶%s %sRestartService%s  %srestart sshd, verify post-state%s\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 750
printf '  › systemctl restart sshd.service\n';               sleep_ms 525
printf '  › Waiting for unit to enter active... ok (0.31s)\n';  sleep_ms 600
printf '  › sshd.service: active (running) since 19:42:08\n'; sleep_ms 525
printf '  %s✓%s  sshd active — succeeded\n' "$GREEN" "$RESET"
printf '    job  3e1b9aa5-d8e2-4f30-8e7c-1062c4517e91\n'
sleep_ms 1500

# 6. Step 3 execution.
printf '\n  %s▶%s %sGetFirewallState%s  %sread firewalld zones%s\n' \
    "$COAT" "$RESET" "$BOLD" "$RESET" "$DIM" "$RESET"
sleep_ms 750
printf '  › active zones: FedoraWorkstation\n';              sleep_ms 525
printf '  › services: dhcpv6-client mdns samba-client ssh\n'; sleep_ms 525
printf '  › default zone: FedoraWorkstation\n';              sleep_ms 525
printf '  %s✓%s  firewall read — succeeded\n' "$GREEN" "$RESET"
printf '    job  9c44f7be-2f88-49a4-b0a2-3df4e6c1d2ab\n'
sleep_ms 1500

# 7. Final summary + audit chain marker.
printf '\n%s✓%s  succeeded  18.4s\n\n' "$GREEN" "$RESET"
printf '%saudit  3 entries appended  hash a31f…cb02%s\n' "$DIM" "$RESET"
sleep_ms 3000
