#!/usr/bin/env bash
# dev-stories.sh — run E2E user stories on your dev machine (no VM required).
#
# What this does:
#   1. Builds sysknife-daemon and sysknife (release mode).
#   2. Starts sysknife-daemon in the background on /tmp/sysknife-daemon.sock if it is
#      not already running there.
#   3. Runs the requested stories (default: 1-7, the read-only ones).
#   4. Stops the daemon if this script started it.
#
# Stories 1-7 validate plan structure only — they check that the LLM proposes
# the right actions, not that those actions succeed on this machine. They work
# on any Linux host regardless of whether rpm-ostree, flatpak, or podman are
# installed.
#
# Stories 8-10 are destructive (rpm-ostree layering, toolbox creation, SSH key
# writes). They also call query_* tools, and those calls will fail on a non-
# Fedora-Atomic host because the underlying commands are absent. Stories 8 and
# 10 will fail on a dev machine for this reason. Story 9 (create toolbox) may
# pass plan-structure checks. To run them anyway:
#
#   SYSKNIFE_ALLOW_DESTRUCTIVE=1 tests/e2e/dev-stories.sh 8 9 10
#
# LLM provider is auto-detected (same logic as BrainConfig::from_env):
#   - ANTHROPIC_API_KEY set  → provider=anthropic, model=claude-sonnet-4-6
#   - OPENAI_API_KEY set     → provider=openai,    model=gpt-4.1
#   - GEMINI_API_KEY set     → provider=gemini,    model=gemini-2.0-flash
#   - otherwise              → provider=ollama,    model=qwen3:8b (must be pulled)
#
# Override with SYSKNIFE_LLM_PROVIDER and SYSKNIFE_LLM_MODEL.
#
# Usage:
#   tests/e2e/dev-stories.sh            # read-only stories (default)
#   tests/e2e/dev-stories.sh 3 6 7      # specific stories
#   SYSKNIFE_ALLOW_DESTRUCTIVE=1 tests/e2e/dev-stories.sh   # all 54
#   SYSKNIFE_LLM_PROVIDER=openai OPENAI_API_KEY=sk-... tests/e2e/dev-stories.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
STORY_DIR="$SCRIPT_DIR/stories"
SOCKET_PATH="/tmp/sysknife-daemon.sock"
DAEMON_PID=""

mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Cleanup — stop the daemon if we started it
# ---------------------------------------------------------------------------

cleanup() {
    if [[ -n "$DAEMON_PID" ]]; then
        echo ""
        echo "Stopping sysknife-daemon (pid $DAEMON_PID)..."
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
        rm -f "$SOCKET_PATH" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

echo "Building sysknife-daemon and sysknife..."
cargo build -p sysknife-daemon -p sysknife-cli --release --quiet \
    --manifest-path "$REPO_ROOT/Cargo.toml"
echo "Build done."
echo ""

DAEMON_BIN="$REPO_ROOT/target/release/sysknife-daemon"

# ---------------------------------------------------------------------------
# Start daemon if not already running
# ---------------------------------------------------------------------------

if [[ -e "$SOCKET_PATH" ]]; then
    echo "sysknife-daemon socket already present at $SOCKET_PATH — skipping start."
else
    echo "Starting sysknife-daemon on $SOCKET_PATH..."
    SYSKNIFE_LISTEN_URI="unix://$SOCKET_PATH" \
    SYSKNIFE_DATABASE_PATH="/tmp/sysknife-daemon-dev.sqlite" \
        "$DAEMON_BIN" >"$LOG_DIR/daemon.log" 2>&1 &
    DAEMON_PID=$!

    # Wait up to 5 s for the socket to appear.
    local_waited=0
    while [[ ! -e "$SOCKET_PATH" ]] && (( local_waited < 50 )); do
        sleep 0.1
        (( local_waited++ )) || true
    done

    if [[ ! -e "$SOCKET_PATH" ]]; then
        echo "ERROR: sysknife-daemon did not start within 5 s."
        echo "Daemon log ($LOG_DIR/daemon.log):"
        cat "$LOG_DIR/daemon.log" || true
        exit 1
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "ERROR: sysknife-daemon process exited before socket appeared."
        echo "Daemon log ($LOG_DIR/daemon.log):"
        cat "$LOG_DIR/daemon.log" || true
        exit 1
    fi
    echo "sysknife-daemon started (pid $DAEMON_PID)."
fi
echo ""

# ---------------------------------------------------------------------------
# LLM provider auto-detection
# ---------------------------------------------------------------------------

# Respect explicit override first; then auto-detect from API keys.
if [[ -z "${SYSKNIFE_LLM_PROVIDER:-}" ]]; then
    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        export SYSKNIFE_LLM_PROVIDER="anthropic"
    elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
        export SYSKNIFE_LLM_PROVIDER="openai"
    elif [[ -n "${GEMINI_API_KEY:-}" ]]; then
        export SYSKNIFE_LLM_PROVIDER="gemini"
    else
        export SYSKNIFE_LLM_PROVIDER="ollama"
    fi
fi
export SYSKNIFE_LISTEN_URI="unix://$SOCKET_PATH"
export PATH="$REPO_ROOT/target/release:$PATH"

echo "LLM provider: $SYSKNIFE_LLM_PROVIDER, model: ${SYSKNIFE_LLM_MODEL:-<provider default>}"
echo "Daemon socket: $SOCKET_PATH"
echo ""

# ---------------------------------------------------------------------------
# Story metadata
# ---------------------------------------------------------------------------

declare -A STORY_NAMES
STORY_NAMES[1]="Check disk usage"
STORY_NAMES[2]="Memory pressure diagnosis"
STORY_NAMES[3]="Service health check"
STORY_NAMES[4]="Firewall inspection"
STORY_NAMES[5]="List layered packages"
STORY_NAMES[6]="Running containers overview"
STORY_NAMES[7]="SSH key inventory"
STORY_NAMES[8]="Layer vim via rpm-ostree (destructive)"
STORY_NAMES[9]="Create a toolbox (destructive)"
STORY_NAMES[10]="Add SSH authorized key (destructive)"
STORY_NAMES[11]="Post-update diagnostic (4-action compound)"
STORY_NAMES[12]="SysKnife activity log — today"
STORY_NAMES[13]="Service logs for firewalld"
STORY_NAMES[14]="Triple compound — disk + memory + services"
STORY_NAMES[15]="Rollback history"
STORY_NAMES[16]="Network status + firewall rules"
STORY_NAMES[17]="Container list + specific info"
STORY_NAMES[18]="Restart bluetooth service (destructive)"
STORY_NAMES[19]="Update system (destructive)"
STORY_NAMES[20]="Add user to wheel group (destructive)"
STORY_NAMES[21]="GetSystemState direct request"
STORY_NAMES[22]="ListProcesses direct"
STORY_NAMES[23]="SetTimezone — Europe/Berlin (destructive)"
STORY_NAMES[24]="StopService — cups (destructive)"
STORY_NAMES[25]="ListUsers direct"
STORY_NAMES[26]="ListUsers + ListGroups compound"
STORY_NAMES[27]="SetServiceEnabled — sshd at boot (destructive)"
STORY_NAMES[28]="GetKernelArguments + ListDeployments compound"
STORY_NAMES[29]="Triple compound — processes + network + memory"
STORY_NAMES[30]="RemoveAuthorizedKey — user alice (destructive)"
STORY_NAMES[31]="RemoveUserFromGroup — alice from docker (destructive)"
STORY_NAMES[32]="Security audit — SSH keys + users + groups"
STORY_NAMES[33]="SetKernelArguments — blacklist nouveau (destructive)"
STORY_NAMES[34]="RollbackDeployment — resist query temptation (destructive)"
STORY_NAMES[35]="ConfigureFirewall — open port 8080 (destructive)"
STORY_NAMES[36]="CreateUser — devteam account (destructive)"
STORY_NAMES[37]="DeleteUser — oldstaff removal (destructive)"
STORY_NAMES[38]="Diagnostic compound — processes + nginx logs + job history"
STORY_NAMES[39]="SetDnsServers — Cloudflare 1.1.1.1 + 1.0.0.1 (destructive)"
STORY_NAMES[40]="RebaseSystem — Fedora Silverblue 41 (destructive)"
STORY_NAMES[41]="Read compound — repos + containers + network"
STORY_NAMES[42]="MaskService cups — not SetServiceEnabled (destructive)"
STORY_NAMES[43]="CleanupDeployments — free deployment disk (destructive)"
STORY_NAMES[44]="SetHostname — workstation-42 (destructive)"
STORY_NAMES[45]="RebootSystem — kernel activation framing (destructive)"
STORY_NAMES[46]="GetPendingUpdates — check not apply"
STORY_NAMES[47]="ListInstalledFlatpaks — local vs remote"
STORY_NAMES[48]="GetServiceStatus — nginx single unit"
STORY_NAMES[49]="ListTimers — scheduled tasks"
STORY_NAMES[50]="ReloadService — nginx without restart (destructive)"
STORY_NAMES[51]="ReloadDaemon — after unit file creation (destructive)"
STORY_NAMES[52]="UpdateFlatpak — Firefox (destructive)"
STORY_NAMES[53]="RemoveBasePackage — gedit from base image (destructive)"
STORY_NAMES[54]="UpdateFlatpak — update all, no specific app (destructive)"

ALLOW_DESTRUCTIVE="${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}"
STORY_TIMEOUT="${SYSKNIFE_STORY_TIMEOUT:-120}"
# Delay between stories (seconds). Avoids TPM rate-limit errors when running
# all 20 stories back-to-back against a cloud LLM. Each story uses
# ~3 K tokens; at 30 K TPM the safe cadence is one story per ~6 s.
# Default 10 s is conservative; set SYSKNIFE_STORY_DELAY=0 to disable.
STORY_DELAY="${SYSKNIFE_STORY_DELAY:-10}"

declare -a STORIES
declare -A RESULTS
declare -A DURATIONS
declare -A MESSAGES

if [[ $# -gt 0 ]]; then
    STORIES=("$@")
elif [[ "$ALLOW_DESTRUCTIVE" == "1" ]]; then
    STORIES=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54)
else
    STORIES=(1 2 3 4 5 6 7 11 12 13 14 15 16 17 21 22 25 26 28 29 32 38 41 46 47 48 49)
fi

# ---------------------------------------------------------------------------
# Story runner
# ---------------------------------------------------------------------------

run_story() {
    local n="$1"
    local name="${STORY_NAMES[$n]:-Story $n}"
    local log="$LOG_DIR/story-${n}.log"
    local script="$STORY_DIR/story-${n}.sh"

    printf "Story %2d  %-46s " "$n" "(${name})"

    if [[ ! -f "$script" ]]; then
        RESULTS[$n]="FAIL"
        MESSAGES[$n]="script not found: $script"
        echo "FAIL — script not found"
        return
    fi

    local start_time exit_code
    start_time=$(date +%s.%N)
    set +e
    timeout "$STORY_TIMEOUT" bash "$script" >"$log" 2>&1
    exit_code=$?
    set -e
    local end_time elapsed
    end_time=$(date +%s.%N)
    elapsed=$(awk "BEGIN{printf \"%.1f\", $end_time - $start_time}" 2>/dev/null || echo "?")
    DURATIONS[$n]="$elapsed"

    if [[ $exit_code -eq 0 ]]; then
        # Check the last line for PASS/SKIP markers.
        local last_line
        last_line=$(grep -E '^(PASS|SKIP)' "$log" | tail -1 || true)
        if [[ "$last_line" == SKIP* ]]; then
            RESULTS[$n]="SKIP"
            MESSAGES[$n]="${last_line#SKIP}"
            echo "SKIP"
        else
            RESULTS[$n]="PASS"
            echo "PASS (${elapsed}s)"
        fi
    else
        RESULTS[$n]="FAIL"
        MESSAGES[$n]=$(tail -n 5 "$log" | grep -v '^$' | tail -n 1 || true)
        if [[ $exit_code -eq 124 ]]; then
            MESSAGES[$n]="timed out after ${STORY_TIMEOUT}s"
        fi
        echo "FAIL (${elapsed}s)"
    fi
}

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------

echo "SysKnife Dev Story Run"
echo "=================="
echo "Date:        $(date --iso-8601=seconds 2>/dev/null || date)"
echo "Stories:     ${STORIES[*]}"
echo "Destructive: $ALLOW_DESTRUCTIVE"
echo "Timeout:     ${STORY_TIMEOUT}s per story"
echo "Delay:       ${STORY_DELAY}s between stories"
echo ""

first=1
for n in "${STORIES[@]}"; do
    if [[ "$first" == "1" ]]; then
        first=0
    elif [[ "$STORY_DELAY" -gt 0 ]]; then
        sleep "$STORY_DELAY"
    fi
    run_story "$n"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "================================================================"
echo "  RESULTS"
echo "================================================================"

pass_count=0
fail_count=0
skip_count=0

for n in "${STORIES[@]}"; do
    local_name="${STORY_NAMES[$n]:-Story $n}"
    local_result="${RESULTS[$n]}"
    local_duration="${DURATIONS[$n]:-?}"
    local_msg="${MESSAGES[$n]:-}"

    printf "  Story %2d  %-46s " "$n" "(${local_name})"
    case "$local_result" in
        PASS)
            echo "PASS (${local_duration}s)"
            (( pass_count++ )) || true
            ;;
        FAIL)
            echo "FAIL (${local_duration}s) — $local_msg"
            (( fail_count++ )) || true
            ;;
        SKIP)
            echo "SKIP$local_msg"
            (( skip_count++ )) || true
            ;;
    esac
done

total=${#STORIES[@]}
echo ""
echo "Summary: $pass_count/$total passed, $fail_count failed, $skip_count skipped"
echo "Logs:    $LOG_DIR/"
echo ""

if (( fail_count > 0 )); then
    echo "NOTE: On a non-Fedora-Atomic host, stories 8 and 10 are expected to fail"
    echo "because query_packages and query_authorized_keys call rpm-ostree and SSH"
    echo "tools that are absent. Stories 1-7, 11-17, and 21-22, 25-26, 28-29 should"
    echo "always pass on any Linux host (plan-structure checks only, no execution)."
    echo "Run on a provisioned Silverblue VM for full coverage."
    echo ""
    exit 1
fi
exit 0
