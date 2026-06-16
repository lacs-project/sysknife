#!/usr/bin/env bash
# SysKnife E2E test harness — runs user stories against a provisioned VM.
#
# Usage:
#   sudo tests/e2e/run-stories.sh                    # read-only stories
#   sudo SYSKNIFE_ALLOW_DESTRUCTIVE=1 tests/e2e/run-stories.sh   # all 54
#   sudo tests/e2e/run-stories.sh 3 5 7              # run specific stories
#
# Prerequisites:
#   - /var/lib/sysknife-e2e/ready exists (provisioning complete)
#   - sysknife-daemon systemd service is running
#   - sysknife is installed in PATH
#   - Ollama is running with a model pulled
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
STORY_DIR="$SCRIPT_DIR/stories"

mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

preflight_ok=true

if [[ ! -f /var/lib/sysknife-e2e/ready ]]; then
  echo "ERROR: /var/lib/sysknife-e2e/ready not found. Run provisioning first."
  preflight_ok=false
fi

if ! systemctl is-active --quiet sysknife-daemon 2>/dev/null; then
  echo "ERROR: sysknife-daemon is not running."
  preflight_ok=false
fi

if ! command -v sysknife &>/dev/null; then
  echo "ERROR: sysknife not found in PATH."
  preflight_ok=false
fi

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq not found in PATH."
  preflight_ok=false
fi

if [[ "$preflight_ok" != "true" ]]; then
  echo ""
  echo "Preflight checks failed. Aborting."
  exit 1
fi

# ---------------------------------------------------------------------------
# LLM + daemon socket env
# ---------------------------------------------------------------------------
# BrainConfig::from_env() defaults to Anthropic, and the DaemonIpcClient
# defaults to /tmp/sysknife-daemon.sock — neither matches our provisioned VM.
# Force the right values here so individual story scripts don't need to
# know or care.
# Auto-detect provider from available API keys if not explicitly set.
if [ -z "${SYSKNIFE_LLM_PROVIDER:-}" ]; then
    if [ -n "${OPENAI_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="openai"
    elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="anthropic"
    elif [ -n "${GEMINI_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="gemini"
    else
        export SYSKNIFE_LLM_PROVIDER="ollama"
    fi
fi
export SYSKNIFE_LLM_PROVIDER
# Default model per provider when not explicitly set.
if [ -z "${SYSKNIFE_LLM_MODEL:-}" ] && [ -z "${SYSKNIFE_TEST_MODEL:-}" ]; then
    case "$SYSKNIFE_LLM_PROVIDER" in
        openai)    SYSKNIFE_LLM_MODEL="gpt-4.1" ;;
        anthropic) SYSKNIFE_LLM_MODEL="claude-sonnet-4-6" ;;
        gemini)    SYSKNIFE_LLM_MODEL="gemini-2.0-flash" ;;
        *)         SYSKNIFE_LLM_MODEL="" ;;
    esac
fi
export SYSKNIFE_LLM_MODEL="${SYSKNIFE_LLM_MODEL:-${SYSKNIFE_TEST_MODEL:-}}"
export SYSKNIFE_OLLAMA_URL="${SYSKNIFE_OLLAMA_URL:-http://127.0.0.1:11434}"
# sysknife-daemon's packaged systemd unit binds /run/sysknife/daemon.sock.
export SYSKNIFE_LISTEN_URI="${SYSKNIFE_LISTEN_URI:-unix:///run/sysknife/daemon.sock}"

# ---------------------------------------------------------------------------
# Determine which stories to run
# ---------------------------------------------------------------------------

ALLOW_DESTRUCTIVE="${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}"

# Timeout per story (seconds). With qwen3:8b on host GPU, stories
# finish in <60 s; with llama3.2:3b on 4 vCPU CPU, 2–4 min; with
# qwen3:8b on CPU, impractical. 600 s is generous for the GPU path
# and tolerant of the CPU fallback. Override with SYSKNIFE_STORY_TIMEOUT.
STORY_TIMEOUT="${SYSKNIFE_STORY_TIMEOUT:-600}"

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
STORY_NAMES[11]="Deployment status + kernel arguments"
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

declare -A RESULTS
declare -A DURATIONS
declare -A MESSAGES

if [[ $# -gt 0 ]]; then
  STORIES=("$@")
elif [[ "$ALLOW_DESTRUCTIVE" == "1" ]]; then
  STORIES=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
           21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 \
           41 42 43 44 45 46 47 48 49 50 51 52 53 54)
else
  # Read-only and non-destructive stories only. Stories self-gate via
  # SYSKNIFE_ALLOW_DESTRUCTIVE — skipped ones still appear in results as SKIP.
  STORIES=(1 2 3 4 5 6 7 11 12 13 14 15 16 17 \
           21 22 25 26 28 29 32 38 41 46 47 48 49)
fi

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_story() {
  local n="$1"
  local script="$STORY_DIR/story-${n}.sh"
  local log="$LOG_DIR/story-${n}.log"
  local name="${STORY_NAMES[$n]:-Story $n}"

  if [[ ! -f "$script" ]]; then
    RESULTS[$n]="SKIP"
    MESSAGES[$n]="script not found: $script"
    DURATIONS[$n]="0.0"
    return
  fi

  printf "  Story %2d (%-46s) " "$n" "$name"

  local start_time
  start_time=$(date +%s.%N)

  if timeout "$STORY_TIMEOUT" bash "$script" > "$log" 2>&1; then
    local last_line
    last_line=$(grep -E '^(PASS|SKIP)' "$log" | tail -1 || true)
    if [[ "$last_line" == SKIP* ]]; then
      RESULTS[$n]="SKIP"
      MESSAGES[$n]="${last_line#SKIP}"
      DURATIONS[$n]="0.0"
      echo "SKIP"
    else
      RESULTS[$n]="PASS"
      local end_time
      end_time=$(date +%s.%N)
      DURATIONS[$n]=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "?")
      echo "PASS (${DURATIONS[$n]}s)"
    fi
  else
    local exit_code=$?
    RESULTS[$n]="FAIL"
    MESSAGES[$n]=$(tail -n 5 "$log" | grep -v '^$' | tail -n 1)
    if [[ $exit_code -eq 124 ]]; then
      MESSAGES[$n]="timed out after ${STORY_TIMEOUT}s"
    fi
    local end_time
    end_time=$(date +%s.%N)
    DURATIONS[$n]=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "?")
    echo "FAIL (${DURATIONS[$n]}s)"
  fi
}

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------

echo ""
echo "SysKnife E2E Test Run"
echo "================="
echo "Date:        $(date --iso-8601=seconds)"
echo "Stories:     ${STORIES[*]}"
echo "Destructive: $ALLOW_DESTRUCTIVE"
echo "Timeout:     ${STORY_TIMEOUT}s per story"
echo ""

for n in "${STORIES[@]}"; do
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
  local_duration="${DURATIONS[$n]}"
  local_msg="${MESSAGES[$n]:-}"

  printf "  Story %2d (%-46s) " "$n" "$local_name"

  case "$local_result" in
    PASS)
      echo "PASS (${local_duration}s)"
      ((pass_count++)) || true
      ;;
    FAIL)
      echo "FAIL (${local_duration}s) — $local_msg"
      ((fail_count++)) || true
      ;;
    SKIP)
      echo "SKIP — $local_msg"
      ((skip_count++)) || true
      ;;
  esac
done

total=${#STORIES[@]}
echo ""
echo "Summary: $pass_count/$total passed, $fail_count failed, $skip_count skipped"
echo "Logs:    $LOG_DIR/"
echo ""

if [[ $fail_count -gt 0 ]]; then
  exit 1
fi
exit 0
