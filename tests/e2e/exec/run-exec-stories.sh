#!/usr/bin/env bash
# SysKnife Tier 4 execution E2E harness.
#
# Each exec story runs `sysknife <intent>` (no --dry-run) and asserts on
# real system state changes — filesystem, /etc/passwd, command output.
#
# Usage:
#   sudo tests/e2e/exec/run-exec-stories.sh                 # safe stories only
#   sudo SYSKNIFE_ALLOW_DESTRUCTIVE=1 \
#        tests/e2e/exec/run-exec-stories.sh                 # all 6 exec stories
#   sudo tests/e2e/exec/run-exec-stories.sh 1 3 6           # specific stories
#
# Prerequisites:
#   - /var/lib/sysknife-e2e/ready exists (provisioning complete)
#   - sysknife-daemon is active
#   - sysknife is in PATH
#   - LLM is reachable (Ollama or cloud key)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"

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

if [[ "$preflight_ok" != "true" ]]; then
  echo ""
  echo "Preflight checks failed. Aborting."
  exit 1
fi

# ---------------------------------------------------------------------------
# LLM + daemon socket env (mirrors run-stories.sh)
# ---------------------------------------------------------------------------

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
# SYSKNIFE_SOCKET — client-side path to the daemon socket (read by the CLI).
# SYSKNIFE_LISTEN_URI — daemon-side bind URI (read by sysknife-daemon, not the CLI).
# Both are needed: LISTEN_URI for any daemon spawned by tests; SOCKET for the CLI client.
export SYSKNIFE_SOCKET="${SYSKNIFE_SOCKET:-/run/sysknife/daemon.sock}"
export SYSKNIFE_LISTEN_URI="${SYSKNIFE_LISTEN_URI:-unix:///run/sysknife/daemon.sock}"

# ---------------------------------------------------------------------------
# Determine which stories to run
# ---------------------------------------------------------------------------

ALLOW_DESTRUCTIVE="${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}"
STORY_TIMEOUT="${SYSKNIFE_STORY_TIMEOUT:-600}"

declare -A EXEC_NAMES
EXEC_NAMES[1]="GetDiskUsage — root filesystem present in output"
EXEC_NAMES[2]="GetMemoryInfo — Mem: line present in output"
EXEC_NAMES[3]="GetServiceStatus — sysknife-daemon shows active"
EXEC_NAMES[4]="SSH key round-trip — add then remove (destructive)"
EXEC_NAMES[5]="User round-trip — create then delete (destructive)"
EXEC_NAMES[6]="ListServices — non-empty output"
EXEC_NAMES[7]="RestartService — firewalld stays active (destructive)"
EXEC_NAMES[8]="SetHostname cycle — change and restore (destructive)"
EXEC_NAMES[9]="SetTimezone cycle — Chicago then restore UTC (destructive)"
EXEC_NAMES[10]="Group membership cycle — audio add then remove (destructive)"
EXEC_NAMES[11]="ConfigureFirewall cycle — ftp add then remove (destructive)"

declare -A RESULTS
declare -A DURATIONS
declare -A MESSAGES

if [[ $# -gt 0 ]]; then
  STORIES=("$@")
elif [[ "$ALLOW_DESTRUCTIVE" == "1" ]]; then
  STORIES=(1 2 3 4 5 6 7 8 9 10 11)
else
  # Safe (non-destructive, Low risk) stories only.
  STORIES=(1 2 3 6)
fi

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

run_exec() {
  local n="$1"
  local script="$SCRIPT_DIR/exec-${n}.sh"
  local log="$LOG_DIR/exec-${n}.log"
  local name="${EXEC_NAMES[$n]:-Exec $n}"

  if [[ ! -f "$script" ]]; then
    RESULTS[$n]="SKIP"
    MESSAGES[$n]="script not found: $script"
    DURATIONS[$n]="0.0"
    return
  fi

  printf "  Exec %2d (%-52s) " "$n" "$name"

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
echo "SysKnife Tier 4 Execution E2E"
echo "============================="
echo "Date:        $(date --iso-8601=seconds)"
echo "Provider:    $SYSKNIFE_LLM_PROVIDER"
echo "Stories:     ${STORIES[*]}"
echo "Destructive: $ALLOW_DESTRUCTIVE"
echo "Timeout:     ${STORY_TIMEOUT}s per story"
echo ""

for n in "${STORIES[@]}"; do
  run_exec "$n"
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
  local_name="${EXEC_NAMES[$n]:-Exec $n}"
  local_result="${RESULTS[$n]}"
  local_duration="${DURATIONS[$n]}"
  local_msg="${MESSAGES[$n]:-}"

  printf "  Exec %2d (%-52s) " "$n" "$local_name"

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
