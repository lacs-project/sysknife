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

# `--metadata` prints the derived story table and exits without running
# anything. It is handled before the preflight on purpose: the table comes from
# story files in the repo, so it is checkable on any host, and
# tests/e2e/story-metadata.test.sh asserts on THIS parser instead of
# reimplementing it. A second parser is a second answer.
METADATA_ONLY=0
if [[ "${1:-}" == "--metadata" ]]; then
  METADATA_ONLY=1
  shift
fi

mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

preflight_ok=true

if [[ $METADATA_ONLY -eq 0 ]] && [[ ! -f /var/lib/sysknife-e2e/ready ]]; then
  echo "ERROR: /var/lib/sysknife-e2e/ready not found. Run provisioning first."
  preflight_ok=false
fi

if [[ $METADATA_ONLY -eq 0 ]] && ! systemctl is-active --quiet sysknife-daemon 2>/dev/null; then
  echo "ERROR: sysknife-daemon is not running."
  preflight_ok=false
fi

if [[ $METADATA_ONLY -eq 0 ]] && ! command -v sysknife &>/dev/null; then
  echo "ERROR: sysknife not found in PATH."
  preflight_ok=false
fi

if [[ $METADATA_ONLY -eq 0 ]] && ! command -v jq &>/dev/null; then
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
    elif [ -n "${GROQ_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="groq"
    elif [ -n "${DEEPSEEK_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="deepseek"
    elif [ -n "${MISTRAL_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="mistral"
    elif [ -n "${XAI_API_KEY:-}" ]; then
        export SYSKNIFE_LLM_PROVIDER="xai"
    else
        export SYSKNIFE_LLM_PROVIDER="ollama"
    fi
fi
export SYSKNIFE_LLM_PROVIDER
# Model: an explicit SYSKNIFE_LLM_MODEL wins, then SYSKNIFE_TEST_MODEL.
# Otherwise leave the variable unset so BrainConfig picks that provider's own
# default. Exporting "" is not the same as leaving it unset: BrainConfig reads
# it with env::var().ok(), so an empty string beats the default and the request
# goes out naming no model at all. The per-provider defaults also used to be
# restated here, which gave gpt-4.1 and claude-sonnet-4-6 a second home that
# could drift from the constants in crates/sysknife-brain/src/config.rs.
if [ -n "${SYSKNIFE_LLM_MODEL:-}" ]; then
    export SYSKNIFE_LLM_MODEL
elif [ -n "${SYSKNIFE_TEST_MODEL:-}" ]; then
    export SYSKNIFE_LLM_MODEL="$SYSKNIFE_TEST_MODEL"
else
    unset SYSKNIFE_LLM_MODEL
fi
export SYSKNIFE_OLLAMA_URL="${SYSKNIFE_OLLAMA_URL:-http://127.0.0.1:11434}"
# sysknife-daemon's packaged systemd unit binds /run/sysknife/daemon.sock.
export SYSKNIFE_LISTEN_URI="${SYSKNIFE_LISTEN_URI:-unix:///run/sysknife/daemon.sock}"

# ---------------------------------------------------------------------------
# Cassette (deterministic record/replay of the LLM call)
# ---------------------------------------------------------------------------
# SYSKNIFE_CASSETTE + SYSKNIFE_CASSETTE_MODE are read by the planner itself; this
# script only has to manage the ledger, which is how a replay proves it happened.
# The ledger is append-only across processes, so it has to be truncated at the
# start of a run or this run inherits the previous one's tally.
# The mode is normalised exactly as CassetteMode::parse does (trim, lowercase).
# They disagreed at first, and the consequence was the worst kind: with
# SYSKNIFE_CASSETTE_MODE=Replay the planner replayed strictly while this script
# skipped the audit entirely, so a subset run of the rejection stories (which
# accept an empty plan) could miss every single call and still exit 0.
CASSETTE_MODE_NORMALIZED="$(printf '%s' "${SYSKNIFE_CASSETTE_MODE:-}" \
  | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
CASSETTE_LEDGER=""
if [ -n "${SYSKNIFE_CASSETTE:-}" ] && [ "$CASSETTE_MODE_NORMALIZED" = "replay" ]; then
  CASSETTE_LEDGER="${SYSKNIFE_CASSETTE}.replay-log.jsonl"
  rm -f "$CASSETTE_LEDGER"
fi

# ---------------------------------------------------------------------------
# Determine which stories to run
# ---------------------------------------------------------------------------

ALLOW_DESTRUCTIVE="${SYSKNIFE_ALLOW_DESTRUCTIVE:-0}"

# Timeout per story (seconds). With qwen3:8b on host GPU, stories
# finish in <60 s; with llama3.2:3b on 4 vCPU CPU, 2–4 min; with
# qwen3:8b on CPU, impractical. 600 s is generous for the GPU path
# and tolerant of the CPU fallback. Override with SYSKNIFE_STORY_TIMEOUT.
STORY_TIMEOUT="${SYSKNIFE_STORY_TIMEOUT:-600}"

# ---------------------------------------------------------------------------
# Story metadata — derived, never restated
# ---------------------------------------------------------------------------
# Every story opens with `# Story N[ (tags)]: Title`, so the title and the
# distro family are already recorded in the story file. They used to be
# duplicated into a 54-entry STORY_NAMES table here, which had already drifted
# apart from the files: the table stopped at 54, so all 50 Ubuntu stories
# printed as a bare "Story 73" with no name in every results table we have
# published. Derive both instead — a second copy of a fact is a copy that will
# disagree.
declare -A STORY_NAMES
declare -A STORY_FAMILY
ALL_STORY_IDS=()
UBUNTU_STORY_IDS=()

for _story_file in "$STORY_DIR"/story-*.sh; do
    [ -f "$_story_file" ] || continue
    _header="$(sed -n '2p' "$_story_file")"
    # `# Story 62 (ubuntu, medium-risk): Unhold a package`
    #             ^tags                   ^title
    if [[ "$_header" =~ ^#\ Story\ ([0-9]+)(\ \(([^\)]*)\))?:\ (.*)$ ]]; then
        _id="${BASH_REMATCH[1]}"
        _tags="${BASH_REMATCH[3]}"
        _title="${BASH_REMATCH[4]}"
    else
        # A story whose header cannot be parsed would otherwise vanish from the
        # derived sets without a word, which is the failure this replaced.
        printf 'ERROR: unparseable story header in %s: %s\n' "$_story_file" "$_header" >&2
        exit 1
    fi
    STORY_NAMES[$_id]="$_title"
    if [[ "$_tags" == *ubuntu* ]]; then
        STORY_FAMILY[$_id]="ubuntu"
        UBUNTU_STORY_IDS+=("$_id")
    else
        STORY_FAMILY[$_id]="atomic"
    fi
    ALL_STORY_IDS+=("$_id")
done

# Numeric order, so results tables read in story order rather than glob order
# (story-10 sorts before story-2 as a string).
mapfile -t ALL_STORY_IDS < <(printf '%s\n' "${ALL_STORY_IDS[@]}" | sort -n)
mapfile -t UBUNTU_STORY_IDS < <(printf '%s\n' "${UBUNTU_STORY_IDS[@]}" | sort -n)

if [[ $METADATA_ONLY -eq 1 ]]; then
  for n in "${ALL_STORY_IDS[@]}"; do
    printf '%s\t%s\t%s\n' "$n" "${STORY_FAMILY[$n]}" "${STORY_NAMES[$n]}"
  done
  exit 0
fi

declare -A RESULTS
declare -A DURATIONS
declare -A MESSAGES

STORY_SET=""

if [[ "${1:-}" == "ubuntu" ]]; then
  # The whole Ubuntu family, derived from the story headers. Documented runs
  # used to spell this `$(seq 55 104)`, a hand-typed range that silently stops
  # covering the suite the moment story 105 is added.
  STORY_SET="ubuntu"
  STORIES=("${UBUNTU_STORY_IDS[@]}")
elif [[ "${1:-}" == "atomic" ]]; then
  STORY_SET="atomic"
  mapfile -t STORIES < <(
    for n in "${ALL_STORY_IDS[@]}"; do
      [[ "${STORY_FAMILY[$n]}" == "atomic" ]] && printf '%s\n' "$n"
    done
  )
elif [[ $# -gt 0 ]]; then
  STORIES=("$@")
elif [[ "$ALLOW_DESTRUCTIVE" == "1" ]]; then
  STORY_SET="atomic"
  mapfile -t STORIES < <(
    for n in "${ALL_STORY_IDS[@]}"; do
      [[ "${STORY_FAMILY[$n]}" == "atomic" ]] && printf '%s\n' "$n"
    done
  )
else
  # Read-only and non-destructive stories only. Stories self-gate via
  # SYSKNIFE_ALLOW_DESTRUCTIVE — skipped ones still appear in results as SKIP.
  # This subset is curated, not derivable: it is the atomic-family stories that
  # need no live rpm-ostree host, which no header tag records.
  STORIES=(1 2 3 4 5 6 7 11 12 13 14 15 16 17 \
           21 22 25 26 28 29 32 38 41 46 47 48 49)
fi

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

# True when a story's output shows the planner refused the request because of
# the built-in rate limit (DEFAULT_MAX_RPM, 20/min) rather than because of
# anything the model did. Stories write the CLI's stderr to their own file, so
# both that and the story log have to be checked.
#
# This has to be consulted even when a story *passed*: the rejection stories
# (91 to 93) accept an empty plan, so a rate-limited run makes them pass while
# proving nothing. Reporting that as PASS is how a throttled suite reads as a
# healthy one.
story_was_rate_limited() {
  local n="$1" log="$2"
  grep -qi 'rate limit exceeded' "$log" 2>/dev/null && return 0
  grep -qi 'rate limit exceeded' "/tmp/sysknife-story-${n}-stderr.log" 2>/dev/null
}

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
    if story_was_rate_limited "$n" "$log"; then
      # Overrides the story's own verdict on purpose. It never saw a plan.
      RESULTS[$n]="RATELIMIT"
      MESSAGES[$n]="planner rate limit hit; this result is not evidence"
      DURATIONS[$n]="0.0"
      echo "RATELIMIT"
    elif [[ "$last_line" == SKIP* ]]; then
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
    local end_time
    end_time=$(date +%s.%N)
    DURATIONS[$n]=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "?")
    if story_was_rate_limited "$n" "$log"; then
      RESULTS[$n]="RATELIMIT"
      MESSAGES[$n]="planner rate limit hit; this result is not evidence"
      echo "RATELIMIT"
      return
    fi
    RESULTS[$n]="FAIL"
    MESSAGES[$n]=$(tail -n 5 "$log" | grep -v '^$' | tail -n 1)
    if [[ $exit_code -eq 124 ]]; then
      MESSAGES[$n]="timed out after ${STORY_TIMEOUT}s"
    fi
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
ratelimit_count=0

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
    RATELIMIT)
      echo "RATELIMIT — $local_msg"
      ((ratelimit_count++)) || true
      ;;
  esac
done

total=${#STORIES[@]}
echo ""
echo "Summary: $pass_count/$total passed, $fail_count failed, $skip_count skipped, $ratelimit_count rate-limited"
if [[ $ratelimit_count -gt 0 ]]; then
  echo ""
  echo "  $ratelimit_count story/stories never reached the model: the planner's own"
  echo "  rate limit (DEFAULT_MAX_RPM, 20 requests/minute) rejected them. Those"
  echo "  results say nothing about the model and must not be counted either way."
  echo "  Raise it for a full-suite run, e.g. SYSKNIFE_MAX_RPM=120."
fi
echo "Logs:    $LOG_DIR/"
echo ""

# ---------------------------------------------------------------------------
# Machine-readable evidence
# ---------------------------------------------------------------------------
# Every validation number SysKnife publishes has to come from a run, not from a
# person's memory of one. The README claimed "65/65 stories validated" in eight
# places for months with no artifact behind it and no number that could produce
# it; scripts/check_public_claims.sh now refuses any N/M story claim that does
# not match one of these files.
#
# Opt-in via SYSKNIFE_RESULTS_JSON so a two-story debugging run cannot overwrite
# a full-suite record. `story_set` names the derived set that was run, and is
# empty for an explicit story list — the checker only honours a full family set,
# so a four-story probe can never become the headline figure.
if [[ -n "${SYSKNIFE_RESULTS_JSON:-}" ]]; then
  results_dir="$(dirname "$SYSKNIFE_RESULTS_JSON")"
  mkdir -p "$results_dir"

  cassette_sha="null"
  if [[ -n "${SYSKNIFE_CASSETTE:-}" ]] && [[ -f "${SYSKNIFE_CASSETTE}" ]]; then
    cassette_sha="\"$(sha256sum "${SYSKNIFE_CASSETTE}" | cut -d' ' -f1)\""
  fi

  # The release the stories actually ran against, read from the host they ran on
  # rather than from whatever the operator typed on the command line.
  release="$(. /etc/os-release 2>/dev/null && printf '%s' "${VERSION_ID:-unknown}")"
  distro_id="$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-unknown}")"

  {
    printf '{\n'
    printf '  "version": 1,\n'
    printf '  "distro_id": "%s",\n' "$distro_id"
    printf '  "release": "%s",\n' "$release"
    printf '  "surface": "%s/%s",\n' "${SYSKNIFE_LLM_PROVIDER:-unset}" "${SYSKNIFE_LLM_MODEL:-provider-default}"
    printf '  "cassette_mode": "%s",\n' "${CASSETTE_MODE_NORMALIZED:-live}"
    printf '  "cassette_sha256": %s,\n' "$cassette_sha"
    printf '  "story_set": "%s",\n' "$STORY_SET"
    printf '  "ran_at": "%s",\n' "$(date --iso-8601=seconds)"
    printf '  "totals": {\n'
    printf '    "total": %d,\n' "$total"
    printf '    "passed": %d,\n' "$pass_count"
    printf '    "failed": %d,\n' "$fail_count"
    printf '    "skipped": %d,\n' "$skip_count"
    printf '    "rate_limited": %d\n' "$ratelimit_count"
    printf '  },\n'
    printf '  "stories": {\n'
    sep=""
    for n in "${STORIES[@]}"; do
      printf '%s    "%s": { "verdict": "%s", "name": "%s" }' \
        "$sep" "$n" "${RESULTS[$n]}" "${STORY_NAMES[$n]//\"/\\\"}"
      sep=",\n"
    done
    printf '\n  }\n'
    printf '}\n'
  } > "$SYSKNIFE_RESULTS_JSON"
  echo "Evidence: $SYSKNIFE_RESULTS_JSON"
  echo ""
fi

# ---------------------------------------------------------------------------
# Cassette replay audit
# ---------------------------------------------------------------------------
# A replay that answered nothing looks exactly like a replay where everything
# passed, so the run is only trustworthy if the ledger says calls were served.
# Checked even when every story passed: that is the case this guards.
cassette_failed=0
if [[ -n "$CASSETTE_LEDGER" ]]; then
  hits=0
  misses=0
  if [[ -f "$CASSETTE_LEDGER" ]]; then
    # Counted line by line rather than with `jq -s`. Slurping needs the whole
    # file to parse, so one truncated trailing line from a process killed
    # mid-suite took both counts to zero and reported "served 0 calls" for a run
    # that had in fact served plenty. A line that cannot be read counts as a
    # miss, matching read_ledger's own unknown-outcome policy.
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      if outcome=$(printf '%s' "$line" | jq -r '.outcome // "miss"' 2>/dev/null); then
        if [[ "$outcome" == "hit" ]]; then hits=$((hits + 1)); else misses=$((misses + 1)); fi
      else
        misses=$((misses + 1))
      fi
    done < "$CASSETTE_LEDGER"
  fi
  echo "Cassette:  replay served ${hits} call(s), ${misses} miss(es)"
  if [[ "${misses:-0}" -gt 0 ]]; then
    echo "  FAIL: the cassette did not cover this run. A miss means the recording"
    echo "  and the code have diverged (most often prompt.rs changed), so these"
    echo "  results describe neither the recording nor the live model. Re-record."
    cassette_failed=1
  fi
  if [[ "${hits:-0}" -eq 0 ]]; then
    echo "  FAIL: replay was requested but no call was served from the cassette."
    echo "  Every story result above is therefore unproven, including the passes."
    cassette_failed=1
  fi
  echo ""
fi

if [[ $fail_count -gt 0 || $cassette_failed -gt 0 ]]; then
  exit 1
fi
exit 0
