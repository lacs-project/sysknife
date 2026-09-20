#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

helper="scripts/crates-index-poll.sh"
workflow=".github/workflows/release.yml"

[[ -f "$helper" ]] || {
    printf 'FAIL: missing %s\n' "$helper" >&2
    exit 1
}

source scripts/crates-index-poll.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

count_file="${tmp}/count"
printf '0\n' > "$count_file"

stub="${tmp}/curl-stub"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count="$(cat "$CRATES_IO_TEST_COUNT_FILE")"
count=$((count + 1))
printf '%s\n' "$count" > "$CRATES_IO_TEST_COUNT_FILE"
case "$count" in
    1|2|3) printf '404' ;;
    *) printf '200' ;;
esac
EOF
chmod +x "$stub"

CRATES_IO_CURL="$stub" \
CRATES_IO_TEST_COUNT_FILE="$count_file" \
CRATES_IO_POLL_TIMEOUT=3 \
CRATES_IO_POLL_INTERVAL=1 \
CRATES_IO_SLEEP=true \
wait_for_crate_version sysknife-daemon 0.15.0

[[ "$(cat "$count_file")" == "4" ]] || {
    printf 'FAIL: expected 4 poll requests, got %s\n' "$(cat "$count_file")" >&2
    exit 1
}

printf '0\n' > "$count_file"

cat > "$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count="$(cat "$CRATES_IO_TEST_COUNT_FILE")"
count=$((count + 1))
printf '%s\n' "$count" > "$CRATES_IO_TEST_COUNT_FILE"
printf '404'
EOF
chmod +x "$stub"

if output="$(
    CRATES_IO_CURL="$stub" \
    CRATES_IO_TEST_COUNT_FILE="$count_file" \
    CRATES_IO_POLL_TIMEOUT=2 \
    CRATES_IO_POLL_INTERVAL=1 \
    CRATES_IO_SLEEP=true \
    wait_for_crate_version sysknife-daemon 0.15.0 2>&1
)"; then
    printf 'FAIL: perpetual 404 unexpectedly succeeded\n' >&2
    exit 1
fi

grep -Fq 'sysknife-daemon 0.15.0' <<<"$output"
grep -Fq 'timed out after 2 seconds' <<<"$output"
[[ "$(cat "$count_file")" == "3" ]]

printf '0\n' > "$count_file"

if output="$(
    CRATES_IO_CURL="$stub" \
    CRATES_IO_TEST_COUNT_FILE="$count_file" \
    CRATES_IO_POLL_INTERVAL=15 \
    CRATES_IO_SLEEP=true \
    wait_for_crate_version sysknife-daemon 0.15.0 2>&1
)"; then
    printf 'FAIL: default timeout unexpectedly succeeded\n' >&2
    exit 1
fi

grep -Fq 'timed out after 300 seconds' <<<"$output"
[[ "$(cat "$count_file")" == "21" ]]

cat > "$stub" <<'EOF'
#!/usr/bin/env bash
exit 7
EOF
chmod +x "$stub"

if output="$(
    CRATES_IO_CURL="$stub" \
    CRATES_IO_POLL_TIMEOUT=2 \
    CRATES_IO_POLL_INTERVAL=1 \
    CRATES_IO_SLEEP=true \
    wait_for_crate_version sysknife-daemon 0.15.0 2>&1
)"; then
    printf 'FAIL: network failure unexpectedly succeeded\n' >&2
    exit 1
fi

grep -Fq 'could not reach crates.io' <<<"$output"
grep -Fq 'sysknife-daemon 0.15.0' <<<"$output"

if grep -Fq 'sleep 30' "$workflow"; then
    printf 'FAIL: release workflow still contains fixed sleep 30\n' >&2
    exit 1
fi

printf 'crates index polling contract passed.\n'