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

url_log="${tmp}/urls"
: > "$url_log"
expected_url='https://crates.io/api/v1/crates/sysknife-daemon/0.15.0'

stub="${tmp}/curl-stub"
cat > "$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count="$(cat "$CRATES_IO_TEST_COUNT_FILE")"
count=$((count + 1))
printf '%s\n' "$count" > "$CRATES_IO_TEST_COUNT_FILE"
printf '%s\n' "${@: -1}" >> "$CRATES_IO_URL_LOG"
if [[ "${@: -1}" != "$CRATES_IO_TEST_EXPECTED_URL" ]]; then
    printf '404'
elif ((count <= 3)); then
    printf '404'
else
    printf '200'
fi
EOF
chmod +x "$stub"

CRATES_IO_CURL="$stub" \
CRATES_IO_TEST_COUNT_FILE="$count_file" \
CRATES_IO_URL_LOG="$url_log" \
CRATES_IO_TEST_EXPECTED_URL="$expected_url" \
CRATES_IO_POLL_TIMEOUT=3 \
CRATES_IO_POLL_INTERVAL=1 \
CRATES_IO_SLEEP=true \
wait_for_crate_version sysknife-daemon 0.15.0

[[ "$(cat "$count_file")" == "4" ]] || {
    printf 'FAIL: expected 4 poll requests, got %s\n' "$(cat "$count_file")" >&2
    exit 1
}

while IFS= read -r called_url; do
    [[ "$called_url" == "$expected_url" ]] || {
        printf 'FAIL: poll requested %s instead of %s\n' "$called_url" "$expected_url" >&2
        exit 1
    }
done < "$url_log"

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

grep -Fq 'source scripts/crates-index-poll.sh' "$workflow" || {
    printf 'FAIL: release workflow does not load the polling helper\n' >&2
    exit 1
}

wait_line="$(
    grep 'wait_for_crate_version "\$crate" "\$VERSION"' "$workflow" \
        | head -n 1 \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
)"
[[ "$wait_line" == 'wait_for_crate_version "$crate" "$VERSION"' ]] || {
    printf 'FAIL: release workflow does not wait for the index after publishing\n' >&2
    exit 1
}

if grep -Fq 'sleep 30' "$workflow"; then
    printf 'FAIL: release workflow still contains fixed sleep 30\n' >&2
    exit 1
fi

printf 'crates index polling contract passed.\n'
