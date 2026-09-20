#!/usr/bin/env bash

crate_version_status() {
    local crate="$1"
    local version="$2"
    local curl_cmd="${CRATES_IO_CURL:-curl}"
    local http_code

    if ! http_code="$(
        "$curl_cmd" \
            --silent \
            --show-error \
            --retry 3 \
            --retry-connrefused \
            --output /dev/null \
            --write-out '%{http_code}' \
            --user-agent 'sysknife-release/1.0 (https://github.com/lacs-project/sysknife)' \
            "https://crates.io/api/v1/crates/${crate}/${version}"
    )"; then
        printf 'ERROR: could not reach crates.io while checking %s %s\n' \
            "$crate" "$version" >&2
        return 2
    fi

    case "$http_code" in
        200)
            return 0
            ;;
        404)
            return 1
            ;;
        *)
            printf 'ERROR: crates.io returned HTTP %s while checking %s %s\n' \
                "$http_code" "$crate" "$version" >&2
            return 2
            ;;
    esac
}

wait_for_crate_version() {
    local crate="$1"
    local version="$2"
    local timeout="${CRATES_IO_POLL_TIMEOUT:-300}"
    local interval="${CRATES_IO_POLL_INTERVAL:-15}"
    local sleep_cmd="${CRATES_IO_SLEEP:-sleep}"
    local elapsed=0
    local status

    while :; do
        if crate_version_status "$crate" "$version"; then
            printf '%s %s is available on crates.io\n' "$crate" "$version"
            return 0
        else
            status=$?
        fi

        if ((status != 1)); then
            return "$status"
        fi

        if ((elapsed >= timeout)); then
            printf 'ERROR: timed out after %s seconds waiting for %s %s to appear on crates.io\n' \
                "$timeout" "$crate" "$version" >&2
            return 1
        fi

        "$sleep_cmd" "$interval"
        elapsed=$((elapsed + interval))
    done
}
