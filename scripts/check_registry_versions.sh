#!/usr/bin/env bash
set -euo pipefail

version="${1#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    printf 'ERROR: expected a semantic version, got %q\n' "$1" >&2
    exit 2
}

check_url() {
    local label="$1" url="$2" status
    status="$(curl --retry 3 --silent --show-error --output /dev/null \
        --user-agent 'sysknife-release-preflight/1.0 (https://github.com/lacs-project/sysknife)' \
        --write-out '%{http_code}' "$url")"
    case "$status" in
        200) printf 'Registry preflight: %-24s %s already published\n' "$label" "$version" ;;
        404) printf 'Registry preflight: %-24s %s available\n' "$label" "$version" ;;
        *)
            printf 'ERROR: registry preflight for %s returned HTTP %s\n' "$label" "$status" >&2
            exit 1
            ;;
    esac
}

check_url sysknife-setup "https://registry.npmjs.org/sysknife-setup/${version}"
for crate in sysknife-proto sysknife-core sysknife-types sysknife-brain \
             sysknife-daemon sysknife-cli; do
    check_url "$crate" "https://crates.io/api/v1/crates/${crate}/${version}"
done
