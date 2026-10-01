#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: check-container-image.sh IMAGE VERSION}"
version="${2:?usage: check-container-image.sh IMAGE VERSION}"
actual="$(docker run --rm --entrypoint sysknife "$image" --version)"
if [[ "$actual" != "sysknife $version" ]]; then
    printf 'FAIL: image version: expected sysknife %s, got %s\n' "$version" "$actual" >&2
    exit 1
fi
uid="$(docker run --rm --entrypoint id "$image" -u)"
if [[ "$uid" != 10001 ]]; then
    printf 'FAIL: image uid: expected 10001, got %s\n' "$uid" >&2
    exit 1
fi
printf 'Image smoke passed: %s, uid=%s\n' "$actual" "$uid"
