#!/usr/bin/env bash
# Every place the release version lives must agree, and must match the tag.
#
# Where those places ARE is declared once, in release-versions.json, and read
# by scripts/release_versions.py. scripts/bump_version.sh writes from the same
# registry, so the writer and the checker cannot hold different ideas of what
# a release touches. Keeping a second list here is exactly how they drift, and
# tests/release/version-sites.test.sh fails if either stops reading it.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected="${1:-}"
expected="${expected#v}"

# Command substitution, not process substitution: `< <(...)` discards the
# exit status, so a registry error printed a diagnostic and this script still
# reported every version matching.
if ! values="$(python3 "$repo_root/scripts/release_versions.py" values)"; then
    printf 'Could not read the version registry; nothing was checked.\n' >&2
    exit 1
fi
if ! pin_count="$(python3 "$repo_root/scripts/release_versions.py" pincount)"; then
    printf 'Could not count internal dependency pins; nothing was checked.\n' >&2
    exit 1
fi

mapfile -t versions <<<"$values"
# An empty list means the registry moved, not that everything agrees. Refuse
# rather than report success over nothing.
if [[ ${#versions[@]} -eq 0 || -z "${versions[0]}" ]]; then
    printf 'The version registry resolved no sites; refusing to check nothing.\n' >&2
    exit 1
fi

baseline="${versions[0]}"
for version in "${versions[@]}"; do
    if [[ "$version" != "$baseline" ]]; then
        printf 'Release versions are inconsistent: expected %s, found %s\n' \
            "$baseline" "$version" >&2
        printf 'Run scripts/release_versions.py values to see every site.\n' >&2
        exit 1
    fi
done

if [[ -n "$expected" && "$baseline" != "$expected" ]]; then
    printf 'Release tag version %s does not match package version %s\n' \
        "$expected" "$baseline" >&2
    exit 1
fi

printf 'All release versions match %s (%d internal dependency pins checked).\n' \
    "$baseline" "$pin_count"
