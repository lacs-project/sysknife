#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rehearsal="${repo_root}/scripts/release_rehearsal.sh"

if [[ ! -x "$rehearsal" ]]; then
    printf 'FAIL: release rehearsal is missing or not executable: %s\n' "$rehearsal" >&2
    exit 1
fi

help="$($rehearsal --help)"
grep -Fq -- '--check' <<<"$help"
grep -Fq -- '--full' <<<"$help"
grep -Fq 'never publishes' <<<"$help"

if "$rehearsal" --publish >/tmp/sysknife-rehearsal-publish.out 2>&1; then
    printf 'FAIL: rehearsal accepted a publishing mode\n' >&2
    exit 1
fi
grep -Fq 'never publishes' /tmp/sysknife-rehearsal-publish.out

check_output="$($rehearsal --check)"
grep -Eq 'sysknife-v[0-9]+\.[0-9]+\.[0-9]+-linux-(x86_64|aarch64)' <<<"$check_output"
grep -Eq 'sysknife-daemon-v[0-9]+\.[0-9]+\.[0-9]+-linux-(x86_64|aarch64)' <<<"$check_output"
grep -Fq 'Rehearsal preflight passed' <<<"$check_output"

for crate in sysknife-proto sysknife-core sysknife-types sysknife-brain \
             sysknife-daemon; do
    grep -Fq "patch.crates-io.${crate}.path" "$rehearsal"
done
grep -Fq 'npm pack ./packages/setup' "$rehearsal"
if grep -Fq -- '--no-verify' "$rehearsal"; then
    printf 'FAIL: rehearsal skips generated crate verification\n' >&2
    exit 1
fi

release_workflow="${repo_root}/.github/workflows/release.yml"
grep -Fq 'check_registry_versions.sh' "$release_workflow"
grep -Fq 'already exists; skipping' "$release_workflow"

# The MCP Registry listing is published by CI, and the ordering is the part
# worth pinning: the registry validator reads the *published* crate's rendered
# README for the ownership marker, so a publish job that stopped depending on
# publish-crates would fail with an error that looks like a permissions problem.
publish_mcp_workflow="${repo_root}/.github/workflows/publish-mcp.yml"
grep -Fq './.github/workflows/publish-mcp.yml' "$release_workflow"
grep -Fq 'publish-crates' "$release_workflow"
grep -Fq 'mcp-publisher publish' "$publish_mcp_workflow"
# OIDC is not an implementation detail here. A device-code login mints a token
# for the *user's* namespace, so it cannot publish io.github.lacs-project/*;
# only the repository identity can. Swapping this back would 403 at release
# time, long after the change looked fine.
grep -Fq 'login github-oidc' "$publish_mcp_workflow"
grep -Fq 'id-token: write' "$publish_mcp_workflow"

# Glama's build spec stays browser-only, so it is still forgotten after releases
# unless something names it. The workflow files a checklist issue with the
# freshly published checksum filled in, so the work is visible without anyone
# reading a build log.
grep -Fq 'Post-release manual steps' "$release_workflow"
grep -Fq 'glama.ai' "$release_workflow"
# The checklist is only useful if it carries the real checksum for this tag,
# and only honest if it appears after publication actually succeeded.
grep -Fq 'sha256sums-linux-x86_64.txt' "$release_workflow"
grep -Eq 'needs: \[release\]' "$release_workflow"
# Positive invariant: EVERY `uses:` in EVERY workflow MUST pin a full 40-hex
# commit SHA. This catches every mutable form (semver tags like @v6.1.0,
# @stable, @main, per-tool tags like @cargo-nextest, and short SHAs), across
# all workflows — not just the publishing one — for a uniform supply-chain
# posture that cannot silently drift.
for workflow in "${repo_root}"/.github/workflows/*.yml; do
    while IFS= read -r uses_line; do
        # A reusable workflow in this same repository is referenced by path and
        # cannot carry a SHA at all: GitHub resolves `./...` at the caller's own
        # commit, so it is pinned by construction and always to this tree. The
        # exemption is deliberately anchored to `./` so a third-party
        # `owner/repo/.github/workflows/x.yml@ref` still has to be pinned.
        if printf '%s\n' "$uses_line" | grep -Eq 'uses:[[:space:]]+\./'; then
            continue
        fi
        if ! printf '%s\n' "$uses_line" | grep -Eq 'uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}([[:space:]]|$)'; then
            printf 'FAIL: %s action is not pinned to a 40-hex SHA: %s\n' \
                "$(basename "$workflow")" "$uses_line" >&2
            exit 1
        fi
    done < <(grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$workflow")
done
if grep -Fq -- '--no-verify' "$release_workflow"; then
    printf 'FAIL: release publication skips generated crate verification\n' >&2
    exit 1
fi

if grep -Eiq '(^|[[:space:]])(cargo|npm)[[:space:]]+publish|gh[[:space:]]+release[[:space:]]+create' "$rehearsal"; then
    printf 'FAIL: rehearsal contains a publication command\n' >&2
    exit 1
fi

printf 'Release rehearsal contract passed.\n'
