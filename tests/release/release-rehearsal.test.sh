#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rehearsal="${repo_root}/scripts/release_rehearsal.sh"

# Invalid registry versions must fail validation before attempting any network
# requests, including when no positional argument was supplied.
assert_invalid_registry_version() {
    local output status
    if output="$(bash "${repo_root}/scripts/check_registry_versions.sh" "$@" 2>&1)"; then
        printf 'FAIL: registry preflight accepted an invalid version\n' >&2
        exit 1
    else
        status=$?
    fi
    if [[ "$status" -ne 2 ]]; then
        printf 'FAIL: registry preflight expected exit 2, got %s: %s\n' "$status" "$output" >&2
        exit 1
    fi
    grep -Fq 'ERROR: expected a semantic version' <<<"$output"
}

assert_invalid_registry_version nope
assert_invalid_registry_version
assert_invalid_registry_version ''

if [[ ! -x "$rehearsal" ]]; then
    printf 'FAIL: release rehearsal is missing or not executable: %s\n' "$rehearsal" >&2
    exit 1
fi

help="$($rehearsal --help)"
grep -Fq -- '--check' <<<"$help"
grep -Fq -- '--full' <<<"$help"
grep -Fq 'never publishes' <<<"$help"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
set +e
"$rehearsal" --publish >"${tmp_dir}/publish.out" 2>&1
publish_status=$?
set -e
if [[ "$publish_status" -eq 0 ]]; then
    printf 'FAIL: rehearsal accepted a publishing mode\n' >&2
    exit 1
fi
if [[ ! -s "${tmp_dir}/publish.out" ]]; then
    printf 'FAIL: rehearsal output was not captured (exit %s)\n' "$publish_status" >&2
    exit 1
fi
grep -Fq 'never publishes' "${tmp_dir}/publish.out"

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
#
# The extraction has to say how many lines it saw. A broken grep, an unmatched
# glob, or a spelling the regex does not read all used to print
# "Release rehearsal contract passed." over nothing. See #407.
#
# The floor is 20. This tree currently has 55 `uses:` lines, 19 of them
# actions/checkout. A regex that only matches checkout, or that only matches
# the `- uses:` spelling (one hit, in docs.yml), falls below it. Adding a
# workflow cannot trip it; extracting a subset can.
assert_action_pins() {
    local workflows_dir="$1"
    local min_uses="$2"
    local old_nullglob uses_count workflow uses_line
    old_nullglob="$(shopt -p nullglob || true)"
    shopt -s nullglob
    local -a workflows=("$workflows_dir"/*.yml "$workflows_dir"/*.yaml)
    eval "$old_nullglob"

    ((${#workflows[@]})) || {
        printf 'FAIL: no workflow files matched under %s\n' "$workflows_dir" >&2
        return 1
    }

    uses_count=0
    for workflow in "${workflows[@]}"; do
        [ -r "$workflow" ] || {
            printf 'FAIL: cannot read %s\n' "$workflow" >&2
            return 1
        }
        while IFS= read -r uses_line; do
            [ -n "$uses_line" ] || continue
            uses_count=$((uses_count + 1))
            # A reusable workflow in this same repository is referenced by path
            # and cannot carry a SHA at all: GitHub resolves `./...` at the
            # caller's own commit, so it is pinned by construction and always
            # to this tree. The exemption is deliberately anchored to `./` so a
            # third-party `owner/repo/.github/workflows/x.yml@ref` still has to
            # be pinned.
            if printf '%s\n' "$uses_line" | grep -Eq 'uses:[[:space:]]+\./'; then
                continue
            fi
            if ! printf '%s\n' "$uses_line" | grep -Eq 'uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}([[:space:]]|$)'; then
                printf 'FAIL: %s action is not pinned to a 40-hex SHA: %s\n' \
                    "$(basename "$workflow")" "$uses_line" >&2
                return 1
            fi
        done < <(grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$workflow" || true)
    done

    if [ "$uses_count" -lt "$min_uses" ]; then
        printf 'FAIL: extracted %s uses: line(s) under %s; need at least %s (extraction is broken, not the workflows)\n' \
            "$uses_count" "$workflows_dir" "$min_uses" >&2
        return 1
    fi
}

assert_action_pins "${repo_root}/.github/workflows" 20

# Negative twin: a workflow whose only `uses:` is a flow-style mapping, which
# the extractor above does not read. Before the floor this check printed
# success over zero lines.
pin_fixture="$(mktemp -d)"
trap 'rm -rf "$pin_fixture"' EXIT
mkdir -p "$pin_fixture/workflows"
cat > "$pin_fixture/workflows/missed.yml" <<'EOF'
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 }
EOF
if pin_output="$(assert_action_pins "$pin_fixture/workflows" 1 2>&1)"; then
    printf 'FAIL: pin check passed over a uses: spelling the extraction does not read\n' >&2
    exit 1
fi
grep -Fq 'extraction is broken, not the workflows' <<<"$pin_output"
# Discovery must fail with its own diagnostic, even when the count floor is zero.
mkdir "$pin_fixture/empty"
if pin_output="$(assert_action_pins "$pin_fixture/empty" 0 2>&1)"; then
    printf 'FAIL: pin check passed over an empty workflow directory\n' >&2
    exit 1
fi
grep -Fxq "FAIL: no workflow files matched under $pin_fixture/empty" <<<"$pin_output"

# The readable workflow clears the floor on its own: a skipped file must not
# masquerade as a workflow with no uses. Root bypasses mode 000 permissions.
if (( EUID == 0 )); then
    printf 'SKIP: unreadable workflow fixture requires a non-root user\n' >&2
else
    mkdir "$pin_fixture/unreadable"
    printf '  uses: ./.github/workflows/local.yml\n' > "$pin_fixture/unreadable/readable.yml"
    cp "$pin_fixture/unreadable/readable.yml" "$pin_fixture/unreadable/blocked.yaml"
    assert_action_pins "$pin_fixture/unreadable" 1
    chmod 000 "$pin_fixture/unreadable/blocked.yaml"
    if pin_output="$(assert_action_pins "$pin_fixture/unreadable" 1 2>&1)"; then
        printf 'FAIL: pin check passed over an unreadable workflow\n' >&2
        exit 1
    fi
    grep -Fxq "FAIL: cannot read $pin_fixture/unreadable/blocked.yaml" <<<"$pin_output"
fi

if grep -Fq -- '--no-verify' "$release_workflow"; then
    printf 'FAIL: release publication skips generated crate verification\n' >&2
    exit 1
fi

if grep -Eiq '(^|[[:space:]])(cargo|npm)[[:space:]]+publish|gh[[:space:]]+release[[:space:]]+create' "$rehearsal"; then
    printf 'FAIL: rehearsal contains a publication command\n' >&2
    exit 1
fi

printf 'Release rehearsal contract passed.\n'
