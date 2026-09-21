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
# Parse YAML so block and flow mappings receive the same checks. Keep the
# discovery floor: accepting a smaller extracted set is not proof of pinning.
assert_action_pins() {
    local workflows_dir="$1"
    local min_uses="$2"
    local old_nullglob workflow
    old_nullglob="$(shopt -p nullglob || true)"
    shopt -s nullglob
    local -a workflows=("$workflows_dir"/*.yml "$workflows_dir"/*.yaml)
    eval "$old_nullglob"

    ((${#workflows[@]})) || {
        printf 'FAIL: no workflow files matched under %s\n' "$workflows_dir" >&2
        return 1
    }

    for workflow in "${workflows[@]}"; do
        [ -r "$workflow" ] || {
            printf 'FAIL: cannot read %s\n' "$workflow" >&2
            return 1
        }
    done

    # Run the parser directly: a process substitution would hide its failures.
    python3 - "$workflows_dir" "$min_uses" "${workflows[@]}" <<'PYTHON'
from pathlib import Path
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("FAIL: action pin check requires PyYAML; install it for python3")


def fail(message):
    sys.exit(f"FAIL: {message}")


def mapping(value, location):
    if not isinstance(value, dict):
        fail(f"{location} must be a mapping")
    return value


def check_reference(reference, workflow):
    # Local actions and reusable workflows resolve at the caller's commit.
    # Remote reusable workflows must still pin a full SHA.
    if isinstance(reference, str):
        if reference.startswith("./"):
            return
        if re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference):
            return
    fail(f"{workflow.name} action is not pinned to a 40-hex SHA: {reference}")


workflows_dir, minimum, *paths = sys.argv[1:]
uses_count = 0
for path in paths:
    workflow = Path(path)
    try:
        document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        fail(f"cannot read {workflow}: {error}")
    except yaml.YAMLError as error:
        print(error, file=sys.stderr)
        fail(f"cannot parse {workflow}")

    document = mapping(document, path)
    jobs = mapping(document.get("jobs"), f"{path}: jobs")
    for name, job in jobs.items():
        location = f"{path}: job {name}"
        job = mapping(job, location)
        if "uses" in job:
            check_reference(job["uses"], workflow)
            uses_count += 1
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            fail(f"{location}: steps must be a sequence")
        for index, step in enumerate(steps, start=1):
            step = mapping(step, f"{location}: step {index}")
            if "uses" in step:
                check_reference(step["uses"], workflow)
                uses_count += 1

if uses_count < int(minimum):
    fail(f"extracted {uses_count} uses: entries under {workflows_dir}; need at least {minimum}")
print(f"Checked {uses_count} uses: entries.")
PYTHON
}

assert_action_pins "${repo_root}/.github/workflows" 20

# Exercise the shipped checker against both YAML spellings and both locations
# GitHub accepts: step actions and job-level reusable workflows.
pin_fixture="$(mktemp -d)"
trap 'rm -rf "$pin_fixture"' EXIT

assert_pin_failure() {
    local directory="$1" minimum="$2" expected="$3" output
    if output="$(assert_action_pins "$directory" "$minimum" 2>&1)"; then
        printf 'FAIL: pin check accepted %s; expected %s\n' "$directory" "$expected" >&2
        exit 1
    fi
    if ! grep -Fxq "$expected" <<<"$output"; then
        printf 'FAIL: expected %s; got %s\n' "$expected" "$output" >&2
        exit 1
    fi
}

mkdir "$pin_fixture/unpinned"
for spelling in flow block; do
    if [[ "$spelling" == block ]]; then
        printf 'jobs:\n  x:\n    steps:\n      - uses: attacker/exfil@main\n' > "$pin_fixture/unpinned/action.yml"
    else
        printf 'jobs: {x: {steps: [{uses: attacker/exfil@main}]}}\n' > "$pin_fixture/unpinned/action.yml"
    fi
    # A zero floor ensures only rejection of the unpinned reference can pass.
    assert_pin_failure "$pin_fixture/unpinned" 0 \
        "FAIL: action.yml action is not pinned to a 40-hex SHA: attacker/exfil@main"
done

# The old missed.yml fixture must now be found, counted, and accepted.
mkdir "$pin_fixture/workflows"
cat > "$pin_fixture/workflows/missed.yml" <<'EOF'
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - { uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 }
EOF
pin_output="$(assert_action_pins "$pin_fixture/workflows" 1)"
grep -Fxq 'Checked 1 uses: entries.' <<<"$pin_output"

cat > "$pin_fixture/workflows/mixed.yaml" <<'EOF'
jobs:
  local:
    uses: ./.github/workflows/local.yml
  remote: {uses: owner/repo/.github/workflows/build.yml@3d3c42e5aac5ba805825da76410c181273ba90b1}
  build:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - run: |
          uses: attacker/this-is-command-text@main
EOF
pin_output="$(assert_action_pins "$pin_fixture/workflows" 4)"
grep -Fxq 'Checked 4 uses: entries.' <<<"$pin_output"
assert_pin_failure "$pin_fixture/workflows" 5 \
    "FAIL: extracted 4 uses: entries under $pin_fixture/workflows; need at least 5"

# A valid companion already clears the floor; no other file may be skipped.
cp "$pin_fixture/workflows/missed.yml" "$pin_fixture/unpinned/valid.yml"
printf 'jobs: {x: {steps: [{uses: attacker/exfil@main}]}}\n' > "$pin_fixture/unpinned/action.yml"
assert_pin_failure "$pin_fixture/unpinned" 1 \
    "FAIL: action.yml action is not pinned to a 40-hex SHA: attacker/exfil@main"
for reference in owner/repo/.github/workflows/build.yml@main actions/checkout@1234567; do
    printf 'jobs: {remote: {uses: %s}}\n' "$reference" > "$pin_fixture/unpinned/action.yml"
    assert_pin_failure "$pin_fixture/unpinned" 1 \
        "FAIL: action.yml action is not pinned to a 40-hex SHA: $reference"
done

# Parse and shape errors must fail even with a valid companion above the floor.
printf 'jobs: [\n' > "$pin_fixture/unpinned/action.yml"
assert_pin_failure "$pin_fixture/unpinned" 1 \
    "FAIL: cannot parse $pin_fixture/unpinned/action.yml"
printf 'jobs: {x: {steps: invalid}}\n' > "$pin_fixture/unpinned/action.yml"
assert_pin_failure "$pin_fixture/unpinned" 1 \
    "FAIL: $pin_fixture/unpinned/action.yml: job x: steps must be a sequence"
printf 'jobs: {x: {steps: [{uses: null}]}}\n' > "$pin_fixture/unpinned/action.yml"
assert_pin_failure "$pin_fixture/unpinned" 1 \
    'FAIL: action.yml action is not pinned to a 40-hex SHA: None'

# A directory-shaped workflow must fail even when valid.yml clears the floor.
rm "$pin_fixture/unpinned/action.yml"
mkdir "$pin_fixture/unpinned/blocked.yaml"
assert_pin_failure "$pin_fixture/unpinned" 1 \
    "FAIL: cannot read $pin_fixture/unpinned/blocked.yaml: [Errno 21] Is a directory: '$pin_fixture/unpinned/blocked.yaml'"

mkdir "$pin_fixture/no-actions"
printf 'jobs: {x: {steps: [{run: echo hello}]}}\n' > "$pin_fixture/no-actions/run.yml"
assert_pin_failure "$pin_fixture/no-actions" 1 \
    "FAIL: extracted 0 uses: entries under $pin_fixture/no-actions; need at least 1"

# -S omits site-packages, including the external YAML parser, for this call only.
(
    python3() { command python3 -S "$@"; }
    assert_pin_failure "$pin_fixture/workflows" 4 \
        'FAIL: action pin check requires PyYAML; install it for python3'
)

# Discovery must fail with its own diagnostic, even when the count floor is zero.
mkdir "$pin_fixture/empty"
assert_pin_failure "$pin_fixture/empty" 0 \
    "FAIL: no workflow files matched under $pin_fixture/empty"

# The readable workflow clears the floor on its own: a skipped file must not
# masquerade as a workflow with no uses. Root bypasses mode 000 permissions.
if (( EUID == 0 )); then
    printf 'SKIP: unreadable workflow fixture requires a non-root user\n' >&2
else
    mkdir "$pin_fixture/unreadable"
    printf 'jobs: {local: {uses: ./.github/workflows/local.yml}}\n' > "$pin_fixture/unreadable/readable.yml"
    cp "$pin_fixture/unreadable/readable.yml" "$pin_fixture/unreadable/blocked.yaml"
    assert_action_pins "$pin_fixture/unreadable" 1
    chmod 000 "$pin_fixture/unreadable/blocked.yaml"
    assert_pin_failure "$pin_fixture/unreadable" 1 \
        "FAIL: cannot read $pin_fixture/unreadable/blocked.yaml"
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
