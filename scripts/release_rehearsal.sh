#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="check"
output="${repo_root}/target/release-rehearsal"

usage() {
    cat <<'EOF'
Usage: scripts/release_rehearsal.sh [--check | --full] [--output DIR]

Validate the release contract and optionally build the exact local artifacts.
This command never publishes packages, creates tags, or creates GitHub releases.

  --check       Fast metadata, claims, tool, and artifact-name preflight (default)
  --full        Package crates and npm setup, build binaries, run smoke checks,
                and write checksums into the output directory
  --output DIR  Artifact directory for --full
  --help        Show this help
EOF
}

while (($# > 0)); do
    case "$1" in
        --check) mode="check" ;;
        --full) mode="full" ;;
        --output)
            shift
            [[ $# -gt 0 ]] || { printf '%s\n' 'ERROR: --output requires a directory' >&2; exit 2; }
            output="$1"
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --publish)
            printf '%s\n' 'ERROR: release rehearsal never publishes; use the protected tag workflow' >&2
            exit 2
            ;;
        *)
            printf 'ERROR: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

cd "$repo_root"

for tool in cargo node npm sha256sum file; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'ERROR: required tool is missing: %s\n' "$tool" >&2
        exit 1
    }
done

bash scripts/check_repo_completeness.sh
bash scripts/check_release_versions.sh
bash scripts/check_public_claims.sh
cargo metadata --locked --no-deps --format-version 1 >/dev/null
node packages/setup/index.js --help >/dev/null

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' apps/sysknife-cli/Cargo.toml | head -n 1)"
case "$(uname -m)" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
        printf 'ERROR: unsupported release architecture: %s\n' "$(uname -m)" >&2
        exit 1
        ;;
esac

cli_name="sysknife-v${version}-linux-${arch}"
daemon_name="sysknife-daemon-v${version}-linux-${arch}"
printf 'Release artifact: %s\n' "$cli_name"
printf 'Release artifact: %s\n' "$daemon_name"

if [[ "$mode" == "check" ]]; then
    printf 'Rehearsal preflight passed for v%s on %s.\n' "$version" "$arch"
    exit 0
fi

mkdir -p "$output"
output="$(cd "$output" && pwd)"

crates=(
    sysknife-proto
    sysknife-core
    sysknife-types
    sysknife-brain
    sysknife-daemon
    sysknife-cli
)

for crate in "${crates[@]}"; do
    # The first public release cannot resolve versioned sibling dependencies
    # from crates.io. Rehearsal-only patches model the crates already published
    # earlier in the release order; packaged manifests keep registry versions.
    package_overrides=()
    case "$crate" in
        sysknife-proto|sysknife-core) ;;
        sysknife-types)
            package_overrides+=(--config 'patch.crates-io.sysknife-proto.path="crates/sysknife-proto"')
            ;;
        sysknife-brain)
            package_overrides+=(
                --config 'patch.crates-io.sysknife-proto.path="crates/sysknife-proto"'
                --config 'patch.crates-io.sysknife-core.path="crates/sysknife-core"'
                --config 'patch.crates-io.sysknife-types.path="crates/sysknife-types"'
            )
            ;;
        sysknife-daemon)
            package_overrides+=(
                --config 'patch.crates-io.sysknife-proto.path="crates/sysknife-proto"'
                --config 'patch.crates-io.sysknife-core.path="crates/sysknife-core"'
                --config 'patch.crates-io.sysknife-types.path="crates/sysknife-types"'
                --config 'patch.crates-io.sysknife-brain.path="crates/sysknife-brain"'
            )
            ;;
        sysknife-cli)
            package_overrides+=(
                --config 'patch.crates-io.sysknife-proto.path="crates/sysknife-proto"'
                --config 'patch.crates-io.sysknife-core.path="crates/sysknife-core"'
                --config 'patch.crates-io.sysknife-types.path="crates/sysknife-types"'
                --config 'patch.crates-io.sysknife-brain.path="crates/sysknife-brain"'
                --config 'patch.crates-io.sysknife-daemon.path="crates/sysknife-daemon"'
            )
            ;;
    esac
    cargo package -p "$crate" --locked --allow-dirty --no-verify \
        "${package_overrides[@]}"
    install -m 0644 "target/package/${crate}-${version}.crate" "$output/"
done

npm pack ./packages/setup --pack-destination "$output" >/dev/null
cargo build --release --locked -p sysknife-cli -p sysknife-daemon

install -m 0755 target/release/sysknife "$output/$cli_name"
install -m 0755 target/release/sysknife-daemon "$output/$daemon_name"
"$output/$cli_name" --help >/dev/null
file "$output/$daemon_name" | grep -Eq 'ELF .* executable'

(
    cd "$output"
    sha256sum "$cli_name" "$daemon_name" > "sha256sums-linux-${arch}.txt"
)

printf 'Full release rehearsal passed. Artifacts: %s\n' "$output"
