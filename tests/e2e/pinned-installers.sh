#!/usr/bin/env bash
# pinned-installers.sh -- sourced, never executed.
#
# Downloads the two installers the E2E harnesses need, rustup and Ollama, and
# runs each only after its sha256 matches a value pinned in this file. They used
# to be `curl https://... | sh`, which runs whatever the server sends at that
# moment, as root, inside a VM that also holds a provider API key.
#
#   source tests/e2e/pinned-installers.sh
#   pinned_install_rustup      # rustup-init for this CPU, as the calling user
#   pinned_install_ollama      # Ollama's install.sh at a fixed commit and version
#
# A checksum mismatch is an error, never a skip: the function returns non-zero
# and nothing it downloaded runs. tests/e2e/pinned-installers.test.sh drives both
# functions against a stubbed curl and fails if an unverified file ever runs.
#
# Used by tests/e2e/provision.sh, tests/e2e/ubuntu-provision.sh and the "Install
# Ollama" step of .github/workflows/e2e.yml.
#
# What is and is not pinned:
#   rustup   The rustup-init binary itself, from the versioned archive path
#            (https://static.rust-lang.org/rustup/archive/<version>/<triple>/),
#            one digest per CPU. `--default-toolchain stable` then resolves the
#            toolchain, and rustup verifies the hashes of the components it
#            downloads against the signed channel manifest.
#   ollama   Ollama's install.sh, from a URL that names a commit rather than a
#            branch, so the script cannot change. The script downloads its
#            payload from ollama.com for PINNED_OLLAMA_VERSION and does not
#            verify it. Pinning that payload needs a different install path.
#
# To bump rustup:
#   v=<new version>; for t in x86_64 aarch64; do
#     curl -fsSL "https://static.rust-lang.org/rustup/archive/$v/$t-unknown-linux-gnu/rustup-init.sha256"
#   done
#   Compare each digest with a download you hashed yourself, then update the three
#   PINNED_RUSTUP_* values together.
# To bump Ollama:
#   Pick a release tag, resolve it to a commit
#   (gh api repos/ollama/ollama/git/ref/tags/v<version> --jq .object.sha), hash
#   https://raw.githubusercontent.com/ollama/ollama/<commit>/scripts/install.sh,
#   and update the three PINNED_OLLAMA_* values together.

PINNED_RUSTUP_VERSION=1.29.2
PINNED_RUSTUP_INIT_SHA256_X86_64=5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4
PINNED_RUSTUP_INIT_SHA256_AARCH64=a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697

PINNED_OLLAMA_VERSION=0.40.11
PINNED_OLLAMA_INSTALLER_COMMIT=675150d6ad2747df1e218ef59de9194bc4a7e538
PINNED_OLLAMA_INSTALLER_SHA256=25f64b810b947145095956533e1bdf56eacea2673c55a7e586be4515fc882c9f

# fetch_verified URL SHA256 DEST
#   Download URL over https, compare its sha256 with SHA256, and only then place
#   it at DEST. On any failure DEST is left exactly as it was and the partial
#   download is removed. Returns 0 on success, 1 on a download or checksum
#   failure, 2 on bad arguments.
fetch_verified() {
    local url="$1" want="$2" dest="$3" partial got

    if [[ "$url" != https://* ]]; then
        printf 'fetch_verified: refusing a non-https URL: %s\n' "$url" >&2
        return 2
    fi
    if [[ ! "$want" =~ ^[0-9a-f]{64}$ ]]; then
        printf 'fetch_verified: the pinned digest for %s is not 64 lowercase hex digits\n' "$url" >&2
        return 2
    fi
    partial="$(mktemp "${dest}.partial.XXXXXX")" || return 1

    if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --output "$partial" "$url"; then
        rm -f "$partial"
        printf 'fetch_verified: download failed: %s\n' "$url" >&2
        return 1
    fi
    if ! got="$(sha256sum <"$partial")"; then
        rm -f "$partial"
        printf 'fetch_verified: could not hash the download of %s\n' "$url" >&2
        return 1
    fi
    got="${got%% *}"
    if [ "$got" != "$want" ]; then
        rm -f "$partial"
        printf 'fetch_verified: checksum mismatch for %s\n  expected %s\n  got      %s\n' \
            "$url" "$want" "$got" >&2
        return 1
    fi
    mv -f "$partial" "$dest" || { rm -f "$partial"; return 1; }
}

# pinned_install_rustup
#   Same effect as `curl https://sh.rustup.rs | sh -s -- -y --default-toolchain
#   stable`, run as the calling user, from a verified rustup-init.
pinned_install_rustup() {
    local arch want dir status

    arch="$(uname -m)"
    case "$arch" in
        x86_64) want="$PINNED_RUSTUP_INIT_SHA256_X86_64" ;;
        aarch64 | arm64) arch=aarch64; want="$PINNED_RUSTUP_INIT_SHA256_AARCH64" ;;
        *)
            printf 'pinned_install_rustup: no pinned rustup-init for architecture %s\n' "$arch" >&2
            return 1
            ;;
    esac

    dir="$(mktemp -d)" || return 1
    if ! fetch_verified \
        "https://static.rust-lang.org/rustup/archive/${PINNED_RUSTUP_VERSION}/${arch}-unknown-linux-gnu/rustup-init" \
        "$want" "$dir/rustup-init"; then
        rm -rf "$dir"
        return 1
    fi
    chmod 0755 "$dir/rustup-init" || { rm -rf "$dir"; return 1; }
    "$dir/rustup-init" -y --default-toolchain stable
    status=$?
    rm -rf "$dir"
    return "$status"
}

# pinned_install_ollama
#   Same effect as `curl https://ollama.com/install.sh | sh`, from a verified
#   copy of the installer at a fixed commit, installing the pinned version.
pinned_install_ollama() {
    local dir status

    dir="$(mktemp -d)" || return 1
    if ! fetch_verified \
        "https://raw.githubusercontent.com/ollama/ollama/${PINNED_OLLAMA_INSTALLER_COMMIT}/scripts/install.sh" \
        "$PINNED_OLLAMA_INSTALLER_SHA256" "$dir/install.sh"; then
        rm -rf "$dir"
        return 1
    fi
    OLLAMA_VERSION="$PINNED_OLLAMA_VERSION" sh "$dir/install.sh"
    status=$?
    rm -rf "$dir"
    return "$status"
}
