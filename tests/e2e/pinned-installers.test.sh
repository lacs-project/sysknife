#!/usr/bin/env bash
#
# pinned-installers.test.sh -- the helper the E2E harnesses download installers
# with must verify a pinned sha256 BEFORE it runs anything.
#
# tests/e2e/provision.sh, tests/e2e/ubuntu-provision.sh and the e2e workflow used
# to run `curl https://... | sh`, which executes whatever the server sends. The
# helper in tests/e2e/pinned-installers.sh fetches to a file, compares the sha256
# with a pinned value and only then runs the file. This test drives that helper
# against a stubbed curl, so it needs no VM, no network and no root.
#
# Every "must not run" case has a positive control that goes through the same
# stub and DOES run. Without it, a stub that never reached the helper would make
# the refusals pass for the wrong reason.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="$repo_root/tests/e2e/pinned-installers.sh"
[ -f "$helper" ] || { printf 'FAIL: missing %s\n' "$helper" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }
ok() { printf 'ok: %s\n' "$1"; }

# shellcheck source=tests/e2e/pinned-installers.sh
source "$helper"

# --- curl stub: records its arguments, writes $STUB_BODY to --output ---------
curl_log="$tmp/curl.log"
STUB_BODY="$tmp/body"
STUB_CURL_RC=0
curl() {
    local out='' i
    printf '%s\n' "$*" >>"$curl_log"
    local args=("$@")
    for ((i = 0; i < ${#args[@]}; i++)); do
        if [ "${args[i]}" = "--output" ]; then out="${args[i + 1]}"; fi
    done
    [ "$STUB_CURL_RC" -eq 0 ] || return "$STUB_CURL_RC"
    [ -n "$out" ] || { printf 'stub curl: no --output given\n' >&2; return 90; }
    cp "$STUB_BODY" "$out"
}
STUB_UNAME=x86_64
uname() { printf '%s\n' "$STUB_UNAME"; }

curl_calls() { if [ -f "$curl_log" ]; then wc -l <"$curl_log"; else echo 0; fi; }
reset_log() { rm -f "$curl_log"; }
sha_of() { local out; out="$(sha256sum <"$1")"; printf '%s' "${out%% *}"; }

# --- 1. constants are well formed --------------------------------------------
[[ "$PINNED_RUSTUP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "PINNED_RUSTUP_VERSION is not x.y.z: $PINNED_RUSTUP_VERSION"
[[ "$PINNED_OLLAMA_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "PINNED_OLLAMA_VERSION is not x.y.z: $PINNED_OLLAMA_VERSION"
[[ "$PINNED_OLLAMA_INSTALLER_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "PINNED_OLLAMA_INSTALLER_COMMIT is not a 40-hex commit"
for name in PINNED_RUSTUP_INIT_SHA256_X86_64 PINNED_RUSTUP_INIT_SHA256_AARCH64 PINNED_OLLAMA_INSTALLER_SHA256; do
    [[ "${!name}" =~ ^[0-9a-f]{64}$ ]] || fail "$name is not 64 lowercase hex digits"
done
[ "$PINNED_RUSTUP_INIT_SHA256_X86_64" != "$PINNED_RUSTUP_INIT_SHA256_AARCH64" ] \
    || fail "the x86_64 and aarch64 rustup-init digests are identical, so one is a copy"
ok "constants are well formed"

# --- 2. fetch_verified --------------------------------------------------------
printf 'payload one\n' >"$STUB_BODY"
good="$(sha_of "$STUB_BODY")"
dest="$tmp/out/file"
mkdir -p "$tmp/out"

reset_log
if fetch_verified "https://example.test/x" "$good" "$dest" 2>"$tmp/err"; then
    cmp -s "$STUB_BODY" "$dest" && ok "matching digest installs the file" || fail "matching digest left wrong content"
else
    fail "matching digest was refused: $(cat "$tmp/err")"
fi
grep -Fq -- "--proto =https" "$curl_log" && grep -Fq -- "--tlsv1.2" "$curl_log" && grep -Fq -- "--fail" "$curl_log" \
    && ok "curl is called with --proto =https, --tlsv1.2 and --fail" \
    || fail "curl was not called with --proto =https --tlsv1.2 --fail: $(cat "$curl_log")"

rm -f "$dest"
bad="$(printf '%064d' 0)"
reset_log
if fetch_verified "https://example.test/x" "$bad" "$dest" 2>"$tmp/err"; then
    fail "a checksum mismatch was accepted"
else
    [ ! -e "$dest" ] && ok "mismatch leaves nothing at the destination" || fail "mismatch left a file at the destination"
    grep -qi 'checksum mismatch' "$tmp/err" && ok "mismatch is reported on stderr" || fail "mismatch said nothing: $(cat "$tmp/err")"
    [ -z "$(find "$tmp/out" -mindepth 1)" ] && ok "mismatch leaves no partial file behind" || fail "partial file left: $(find "$tmp/out" -mindepth 1)"
fi

# A previously verified file must not be replaced by an unverified one.
printf 'old verified\n' >"$dest"
if fetch_verified "https://example.test/x" "$bad" "$dest" 2>/dev/null; then fail "mismatch over an existing file was accepted"; fi
[ "$(cat "$dest")" = "old verified" ] && ok "mismatch keeps the existing file" || fail "mismatch replaced the existing file"
rm -f "$dest"

STUB_CURL_RC=22
if fetch_verified "https://example.test/x" "$good" "$dest" 2>/dev/null; then fail "a failed download was accepted"; else
    [ ! -e "$dest" ] && ok "failed download leaves nothing" || fail "failed download left a file"
fi
STUB_CURL_RC=0

# A move that fails after a verified download must be reported, and must not
# leave the partial file behind.
rm -f "$dest"
mv() { return 1; }
if fetch_verified "https://example.test/x" "$good" "$dest" 2>/dev/null; then fail "a failed move was reported as success"; fi
unset -f mv
if [ -z "$(find "$tmp/out" -mindepth 1)" ]; then ok "a failed move is reported and leaves nothing behind"; else fail "a failed move left: $(find "$tmp/out" -mindepth 1)"; fi

reset_log
if fetch_verified "http://example.test/x" "$good" "$dest" 2>/dev/null; then fail "an http URL was accepted"; else
    [ "$(curl_calls)" -eq 0 ] && ok "http URL refused before any download" || fail "http URL reached curl"
fi
for malformed in "" "abc" "${good^^}" "${good}0" "sha256:${good}"; do
    reset_log
    if fetch_verified "https://example.test/x" "$malformed" "$dest" 2>/dev/null; then fail "malformed digest accepted: '$malformed'"; fi
    [ "$(curl_calls)" -eq 0 ] || fail "malformed digest '$malformed' reached curl"
done
ok "malformed digests are refused before any download"

# --- 3. pinned_install_rustup -------------------------------------------------
# The stub "rustup-init" records that it ran and with which arguments.
marker="$tmp/rustup-ran"
make_rustup_body() {
    printf '#!/bin/sh\nprintf "%%s\\n" "$*" > %q\n' "$marker" >"$STUB_BODY"
    chmod +x "$STUB_BODY"
}
make_rustup_body
body_sha="$(sha_of "$STUB_BODY")"
saved_x86="$PINNED_RUSTUP_INIT_SHA256_X86_64"
saved_arm="$PINNED_RUSTUP_INIT_SHA256_AARCH64"

# positive control: the digest matches, so it must run, with the flags the
# harness always passed through sh.rustup.rs.
rm -f "$marker"; reset_log
PINNED_RUSTUP_INIT_SHA256_X86_64="$body_sha"
if pinned_install_rustup 2>"$tmp/err"; then
    [ -f "$marker" ] && [ "$(cat "$marker")" = "-y --default-toolchain stable" ] \
        && ok "rustup-init runs with -y --default-toolchain stable once the digest matches" \
        || fail "rustup-init did not run with the expected arguments: $(cat "$marker" 2>/dev/null)"
else
    fail "positive control failed: $(cat "$tmp/err")"
fi
grep -Fq "https://static.rust-lang.org/rustup/archive/${PINNED_RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" "$curl_log" \
    && ok "x86_64 downloads the versioned rustup-init URL" || fail "wrong x86_64 URL: $(cat "$curl_log")"

# aarch64 selects its own digest and URL.
STUB_UNAME=aarch64; rm -f "$marker"; reset_log
PINNED_RUSTUP_INIT_SHA256_X86_64="$saved_x86"; PINNED_RUSTUP_INIT_SHA256_AARCH64="$body_sha"
pinned_install_rustup 2>/dev/null && [ -f "$marker" ] \
    && ok "aarch64 uses PINNED_RUSTUP_INIT_SHA256_AARCH64" || fail "aarch64 did not run under its own digest"
grep -Fq "/${PINNED_RUSTUP_VERSION}/aarch64-unknown-linux-gnu/rustup-init" "$curl_log" \
    && ok "aarch64 downloads the aarch64 URL" || fail "wrong aarch64 URL: $(cat "$curl_log")"
# ...and x86_64's digest must not authorise an aarch64 binary.
PINNED_RUSTUP_INIT_SHA256_AARCH64="$saved_arm"; PINNED_RUSTUP_INIT_SHA256_X86_64="$body_sha"; rm -f "$marker"
if pinned_install_rustup 2>/dev/null; then fail "the x86_64 digest authorised an aarch64 download"; fi
[ ! -f "$marker" ] && ok "an aarch64 host does not accept the x86_64 digest" || fail "binary ran under the wrong digest"

# mismatch: the pinned digest is not the body's, so nothing may run.
STUB_UNAME=x86_64; rm -f "$marker"; reset_log
PINNED_RUSTUP_INIT_SHA256_X86_64="$saved_x86"
if pinned_install_rustup 2>/dev/null; then fail "rustup-init ran although its digest did not match"; fi
[ ! -f "$marker" ] && ok "a digest mismatch never runs rustup-init" || fail "rustup-init ran on a digest mismatch"

# unsupported architecture: refuse, and do not even download.
STUB_UNAME=sparc64; rm -f "$marker"; reset_log
if pinned_install_rustup 2>/dev/null; then fail "an unsupported architecture was accepted"; fi
[ "$(curl_calls)" -eq 0 ] && [ ! -f "$marker" ] && ok "an unsupported architecture is refused before any download" || fail "unsupported architecture reached curl or ran"
STUB_UNAME=x86_64
PINNED_RUSTUP_INIT_SHA256_X86_64="$saved_x86"

# --- 4. pinned_install_ollama -------------------------------------------------
# The stub "install.sh" records the OLLAMA_VERSION the installer would see.
omarker="$tmp/ollama-ran"
printf '#!/bin/sh\nprintf "%%s\\n" "${OLLAMA_VERSION:-unset}" > %q\n' "$omarker" >"$STUB_BODY"
osha="$(sha_of "$STUB_BODY")"
saved_osha="$PINNED_OLLAMA_INSTALLER_SHA256"

rm -f "$omarker"; reset_log
PINNED_OLLAMA_INSTALLER_SHA256="$osha"
if pinned_install_ollama 2>"$tmp/err"; then
    [ "$(cat "$omarker" 2>/dev/null)" = "$PINNED_OLLAMA_VERSION" ] \
        && ok "the installer runs with OLLAMA_VERSION pinned to $PINNED_OLLAMA_VERSION" \
        || fail "installer did not see the pinned version: $(cat "$omarker" 2>/dev/null)"
else
    fail "ollama positive control failed: $(cat "$tmp/err")"
fi
grep -Fq "https://raw.githubusercontent.com/ollama/ollama/${PINNED_OLLAMA_INSTALLER_COMMIT}/scripts/install.sh" "$curl_log" \
    && ok "the installer URL is pinned to a commit" || fail "installer URL is not commit-pinned: $(cat "$curl_log")"

rm -f "$omarker"; PINNED_OLLAMA_INSTALLER_SHA256="$saved_osha"
if pinned_install_ollama 2>/dev/null; then fail "the ollama installer ran although its digest did not match"; fi
[ ! -f "$omarker" ] && ok "a digest mismatch never runs the ollama installer" || fail "ollama installer ran on a digest mismatch"

# A caller's own OLLAMA_VERSION must not leak into the constants or back out.
[ "${OLLAMA_VERSION:-unset}" = "unset" ] && ok "the helper does not export OLLAMA_VERSION" || fail "helper leaked OLLAMA_VERSION=$OLLAMA_VERSION"

if [ "$failures" -ne 0 ]; then
    printf '\n%d pinned-installers failure(s).\n' "$failures" >&2
    exit 1
fi
printf 'Pinned installers passed.\n'
