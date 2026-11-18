#!/usr/bin/env bash
#
# dev-stories-target-dir.test.sh — dev-stories.sh must use Cargo's configured
# target directory for both binaries, ahead of any older sysknife on PATH.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

target_dir="$work/custom target"
stale_dir="$work/earlier"
stubs="$work/stubs"
mkdir -p "$target_dir/release" "$stale_dir" "$stubs"

cat >"$stubs/cargo" <<'CARGO'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$CARGO_LOG"
[[ "${1:-}" == metadata ]] || { printf 'unexpected cargo command: %s\n' "$*" >&2; exit 1; }
printf '{"target_directory":"%s"}\n' "$STUB_TARGET_DIR"
CARGO
chmod +x "$stubs/cargo"

printf '#!/bin/sh\nexit 0\n' >"$target_dir/release/sysknife"
printf '#!/bin/sh\nexit 0\n' >"$target_dir/release/sysknife-daemon"
printf '#!/bin/sh\nexit 0\n' >"$stale_dir/sysknife"
chmod +x "$target_dir/release/sysknife" "$target_dir/release/sysknife-daemon" "$stale_dir/sysknife"

export STUB_TARGET_DIR="$target_dir" CARGO_LOG="$work/cargo.log"
export PATH="$stubs:$stale_dir:$PATH"
source "$repo_root/scripts/dev-stories-target.sh"

resolved="$(dev_stories_target_dir "$repo_root")"
[[ "$resolved" == "$target_dir" ]] || {
    printf 'target directory: expected %s, got %s\n' "$target_dir" "$resolved" >&2
    exit 1
}
[[ "$(wc -l <"$CARGO_LOG")" -eq 1 ]] || {
    printf 'Cargo metadata should be queried once\n' >&2
    exit 1
}
[[ "$(command -v sysknife)" == "$stale_dir/sysknife" ]] || {
    printf 'test setup did not put the stale CLI first on PATH\n' >&2
    exit 1
}

dev_stories_configure_paths "$resolved"
[[ "$DAEMON_BIN" == "$target_dir/release/sysknife-daemon" ]] || {
    printf 'daemon path: expected %s/release/sysknife-daemon, got %s\n' "$target_dir" "$DAEMON_BIN" >&2
    exit 1
}
[[ "$(command -v sysknife)" == "$target_dir/release/sysknife" ]] || {
    printf 'the built CLI did not win PATH resolution\n' >&2
    exit 1
}

rm "$target_dir/release/sysknife"
if output="$(dev_stories_configure_paths "$resolved" 2>&1)"; then
    printf 'missing built CLI unexpectedly passed the PATH guard\n' >&2
    exit 1
fi
[[ "$(command -v sysknife)" == "$stale_dir/sysknife" ]] || {
    printf 'test setup did not expose the stale CLI after removing the built one\n' >&2
    exit 1
}
grep -Fq 'expected built sysknife' <<<"$output" || {
    printf 'PATH guard diagnostic was unclear: %s\n' "$output" >&2
    exit 1
}

printf 'dev-stories-target-dir: configured target paths and stale-CLI guard passed\n'
