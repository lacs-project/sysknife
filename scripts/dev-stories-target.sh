#!/usr/bin/env bash

dev_stories_target_dir() {
    local repo_root="${1:?repository root is required}"
    cargo metadata --format-version 1 --no-deps --locked \
        --manifest-path "$repo_root/Cargo.toml" |
        jq -er '.target_directory'
}

dev_stories_configure_paths() {
    local target_dir="${1:?Cargo target directory is required}"
    local built_cli="$target_dir/release/sysknife"
    local found_cli

    export DAEMON_BIN="$target_dir/release/sysknife-daemon"
    export PATH="$target_dir/release:$PATH"

    found_cli="$(command -v sysknife || true)"
    if [[ "$found_cli" != "$built_cli" ]]; then
        printf 'ERROR: expected built sysknife at %s, found %s\n' \
            "$built_cli" "${found_cli:-not found on PATH}" >&2
        return 1
    fi
}
