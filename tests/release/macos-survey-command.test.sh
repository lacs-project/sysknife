#!/usr/bin/env bash
#
# macos-survey-command.test.sh — the macOS survey command printed in
# CONTRIBUTING.md must keep selecting a real slice of the suite.
#
# #411 measured the workspace on a hosted macOS runner: the whole-workspace
# build stops at sysknife-cli (an ungated SocketTarget::Vsock reference), and
# with that package excluded the rest of the suite runs with thirteen known
# host-assumption reds. CONTRIBUTING.md answers "what can I trust on a Mac"
# with that survey command — and a documented command that silently selects
# nothing reads exactly like one that passes, the failure this repository has
# already been bitten by (see scripts/test_baseline.sh).
#
# Design rules, both learned in review on #515:
#
#   * The command is read out of CONTRIBUTING.md, never restated here, so
#     editing the doc re-targets the guard without touching this file.
#   * A pattern that matched nothing would make every assertion below
#     vacuously true. Demand exactly one documented command before asserting
#     anything about it.
#
# Swaps `nextest run` for `nextest list` on the documented arguments, so the
# check enumerates the selection without running it. Needs cargo and
# cargo-nextest; place it after the suite step so the list pass is
# metadata-only. Wired into the test-workspace job of .github/workflows/ci.yml;
# scripts/ci-local.sh runs it with every other release test in its hygiene group.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doc="$repo_root/CONTRIBUTING.md"

[ -f "$doc" ] || { printf 'missing file: %s\n' "$doc" >&2; exit 1; }
# Fail closed and say why: without nextest the listing below cannot run, and
# cargo's own "no such command" reads like the documented command broke.
if ! (cd "$repo_root" && cargo nextest --version) >/dev/null 2>&1; then
    printf 'cargo-nextest is not installed, so the macOS survey command was not checked\n' >&2
    printf '  install: cargo install cargo-nextest --locked\n' >&2
    exit 1
fi

# Exactly one documented survey command. A second copy would let the two
# drift apart, which is the defect this guard exists to stop.
mapfile -t commands < <(grep -E '^cargo nextest run .* --exclude ' "$doc")
if [ "${#commands[@]}" -ne 1 ]; then
    printf 'expected exactly one macOS survey command in CONTRIBUTING.md, found %d\n' \
        "${#commands[@]}" >&2
    exit 1
fi

read -r -a argv <<<"${commands[0]}"
if [ "${#argv[@]}" -lt 3 ] || [ "${argv[2]}" != "run" ]; then
    printf 'documented macOS survey command is not a nextest run: %s\n' \
        "${commands[0]}" >&2
    exit 1
fi

case "${commands[0]}" in
    *--locked*) : ;;
    *)
        printf 'documented macOS survey command is missing --locked: %s\n' \
            "${commands[0]}" >&2
        exit 1
        ;;
esac

# nextest ignores an --exclude naming no workspace package, so a renamed
# sysknife-cli would put the package that does not build on macOS back into the
# documented command while every check below still passed. Ask cargo which
# packages exist and refuse an exclusion that names none of them.
excluded=()
for ((k = 0; k < ${#argv[@]}; k++)); do
    if [ "${argv[k]}" = "--exclude" ] && [ $((k + 1)) -lt ${#argv[@]} ]; then
        excluded+=("${argv[k + 1]}")
    fi
done
if [ "${#excluded[@]}" -eq 0 ]; then
    printf 'documented macOS survey command excludes no package: %s\n' "${commands[0]}" >&2
    exit 1
fi
if ! members=$(cd "$repo_root" && cargo metadata --no-deps --format-version 1 --locked |
    python3 -c 'import json, sys; print("\n".join(p["name"] for p in json.load(sys.stdin)["packages"]))'); then
    printf 'could not list the workspace packages, so the exclusion was not checked\n' >&2
    exit 1
fi
for pkg in "${excluded[@]}"; do
    if ! grep -qxF -- "$pkg" <<<"$members"; then
        printf 'documented macOS survey command excludes %s, which is not a workspace package\n' \
            "$pkg" >&2
        exit 1
    fi
done

# Same selection, enumeration instead of execution. --no-fail-fast is
# run-only.
list_argv=()
for word in "${argv[@]}"; do
    if [ "$word" = "run" ]; then
        list_argv+=("list")
    elif [ "$word" = "--no-fail-fast" ]; then
        continue
    else
        list_argv+=("$word")
    fi
done

if ! list_out=$(cd "$repo_root" && "${list_argv[@]}" 2>&1); then
    printf 'documented macOS survey command no longer runs:\n  %s\n%s\n' \
        "${commands[0]}" "$list_out" >&2
    exit 1
fi

# Every nextest-listed test id contains `::`; nothing else in the listing
# does. An empty selection is the silent rot this guard is here to catch.
tests_found=$(printf '%s\n' "$list_out" | grep -c '::' || true)
if [ "$tests_found" -lt 1 ]; then
    printf 'documented macOS survey command selects no tests: %s\n' \
        "${commands[0]}" >&2
    exit 1
fi

printf 'macOS survey command selects %s tests\n' "$tests_found"
