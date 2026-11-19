#!/usr/bin/env bash
# The audit-tamper demo: what an operator sees the morning after an agent worked
# on a server, and what happens when someone edits the log.
#
# Everything in it is the real thing: the daemon, the MCP server, the approval
# receipts, the Ed25519 audit chain and `sysknife audit verify`. An LLM plans each
# request (any provider the planner supports), so `seed` needs a provider key.
# The recording (audit-tamper.tape) needs no key: it replays a saved seed.
#
#   audit-tamper.sh seed    run the agent session once, save the daemon state
#   audit-tamper.sh shell   open a root prompt on a COPY of that state (the tape uses this)
#
# Needs podman or docker, and a debug build: cargo build -p sysknife-cli -p sysknife-daemon
# Seeding also needs SYSKNIFE_LLM_PROVIDER, SYSKNIFE_LLM_MODEL and that provider's
# key variable (GROQ_API_KEY, OPENAI_API_KEY, ...) in the environment. The key is
# passed to the container by name, never on a command line.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
bin="${SYSKNIFE_DEMO_BIN:-${CARGO_TARGET_DIR:-$root/target}/debug}"
state="${SYSKNIFE_DEMO_STATE:-${XDG_CACHE_HOME:-$HOME/.cache}/sysknife-demo/state}"
image="localhost/sysknife-audit-demo:1"

if command -v podman >/dev/null 2>&1; then
    rt=podman
elif command -v docker >/dev/null 2>&1; then
    rt=docker
else
    echo "audit-tamper: needs podman or docker" >&2
    exit 1
fi

for f in sysknife sysknife-daemon; do
    [[ -x "$bin/$f" ]] || { echo "audit-tamper: $bin/$f is missing; run: cargo build -p sysknife-cli -p sysknife-daemon" >&2; exit 1; }
done

ensure_image() {
    if ! "$rt" image exists "$image" 2>/dev/null && ! "$rt" image inspect "$image" >/dev/null 2>&1; then
        "$rt" build -q -t "$image" -f "$here/audit-tamper.Containerfile" "$here" >/dev/null
    fi
}

# Binaries and helper scripts are mounted read-only; state is the only writable mount.
run_args() {  # $1 = state directory to mount
    printf '%s\n' --rm --hostname web01 \
        -v "$bin/sysknife:/usr/local/bin/sysknife:ro" \
        -v "$bin/sysknife-daemon:/usr/local/bin/sysknife-daemon:ro" \
        -v "$here/audit-tamper-guest.sh:/audit-tamper-guest.sh:ro" \
        -v "$here/audit-tamper-agent.py:/audit-tamper-agent.py:ro" \
        -v "$1:/var/lib/sysknife"
}

case "${1:-}" in
seed)
    : "${SYSKNIFE_LLM_PROVIDER:?set SYSKNIFE_LLM_PROVIDER, SYSKNIFE_LLM_MODEL and the provider key variable}"
    : "${SYSKNIFE_LLM_MODEL:?set SYSKNIFE_LLM_MODEL}"
    # Replace only a directory that looks like an earlier seed.
    if [[ -e "$state" ]] && [[ -n "$(ls -A "$state")" ]] && [[ ! -f "$state/daemon.sqlite" ]]; then
        echo "audit-tamper: $state exists and is not a previous seed; refusing to delete it" >&2
        exit 1
    fi
    rm -rf -- "${state:?}"
    mkdir -p "$state"
    ensure_image
    key_args=()
    for v in GROQ_API_KEY OPENAI_API_KEY ANTHROPIC_API_KEY GEMINI_API_KEY; do
        [[ -n "${!v:-}" ]] && key_args+=(-e "$v")
    done
    mapfile -t args < <(run_args "$state")
    "$rt" run "${args[@]}" -e SYSKNIFE_LLM_PROVIDER -e SYSKNIFE_LLM_MODEL "${key_args[@]}" \
        "$image" sh /audit-tamper-guest.sh seed
    echo "saved to $state"
    ;;
shell)
    [[ -f "$state/daemon.sqlite" ]] || { echo "audit-tamper: no seed at $state; run: $0 seed" >&2; exit 1; }
    ensure_image
    work="$(mktemp -d)"
    trap 'rm -rf -- "$work"' EXIT
    cp -a "$state/." "$work/"
    mapfile -t args < <(run_args "$work")
    "$rt" run -it "${args[@]}" "$image" sh /audit-tamper-guest.sh shell
    ;;
*)
    echo "usage: $0 seed|shell" >&2
    exit 2
    ;;
esac
