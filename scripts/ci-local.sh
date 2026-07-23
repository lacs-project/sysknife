#!/usr/bin/env bash
set -euo pipefail

# ci-local.sh — mirror the runnable jobs from .github/workflows/ci.yml on a
# contributor's machine, so failures are caught before pushing (and before
# spending GitHub Actions minutes). See docs/developer-guide.md, "Running CI
# locally", for the full write-up.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Host port for the throwaway postgres-contract container. Deliberately not
# postgres's own default (5432) so a developer's already-running local
# Postgres server, if any, is never shadowed or port-conflicted.
readonly POSTGRES_HOST_PORT=5433
readonly POSTGRES_CONTAINER_NAME="sysknife-ci-local-postgres"
# Health-check budget: 30 retries * 1s = 30s, generous for a cold
# `postgres:17-alpine` pull + start on a typical dev machine.
readonly POSTGRES_HEALTH_RETRIES=30
readonly POSTGRES_HEALTH_INTERVAL_SECS=1

mode="full"
run_postgres=true

usage() {
    cat <<'EOF'
Usage: scripts/ci-local.sh [--fast] [--no-postgres] [--install-hooks] [--help]

Mirror the runnable jobs from .github/workflows/ci.yml locally so failures
are caught before pushing (and before spending GitHub Actions minutes).

  --fast           Rust fmt/clippy/nextest + frontend tsc/vitest only (the
                    same subset the pre-push hook runs)
  --no-postgres    Skip the optional postgres-contract job even when a
                    container runtime or SYSKNIFE_TEST_POSTGRES_URL is present
  --install-hooks  Set git core.hooksPath to .githooks (enables the pre-push
                    gate: scripts/ci-local.sh --fast) and exit -- does not
                    run any checks
  --help           Show this help and exit

Groups (default, full run): rust, frontend, hygiene, security,
postgres-contract (optional -- skipped if no runtime/URL is available).

For a full Docker-based replay of the exact GitHub Actions workflow (all
jobs, exact runner image), see https://github.com/nektos/act instead.
EOF
}

while (($# > 0)); do
    case "$1" in
        --fast) mode="fast" ;;
        --no-postgres) run_postgres=false ;;
        --install-hooks)
            git -C "$repo_root" config core.hooksPath .githooks
            printf 'ci-local: git core.hooksPath set to .githooks (pre-push gate enabled)\n'
            printf 'ci-local: disable with: git config --unset core.hooksPath\n'
            exit 0
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            printf 'ci-local: unknown flag: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

cd "$repo_root"

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

RESULTS=()
hard_failures=0

have() { command -v "$1" >/dev/null 2>&1; }

# Record one outcome. status is one of PASS / FAIL / WARN / SKIP; only FAIL
# counts toward the exit code.
record() {
    local status="$1" label="$2"
    RESULTS+=("${status}  ${label}")
    if [[ "$status" == "FAIL" ]]; then
        hard_failures=$((hard_failures + 1))
    fi
}

# Run a step, print its heading, and record PASS/FAIL. Always returns 0 so a
# bare call never trips `set -e` -- every check runs even after an earlier one
# fails, and the aggregate result is decided at the end from $hard_failures.
run_step() {
    local label="$1"
    shift
    printf '\n==> %s\n' "$label"
    if "$@"; then
        record PASS "$label"
    else
        record FAIL "$label"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

printf 'ci-local: detecting tools...\n'
tools=(cargo cargo-nextest cargo-audit node npm markdownlint-cli2 markdown-link-check yamllint shellcheck)
for t in "${tools[@]}"; do
    if have "$t"; then
        printf '  [x] %s\n' "$t"
    else
        printf '  [ ] %s (not found)\n' "$t"
    fi
done

missing_required=()
have cargo || missing_required+=(cargo)
have node || missing_required+=(node)

if ((${#missing_required[@]} > 0)); then
    printf '\nci-local: FATAL missing required tool(s): %s\n' "${missing_required[*]}" >&2
    printf 'Install cargo: https://rustup.rs\n' >&2
    printf 'Install node:  https://nodejs.org\n' >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# rust
# ---------------------------------------------------------------------------

run_cargo_doc() {
    RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --workspace --locked
}

run_rust_group() {
    printf '\n### rust\n'
    run_step 'rust: cargo fmt --all --check' cargo fmt --all --check
    run_step 'rust: cargo clippy --workspace --all-features --locked -- -D warnings' \
        cargo clippy --workspace --all-features --locked -- -D warnings

    if [[ "$mode" == "full" ]]; then
        run_step 'rust: cargo doc (RUSTDOCFLAGS=-D warnings)' run_cargo_doc
    fi

    if have cargo-nextest; then
        run_step 'rust: cargo nextest run --workspace --locked' \
            cargo nextest run --workspace --locked
    else
        record WARN 'rust: cargo nextest run -- SKIPPED (cargo-nextest not found; install: cargo install cargo-nextest --locked)'
    fi
}

# ---------------------------------------------------------------------------
# frontend (apps/sysknife-shell)
# ---------------------------------------------------------------------------

frontend_install() (
    cd "$repo_root/apps/sysknife-shell" || exit 1
    if npm ci; then
        exit 0
    fi
    printf 'ci-local: npm ci failed -- retrying with npm install (offline/lockfile-mismatch fallback)\n' >&2
    npm install
)

frontend_audit() (
    cd "$repo_root/apps/sysknife-shell" || exit 1
    npm audit --omit=dev --audit-level=high
)

frontend_tsc() (
    cd "$repo_root/apps/sysknife-shell" || exit 1
    ./node_modules/.bin/tsc --noEmit
)

frontend_vitest() (
    cd "$repo_root/apps/sysknife-shell" || exit 1
    ./node_modules/.bin/vitest run
)

run_frontend_group() {
    printf '\n### frontend (apps/sysknife-shell)\n'

    if ! have npm; then
        record WARN 'frontend: npm ci -- SKIPPED (npm not found; install: https://nodejs.org)'
        return
    fi

    printf '\n==> frontend: npm ci (falls back to npm install)\n'
    if frontend_install; then
        record PASS 'frontend: npm ci (falls back to npm install)'
    else
        record FAIL 'frontend: npm ci (falls back to npm install)'
        record SKIP 'frontend: npm audit / tsc / vitest -- SKIPPED (dependency install failed)'
        return
    fi

    if [[ "$mode" == "full" ]]; then
        printf '\n==> frontend: npm audit --omit=dev --audit-level=high (non-fatal)\n'
        if frontend_audit; then
            record PASS 'frontend: npm audit --omit=dev --audit-level=high'
        else
            record WARN 'frontend: npm audit --omit=dev --audit-level=high (non-fatal; review output above)'
        fi
    fi

    run_step 'frontend: tsc --noEmit' frontend_tsc
    run_step 'frontend: vitest run' frontend_vitest
}

# ---------------------------------------------------------------------------
# hygiene
# ---------------------------------------------------------------------------

hygiene_markdownlint() (
    cd "$repo_root" || exit 1
    markdownlint-cli2 \
        README.md \
        CONTRIBUTING.md \
        SECURITY.md \
        CODE_OF_CONDUCT.md \
        ROADMAP.md \
        docs/architecture.md \
        docs/developer-guide.md \
        docs/adr/*.md
)

hygiene_markdown_link_check() (
    cd "$repo_root" || exit 1
    files=(
        README.md
        CONTRIBUTING.md
        SECURITY.md
        CODE_OF_CONDUCT.md
        ROADMAP.md
        docs/architecture.md
        docs/developer-guide.md
        docs/adr/0001-system-boundaries.md
        docs/adr/0002-brain-provider-layer.md
        docs/adr/0003-ipc-wire-protocol.md
    )
    for f in "${files[@]}"; do
        markdown-link-check --config .markdown-link-check.json "$f" || exit 1
    done
)

hygiene_yamllint() (
    cd "$repo_root" || exit 1
    yamllint .github/ISSUE_TEMPLATE/*.yml .github/workflows/*.yml
)

# Same scan as e2e.yml's "ShellCheck maintained scripts" step -- kept here too
# since every script this task adds/touches must stay shellcheck-clean.
hygiene_shellcheck() (
    cd "$repo_root" || exit 1
    find tests/e2e tests/release scripts assets/demo \
        -type f -name '*.sh' -print0 \
        | xargs -0 shellcheck --severity=warning
)

run_hygiene_group() {
    printf '\n### hygiene\n'
    run_step 'hygiene: check_repo_completeness.sh' bash "$repo_root/scripts/check_repo_completeness.sh"
    run_step 'hygiene: check_release_versions.sh' bash "$repo_root/scripts/check_release_versions.sh"
    run_step 'hygiene: public-claims.test.sh' bash "$repo_root/tests/release/public-claims.test.sh"
    run_step 'hygiene: npm test --prefix packages/setup' npm test --prefix "$repo_root/packages/setup"
    run_step 'hygiene: release-rehearsal.test.sh' bash "$repo_root/tests/release/release-rehearsal.test.sh"
    run_step 'hygiene: ubuntu-vm-bootstrap.test.sh' bash "$repo_root/tests/e2e/ubuntu-vm-bootstrap.test.sh"

    if have markdownlint-cli2; then
        run_step 'hygiene: markdownlint-cli2' hygiene_markdownlint
    else
        record WARN 'hygiene: markdownlint-cli2 -- SKIPPED (not found; install: npm install --global markdownlint-cli2)'
    fi

    if have markdown-link-check; then
        run_step 'hygiene: markdown-link-check' hygiene_markdown_link_check
    else
        record WARN 'hygiene: markdown-link-check -- SKIPPED (not found; install: npm install --global markdown-link-check)'
    fi

    if have yamllint; then
        run_step 'hygiene: yamllint' hygiene_yamllint
    else
        record WARN 'hygiene: yamllint -- SKIPPED (not found; install: pip install yamllint)'
    fi

    if have shellcheck; then
        run_step 'hygiene: shellcheck (tests/e2e tests/release scripts assets/demo)' hygiene_shellcheck
    else
        record WARN 'hygiene: shellcheck -- SKIPPED (not found; install: sudo apt-get install shellcheck)'
    fi
}

# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------

run_security_group() {
    printf '\n### security\n'
    if have cargo-audit; then
        # RUSTSEC-2026-0097 is ignored here too -- see the matching comment in
        # .github/workflows/ci.yml for why (GUI-only transitive dep, no fix yet).
        run_step 'security: cargo audit --ignore RUSTSEC-2026-0097' \
            cargo audit --ignore RUSTSEC-2026-0097
    else
        record WARN 'security: cargo audit -- SKIPPED (cargo-audit not found; install: cargo install cargo-audit --locked)'
    fi
}

# ---------------------------------------------------------------------------
# postgres-contract (optional)
# ---------------------------------------------------------------------------

run_postgres_contract_group() {
    printf '\n### postgres-contract (optional)\n'
    local label="postgres-contract: cargo test -p sysknife-daemon --test postgres_store --locked"

    if [[ "$run_postgres" != true ]]; then
        record SKIP "${label} (--no-postgres)"
        return
    fi

    if [[ -n "${SYSKNIFE_TEST_POSTGRES_URL:-}" ]]; then
        run_step "$label" cargo test -p sysknife-daemon --test postgres_store --locked
        return
    fi

    local runtime=""
    if have docker; then
        runtime="docker"
    elif have podman; then
        runtime="podman"
    fi

    if [[ -z "$runtime" ]]; then
        record SKIP "${label} (no SYSKNIFE_TEST_POSTGRES_URL and no docker/podman found)"
        return
    fi

    printf '\n==> postgres-contract: starting postgres:17-alpine via %s\n' "$runtime"
    "$runtime" rm -f "$POSTGRES_CONTAINER_NAME" >/dev/null 2>&1 || true

    if ! "$runtime" run -d --rm \
        --name "$POSTGRES_CONTAINER_NAME" \
        -e POSTGRES_USER=sysknife \
        -e POSTGRES_PASSWORD=sysknife \
        -e POSTGRES_DB=sysknife_test \
        -p "127.0.0.1:${POSTGRES_HOST_PORT}:5432" \
        postgres:17-alpine >/dev/null; then
        record FAIL "${label} (failed to start postgres:17-alpine via ${runtime})"
        return
    fi

    local tries=0
    until "$runtime" exec "$POSTGRES_CONTAINER_NAME" pg_isready -U sysknife -d sysknife_test >/dev/null 2>&1; do
        tries=$((tries + 1))
        if ((tries > POSTGRES_HEALTH_RETRIES)); then
            record FAIL "${label} (postgres container did not become healthy in time)"
            "$runtime" rm -f "$POSTGRES_CONTAINER_NAME" >/dev/null 2>&1 || true
            return
        fi
        sleep "$POSTGRES_HEALTH_INTERVAL_SECS"
    done

    SYSKNIFE_TEST_POSTGRES_URL="postgres://sysknife:sysknife@127.0.0.1:${POSTGRES_HOST_PORT}/sysknife_test?sslmode=disable" \
        run_step "$label" cargo test -p sysknife-daemon --test postgres_store --locked

    "$runtime" rm -f "$POSTGRES_CONTAINER_NAME" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

run_rust_group
run_frontend_group

if [[ "$mode" == "full" ]]; then
    run_hygiene_group
    run_security_group
    run_postgres_contract_group
fi

printf '\n=========================================\n'
printf ' ci-local summary (%s run)\n' "$mode"
printf '=========================================\n'
for r in "${RESULTS[@]}"; do
    printf '%s\n' "$r"
done
printf '=========================================\n'

if ((hard_failures > 0)); then
    printf 'ci-local: FAIL (%d failing check(s))\n' "$hard_failures"
    exit 1
fi

printf 'ci-local: PASS\n'
