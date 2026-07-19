# SysKnife OSS Launch Readiness Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the local release-hardening branch ready for an evidence-gated
public OSS beta and a pull request against `main`.

**Architecture:** Preserve the planner/approval/daemon boundaries. Add an
explicit support-tier documentation contract, transactional Postgres schema
migrations with a live CI contract, deterministic release rehearsal, and media
that demonstrates terminal-issued one-time receipts.

**Tech Stack:** Rust/Tokio/SQLx/PostgreSQL/Rusqlite, Bash, GitHub Actions,
npm, mdBook, VHS.

---

## Task 1: Make Public Claims Machine-Checkable

**Files:**

- Add: `scripts/check_public_claims.sh`
- Add: `tests/release/public-claims.test.sh`
- Modify: `.github/workflows/ci.yml`

1. Write a failing shell test that detects the stale `1,227` count, publish-
   pending wording, unsupported Fedora Workstation claims, and MCP chat-only
   approval language.
2. Run the test and confirm it fails against the current docs.
3. Add a focused checker that rejects those known-invalid claims and verifies
   that receipt-based MCP wording remains present.
4. Add the checker to CI and rerun its test.

## Task 2: Correct Support Semantics And Documentation

**Files:**

- Modify: `crates/sysknife-core/src/distro.rs`
- Modify: `README.md`
- Modify: `docs/introduction.md`
- Modify: `docs/quickstart.md`
- Modify: `docs/distro-support.md`
- Modify: `ROADMAP.md`

1. Add a failing Rust test proving plain Fedora is not reported as supported
   before the `dnf` action family exists, plus Fedora 44 Atomic fixture tests.
2. Change only the support predicate and fixtures needed to make those tests
   pass; retain Fedora-family detection for planning.
3. Replace binary supported/unsupported marketing with validated,
   smoke-tested, and experimental tiers.
4. Update the test count to 1,228, remove stale npm language, and make rollback
   scope and Ubuntu/Fedora evidence consistent on every entry page.
5. Run distro tests and the public-claims checker.

## Task 3: Add Transactional Postgres Migrations

**Files:**

- Modify: `crates/sysknife-daemon/src/store/postgres.rs`
- Add: `crates/sysknife-daemon/tests/postgres_store.rs`

1. Write a service-backed test that constructs a legacy schema without a
   migrations table, connects `PostgresStore`, and expects migration version 1
   to be recorded without losing the legacy row.
2. Run it against a disposable local PostgreSQL container and confirm failure.
3. Implement a migration runner using one transaction, a database advisory
   lock, `schema_migrations`, and an immutable ordered migration list.
4. Add store-contract assertions for record, preview, approval, atomic claim,
   receipt replay rejection, history, and audit-chain verification.
5. Run the service-backed test twice to prove idempotence.

## Task 4: Enforce Postgres And Shell Contracts In CI

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/e2e.yml`

1. Add a PostgreSQL service job that runs only the live Postgres integration
   test with a dedicated `SYSKNIFE_TEST_POSTGRES_URL`.
2. Change E2E workflow triggers so `scripts-lint` runs on pull requests and
   pushes to `main`, while `container-smoke` remains manual-only.
3. Replace mutable `action-shellcheck@master` use with a locally installed
   ShellCheck invocation over all maintained scripts.
4. Validate workflow YAML and run the same shell commands locally.

## Task 5: Build A Non-Publishing Release Rehearsal

**Files:**

- Add: `scripts/release_rehearsal.sh`
- Add: `tests/release/release-rehearsal.test.sh`
- Add: `.github/workflows/release-rehearsal.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `docs/release.md`

1. Write a failing test for rehearsal modes, artifact naming, and refusal to
   publish.
2. Implement a script that checks versions, runs Cargo package dry-runs, packs
   and inspects npm contents, builds release binaries, exercises `--help`, and
   emits SHA-256 files into a disposable output directory.
3. Add a manual x86_64/ARM64 rehearsal workflow that uploads short-lived
   artifacts but never publishes or creates a release.
4. Migrate npm publication to Node 24 plus OIDC trusted publishing and remove
   the `NPM_TOKEN` requirement; retain the crates.io token preflight.
5. Document trusted-publisher setup, immutable releases, and rehearsal usage.

## Task 6: Document Production Audit Operations

**Files:**

- Modify: `docs/storage-cloud.md`
- Modify: `docs/configuration.md`
- Modify: `SECURITY.md`
- Add: `docs/release-readiness.md`
- Modify: `docs/SUMMARY.md`

1. Document that action audit records use SQLite/Postgres, daemon diagnostics
   use journald, and RFC 5424 UDP forwarding is best-effort rather than the
   durable source of truth.
2. Add a production checklist for TLS verification, restricted DB roles,
   retention, managed backups/PITR, restore drills, independent checkpoints,
   and SIEM collection.
3. Add a release gate checklist for current Silverblue 44 and Ubuntu VM
   evidence, clean-host x86_64/ARM64 installs, registry configuration,
   repository rulesets, immutable releases, and independent security review.
4. Mark gates as external/manual rather than claiming they passed.

## Task 7: Replace The Stale MCP Animation

**Files:**

- Modify: `assets/demo/mcp-flow-mock.sh`
- Modify: `assets/demo/mcp-flow.tape`
- Modify: `assets/demo/mcp-flow.gif`
- Modify: `assets/demo/README.md`

1. Add receipt-flow assertions to the public-claims test against the demo
   source.
2. Rewrite the deterministic replay to show transaction IDs, terminal
   approval, one-time receipts, successful execution, and replay rejection.
3. Regenerate the GIF with VHS and inspect sampled frames for legibility and
   protocol correctness.
4. Keep the standalone CLI GIF unless inspection finds behavior that no longer
   matches default CLI semantics.

## Task 8: Complete Verification And Claude `/pr-review`

1. Run Rust formatting, clippy, docs, `cargo nextest`, `cargo audit`, and the
   live PostgreSQL contract.
2. Run frontend typecheck, tests, build, and production dependency audit.
3. Run all shell/repository/public-claim checks and the release rehearsal.
4. Inspect `git diff --check`, generated media, package contents, and the full
   `main...HEAD` diff.
5. Invoke Claude Code `/pr-review` over the complete branch diff, using its
   Terra agents when available.
6. Evaluate every finding with the receiving-code-review workflow; implement
   each technically valid item one at a time with focused verification.
7. Rerun the complete verification matrix and leave the branch local, ready
   for the user-authorized merge decision.
