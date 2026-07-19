# SysKnife OSS Release Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Produce a locally committed branch that is safe, testable, and ready
for a pull request against the unpublished `main` branch.

**Architecture:** Keep the brain as planner, CLI/GUI as approval presenter, and
daemon as policy/execution authority. Bind execution to a daemon-persisted,
one-time approval receipt and route all process execution through an injectable
executor. Harden VM and release workflows around fail-closed checks.

**Tech Stack:** Rust/Tokio/Rusqlite/SQLx, Tauri/React/TypeScript, Bash,
GitHub Actions, npm, cargo-nextest.

---

## Task 1: Record And Fix The Baseline Test Escape

**Files:**

- Modify: `crates/sysknife-daemon/src/executor.rs`
- Modify: `crates/sysknife-daemon/src/dispatcher.rs`
- Modify: `crates/sysknife-daemon/tests/rollback.rs`
- Modify: `crates/sysknife-daemon/tests/lifecycle_events.rs`
- Modify: `crates/sysknife-daemon/tests/concurrency_guard.rs`

1. Preserve a focused test demonstrating that an injected executor is bypassed
   by command-backed actions and launches a real process.
2. Add a streaming method to the executor abstraction, with production process
   streaming and deterministic fake implementations.
3. Route dispatcher command actions through the abstraction.
4. Run the affected daemon tests and confirm no `sudo`, `apt-get`, or
   `rpm-ostree` child process is launched.

## Task 2: Add One-Time Daemon Approval Receipts

**Files:**

- Modify: `crates/sysknife-daemon/src/transactions.rs`
- Modify: `crates/sysknife-daemon/src/store.rs`
- Modify: `crates/sysknife-daemon/src/store/postgres.rs`
- Modify: `crates/sysknife-daemon/src/dispatcher.rs`
- Modify: `crates/sysknife-daemon/tests/preview_approval.rs`
- Modify: related store and dispatcher tests

1. Add failing tests for execution without approval, wrong receipt, changed
   parameters, duplicate approval, and receipt reuse.
2. Add store operations that approve one queued transaction and atomically
   claim only a matching approved transaction.
3. Add daemon `approve` request/response types. Generate a random receipt,
   persist only its digest, and return the receipt once.
4. Replace request-hash execution authorization with transaction ID plus receipt
   verification while retaining canonical request-hash binding.
5. Pass SQLite, Postgres store-contract, dispatcher, and concurrency tests.

## Task 3: Update CLI, GUI, And MCP Approval Flows

**Files:**

- Modify: `apps/sysknife-cli/src/client.rs`
- Modify: `apps/sysknife-cli/src/cli.rs`
- Modify: `apps/sysknife-cli/src/main.rs`
- Modify: `apps/sysknife-cli/src/runner.rs`
- Modify: `apps/sysknife-cli/src/mcp_server.rs`
- Modify: `apps/sysknife-shell/src-tauri/src/commands.rs`
- Modify: frontend/CLI tests as required

1. Add failing client tests for preview transaction IDs, approve receipts, and
   execute payloads that omit or forge receipts.
2. Add interactive `sysknife approve <transaction-id>` and reject its use from
   a non-interactive stdin.
3. Have CLI/GUI confirmation flows request and immediately consume a receipt.
4. Make MCP plan output include persisted transaction IDs and make MCP execute
   require a receipt per exact step. Remove `max_risk` as an approval surrogate.
5. Add the regression test that direct `sysknife_execute` cannot mutate without
   an independently issued receipt.

## Task 4: Harden Ubuntu VM End-To-End Bootstrap

**Files:**

- Modify: `tests/e2e/ubuntu-vm.sh`
- Modify: `docs/contributing/ubuntu-vm-testing.md`
- Add/Modify: shell tests under `tests/e2e/`

1. Add failing shell assertions for fail-fast cloud-init, network readiness,
   bounded apt retries, failure markers, and readiness checks.
2. Generate a dedicated bootstrap script from cloud-init and execute it with
   strict shell options.
3. Fail `install` on cloud-init failure, timeout, missing success marker, or
   missing required packages; print cloud-init diagnostics.
4. Run shell syntax, shellcheck where available, and generated-config tests.

## Task 5: Harden Dependencies And Release Provenance

**Files:**

- Modify: `Cargo.lock`
- Modify: `apps/sysknife-shell/package.json`
- Modify: `apps/sysknife-shell/package-lock.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Add: release validation/SBOM helper scripts as needed

1. Run `cargo audit` and `npm audit`; update vulnerable dependencies without
   unrelated major migrations.
2. Add frontend audit and dependency-review CI jobs.
3. Add tag/package version consistency validation.
4. Generate SPDX SBOM release artifacts and attest release binaries with
   `actions/attest`; grant only required workflow permissions.
5. Make missing publication credentials a failed release preflight, not a
   successful skipped publish.

## Task 6: Align OSS Documentation And Packaging

**Files:**

- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `ROADMAP.md`
- Modify: `docs/architecture.md`
- Modify: `docs/mcp.md`
- Modify: `docs/release.md`
- Modify: `docs/cli.md`
- Modify: `packages/setup/README.md`
- Modify: package metadata and fixtures where stale

1. Add tests/checks for package-version and package-name consistency.
2. Document the receipt flow and same-user process boundary accurately.
3. Remove stale publish-pending, scoped-package, cancellation-complete, and
   version claims.
4. Document checksums, SBOMs, provenance verification, and release preflight.
5. Run repository completeness, markdown lint, and link checks.

## Task 7: Verify, Review, And Finalize Locally

1. Run `cargo fmt --all --check`, clippy, docs, and
   `cargo nextest run --workspace --locked`.
2. Run frontend typecheck, tests, build, and `npm audit`.
3. Run shell checks, repository completeness, package smoke tests, and
   `cargo audit`.
4. Commit cohesive changes only after the mandated nextest gate passes.
5. Run Claude Code `/pr-review` with Terra agents over `main...HEAD` plus any
   remaining working-tree diff.
6. Validate each finding using the receiving-code-review workflow, implement
   every technically valid finding with tests, and rerun all verification.
7. Leave the branch local and report the commit range and PR-ready summary; do
   not push or create a remote pull request.
