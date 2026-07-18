# SysKnife OSS Release Hardening Design

## Objective

Make the unpublished `main` branch safe and reproducible enough for a public
OSS release without changing SysKnife's core planner/shell/daemon boundaries.
The release must have a mechanically enforced human approval boundary, a clean
test suite, deterministic VM bootstrap behavior, dependency gates, verifiable
binary provenance, and documentation that matches what ships.

## Security Boundary

The current daemon treats the preview's public request hash as an approval
credential. An MCP client can therefore preview a mutation and immediately
echo that hash into `execute`, bypassing the claimed human approval step.

Replace that contract with a one-time opaque receipt:

1. Preview persists the canonical request and returns a transaction ID.
2. An explicit `sysknife approve <transaction-id>` CLI command prompts on an
   interactive terminal and asks the daemon to approve that exact transaction.
3. The daemon creates a random receipt, persists only its SHA-256 digest in the
   existing `approval_id` field, and returns the raw receipt once.
4. Execute supplies the transaction ID and raw receipt. The daemon verifies the
   receipt digest, verifies that action and parameters still hash to the stored
   request, and atomically consumes the approved queued transaction.
5. MCP has no approval tool. `sysknife_plan` creates the persisted previews and
   returns transaction IDs; `sysknife_execute` requires the independently
   issued receipt for every step.

This protects the SysKnife MCP tool boundary. It does not claim to isolate the
daemon from a hostile process already running as the same local OS user and
able to speak the private IPC protocol directly.

Normal CLI and GUI flows continue to capture their own confirmation, then call
the same daemon approval endpoint before execution. High-risk automation remains
interactive-only.

## Execution Testability

Command-backed actions currently bypass the injected `ActionExecutor` and call
`sudo` directly. Integration tests that appear mocked therefore launch real
package-manager commands and hang. Route both captured and streaming command
execution through one injectable execution boundary. Production keeps streamed
progress; tests receive a deterministic fake. No integration test may invoke a
host package manager or depend on passwordless sudo.

## Ubuntu VM Bootstrap

Cloud-init must fail closed:

- Wait for DNS and archive endpoints before package installation.
- Retry transient apt metadata and package download failures with bounded
  backoff.
- Run provisioning through a fail-fast script that records either a success
  marker or a diagnostic failure marker.
- Treat timeout, failed cloud-init status, missing packages, or a failure marker
  as an installation error rather than a warning.
- Add shell-level tests for generated cloud-init and readiness behavior.

## Supply Chain And Release

- Keep `cargo audit` blocking on vulnerabilities and add `npm audit` for the
  Tauri frontend.
- Add GitHub dependency review for pull requests.
- Generate SPDX SBOMs for release assets and GitHub artifact attestations for
  the binaries. Keep SHA-256 files for offline verification.
- Validate that a release tag matches every package version before publishing.
- Do not silently report a successful release when npm or crates.io publishing
  credentials are absent.

## Documentation Contract

Update README, security architecture, MCP instructions, release instructions,
package metadata, roadmap, and cancellation wording to describe only implemented
behavior. Document receipt handling, the same-user threat boundary, current
package names and versions, provenance verification, and the GUI cancellation
limitation until daemon-side cancellation is real.

## Verification

The branch is release-ready only after formatting, linting, Rust and frontend
tests, dependency audits, shell checks, repository completeness checks, and
package smoke tests pass. A final independent Claude Code `/pr-review` using
Terra agents must review the full branch diff; every valid finding is fixed and
the complete verification set is rerun.
