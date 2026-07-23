# Changelog

All notable changes to SysKnife are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before `0.2.5` predate the public launch; their notes live in the
[git tag history](https://github.com/lacs-project/sysknife/tags).

## [0.2.6] — 2026-07-23

### Security

- **Per-action risk is now single-sourced on each action's `ActionSpec`.** The
  preview/approval gate and the RBAC role table derive risk from it and are
  consistency-tested for every action, so they can no longer silently diverge
  from the documented risk. Consolidating the sources surfaced and fixed five
  actions the gate had been treating as auto-approvable **Medium** despite being
  **High**: `ConfigureFirewall`, `CreateUser`, `SetDnsServers`,
  `AddPackageRepository`, and `MaskService` now correctly require High-risk,
  exact-name approval.

### Changed

- Reclassified twelve actions against common sysadmin practice — raised
  `AddAuthorizedKey`, `RemoveAuthorizedKey`, `AddPpa`, `VacuumJournal`, and
  `ConfigureWifi`; lowered `RenewCertificates`, `CreateGroup`, `AddAuditRule`,
  `CreateLvSnapshot`, `CreateLogicalVolume`, and `SetServiceResourceLimits`.
- Documentation risk levels and action names are aligned with the code, and the
  demo assets were corrected to match.
- The Code of Conduct now lists the project contact address.

### Added

- Glama MCP registry listing support (Dockerfile and ownership marker).
- Documented cargo-based MCP Registry publishing, with per-crate READMEs.

### Fixed

- Corrected the social-preview image URL.
- Repaired a broken intra-doc link and de-flaked the CI markdown link check.

## [0.2.5] — 2026-07-23 (first public release)

### Added

- **MCP server** exposing five tools — `sysknife_plan`, `sysknife_execute`,
  `sysknife_history`, `sysknife_doctor`, `sysknife_audit_verify` — for Claude
  Code, Cursor, and Codex CLI.
- **Hard, server-enforced approval interlock.** `sysknife_execute` requires a
  one-time, TTL-bounded approval receipt bound to the exact plan step. The MCP
  server cannot mint receipts; only `sysknife approve <transaction-id>` in a
  real terminal can. Missing, expired, mismatched, or replayed receipts are
  rejected by the daemon.
- **Structured history IPC** — `sysknife_history` returns typed records
  (timestamp, risk level, status) over the daemon socket instead of parsed text.
- **Daemon `cancel` verb** — cancels a queued transaction (`Queued → Canceled`);
  in-flight transactions are never interrupted.
- **PostgreSQL audit backend** with transactional schema migrations
  (advisory-locked, idempotent) and a live Postgres CI contract, alongside the
  default SQLite store.
- **Ubuntu 24.04 support** — gate + audit validated on a live VM; VM tooling and
  smoke tests for 22.04 / 24.04 / 26.04.
- **Release provenance** — SPDX SBOM and build-provenance attestations on
  release binaries (x86_64 + aarch64), with idempotent npm / crates.io /
  GitHub-release publishing.
- **`npx sysknife-setup`** onboarding wizard: downloads a checksum-verified
  binary and writes MCP config for Claude Code, Cursor, or Codex CLI.
- **Security CI**: CodeQL (Rust + TypeScript), OpenSSF Scorecard, verified-only
  secret scanning, `cargo audit`, `npm audit`, and dependency review.

### Changed

- Approval no longer uses `max_risk` as a surrogate; execution authorization is
  a per-step receipt independent of risk level.
- All third-party GitHub Actions are pinned to full commit SHAs.
- Documentation and public claims are machine-checked in CI.

### Security

- Audit chain is **Ed25519-signed**; verification needs only the public key
  (non-repudiable, third-party verifiable), with signed checkpoints guarding
  against truncation.

[0.2.6]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.6
[0.2.5]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.5
