# Changelog

All notable changes to SysKnife are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before `0.2.5` predate the public launch; their notes live in the
[git tag history](https://github.com/lacs-project/sysknife/tags).

## [0.2.10] — 2026-07-24

### Security

- Unix caller-role resolution now pins the connecting peer with a pidfd
  (`SO_PEERPIDFD`, Linux 6.5+ / Ubuntu 24.04+) and confirms it was not reaped
  before trusting the supplementary group set read from `/proc/{pid}/status`,
  closing a PID-reuse race on that read. The uid/gid/pid from `SO_PEERCRED` were
  already race-free; on older kernels (Ubuntu 22.04) the read stays best-effort,
  exactly as before.
- Removed a stale, unused `apps/sysknife-shell/pnpm-lock.yaml` that still pinned
  `postcss` 8.5.10 and kept a high-severity advisory open. The GUI is built with
  npm (`package-lock.json`, already on `postcss` 8.5.20); nothing referenced the
  pnpm lockfile.

### Changed

- **Planner risk is now type-enforced as authoritative at the approval gate.** A
  raw `Plan` (LLM output) exposes only `proposed_risk_level()`; the CLI converts
  it to an `AuthorizedPlan` — substituting the daemon's `ActionSpec` risk, the
  single source of truth — before any gate, and only an `AuthorizedPlan`'s steps
  expose the `risk_level()` the gate reads. This makes it structurally impossible
  to auto-approve against the model's proposed risk, reinforcing the v0.2.7
  runtime fix at the type level. No behavior change.
- Supply-chain hardening: the `Dockerfile` base images are pinned by
  manifest-list digest (not just tag), and the GitHub Pages docs workflow now
  verifies the sha256 of the mdBook and mdbook-admonish release tarballs before
  extracting them. Dependabot continues to bump both.

## [0.2.9] — 2026-07-23

### Security

- Destructive user/group actions (`DeleteUser`, `LockUserAccount`,
  `DeleteGroup`) now reject critical accounts and groups (`root`, `sudo`,
  `wheel`, core system accounts, uid/gid 0) via a hard denylist, independent of
  the approval gate.
- The GRUB kernel-argument allowlist now blocks Ubuntu LSM / mitigation-disable
  arguments (`apparmor=0`, `mitigations=off`, `lockdown=`, `pti=off`, `nosmap`,
  `nosmep`) in addition to the SELinux ones.
- The `snap install` and `fail2ban` action builders now validate their
  arguments in the constructor (defense in depth), not only at the executor
  boundary.
- Five High-risk actions (`ConfigureFirewall`, `SetDnsServers`, `ConfigureWifi`,
  `MaskService`, `CreateUser`) now render accurate lockout / interception /
  privilege warnings and require exact-name approval, instead of a generic
  "service interruption" preview.
- A `config.toml` that is present but unparseable now fails loudly instead of
  silently falling back to defaults (which would have dropped `[storage]` /
  `[policy]` — a silent security downgrade).

### Fixed

- **`npx sysknife-setup`'s approval gate is no longer broken by default.** The
  wizard-installed user daemon now binds the same socket the CLI resolves with
  no environment set (`%t` → `$XDG_RUNTIME_DIR/sysknife/daemon.sock`), so
  `sysknife approve` works in a fresh terminal without exporting anything.
- The default LLM rate limiter no longer silently disables itself on a fresh
  install (its state directory was never created, so writes failed open).
- Preview `rollback_available` is now honest: six Debian-family actions
  (`AddPpa`, `RemovePpa`, `NetplanSet`, `GrubSetKargs`, `ProAttach`,
  `ProDetach`) no longer advertise an automatic rollback that never ran; a
  workspace-wide invariant test enforces `rollback_available` ⇔ a real rollback
  command exists.
- Ubuntu derivatives (Linux Mint, Pop!\_OS, …) are now recognized via `ID_LIKE`,
  so `apt` / `snap` / `ufw` actions route correctly instead of being rejected
  as an unknown distribution.
- SQLite transaction status updates are now atomic (compare-and-set), matching
  the PostgreSQL backend.
- UFW application profiles containing spaces (`Nginx Full`, `Apache Full`) are
  now accepted.
- The MCP server now applies the same distro-routing guard as the CLI, and LLM
  provider errors are no longer misclassified (e.g. "generate" → "rate limit").

### Added

- `scripts/ci-local.sh` and a `.githooks/pre-push` hook that mirror the CI jobs
  locally, so failures are caught before pushing (saving GitHub Actions
  minutes). Documented in the developer guide, alongside `act` for full
  Docker-based workflow replay.

### Changed

- Documentation drift corrections: socket / database defaults (`cli.md`,
  `configuration.md`), the vsock token walkthrough, the Ubuntu action reference
  (netplan mechanism and added actions), the Observer action count, ADR-0002's
  provider count, and others. Hardened the invisible-Unicode sanitizer and the
  provider error-message redactor.

## [0.2.8] — 2026-07-23

### Security

- Bumped the transitive `postcss` dependency of the `sysknife-shell` GUI to
  `>= 8.5.12` via an npm `overrides` pin, resolving a high-severity advisory
  (arbitrary file read / information disclosure via an attacker-controlled
  `sourceMappingURL` in CSS comments).

### Fixed

- The CLI (and the MCP server) now resolve the daemon socket via
  `sysknife-core`'s `default_listen_uri()` — the same resolver the daemon and
  the Tauri GUI already use — instead of a hardcoded production path. Previously
  `sysknife doctor` and every CLI command failed to reach a dev/non-systemd
  daemon until `SYSKNIFE_SOCKET` was set by hand. `$SYSKNIFE_SOCKET` still takes
  precedence as an explicit override. Thanks to Raúl Cárdenas for the report.

### Changed

- Dropped backwards-compatibility cruft (the project has never been deployed at
  scale, so matched versions are an invariant): the dead `fail2ban`
  `InvalidIpAddress` type alias, the `--codex-only` setup-wizard flag alias, the
  `install-key` VM-script alias, the `ubuntu-vm` "legacy noble" migration shim,
  and a phantom `/tmp/sysknife-daemon.sock` path in the setup wizard.
- Documented the `SYSKNIFE_SOCKET` override and corrected stale daemon
  socket-default text (`$XDG_RUNTIME_DIR/sysknife/daemon.sock`, not
  `/tmp/sysknife-daemon.sock`) in the developer and architecture docs.
- Internal simplification of the CLI risk-gate/socket module and the daemon
  preview gate (de-duplication and named constants); no behavior change.

## [0.2.7] — 2026-07-23

### Security

- The CLI's `--yes` / `--max-risk` auto-approval now derives each step's risk
  from the daemon's `ActionSpec` (the single source of truth) instead of the
  planner's proposed risk, so a plan that under-rates an action can no longer let
  it auto-approve. A fail-closed guard also aborts before execution if the
  running daemon rates a step higher than the CLI approved it — closing a
  CLI/daemon version-skew window.

### Changed

- Preview `reboot_required` / `rollback_available` are now derived from the
  `ActionSpec`, fixing stale display for `RollbackDeployment`, `AddPpa`,
  `RemovePpa`, and `GrubSetKargs`.
- Twenty-four apt / PPA / snap / GRUB / AppArmor / Fail2ban / resolvectl /
  Flatpak actions that previously previewed as "unclassified" now show accurate
  side effects and warnings; a completeness test prevents the drift from
  recurring.

### Added

- Dependabot now tracks Docker base images and applies a supply-chain cooldown
  to version updates; repository vulnerability alerts and automated security
  updates are enabled.

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
  `AddAuthorizedKey`, `RemoveAuthorizedKey`, `AddPpa`, `VacuumJournal`,
  `ConfigureWifi`, and `AptAutoremove`; lowered `RenewCertificates`,
  `CreateGroup`, `AddAuditRule`, `CreateLvSnapshot`, `CreateLogicalVolume`, and
  `SetServiceResourceLimits`.
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

[0.2.10]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.10
[0.2.9]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.9
[0.2.8]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.8
[0.2.7]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.7
[0.2.6]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.6
[0.2.5]: https://github.com/lacs-project/sysknife/releases/tag/v0.2.5
