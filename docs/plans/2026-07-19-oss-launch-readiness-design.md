# SysKnife OSS Launch Readiness Design

## Objective

Turn the hardened `v0.2.5` branch into an evidence-gated public beta without
claiming validation that has not happened. The repository must explain its
actual operating-system tiers, demonstrate the one-time receipt boundary, test
the production audit backend against a real database, and provide a repeatable
release rehearsal before any public tag is created.

## Chosen Approach

Use an evidence-gated public beta rather than a documentation-only launch or a
claim of full production certification.

- A documentation-only release would leave the Postgres backend and E2E shell
  harness without enforceable integration gates.
- Full certification is not locally achievable because it requires current
  live-VM runs and independent review of the privileged daemon.
- The public-beta approach automates every deterministic check and records
  live-VM, repository-setting, registry, and external-security evidence as
  explicit release gates.

## Public Support Contract

Documentation will distinguish three states:

1. **Validated:** the complete documented E2E suite passed on a real VM.
2. **Smoke-tested:** bootstrap and basic runtime checks passed, but full action
   parity was not exercised.
3. **Experimental or planned:** code may recognize the platform, but the
   project does not promise production support.

Ubuntu 24.04 is validated. Ubuntu 22.04 and 26.04 are smoke-tested. Fedora
Atomic remains a supported target, but the launch checklist must record a
current Fedora 44 Silverblue run before the release can claim current-live-VM
validation. Plain Fedora Workstation and Server remain experimental until the
`dnf` action family exists; the runtime support predicate must not report them
as fully supported.

## Database Lifecycle

SQLite remains the local default. PostgreSQL remains the recommended
production audit backend, but that claim will be backed by:

- numbered, transactional migrations recorded in a schema-migrations table;
- a database-scoped advisory lock so concurrent daemon startups cannot race;
- adoption of existing pre-migration installations without data loss;
- a real PostgreSQL service-backed store contract in CI;
- operator documentation for TLS, least privilege, retention, backup, PITR,
  restore drills, external checkpoints, and SIEM forwarding.

The first migration adopts the current schema. Future changes append migration
steps instead of modifying the initial schema in place.

## CI And Release Evidence

The fast shell harness gate will run on pull requests and pushes to `main`;
probabilistic LLM/container smoke tests remain manual. A release-rehearsal
script and workflow will build packages, run package dry-runs, inspect npm
contents, exercise binary help output, and produce checksums without publishing.

npm publishing will use trusted publishing/OIDC rather than a long-lived token.
crates.io remains token-based, with the external registry configuration listed
as a release prerequisite. GitHub rulesets, required checks, immutable releases,
registry trusted-publisher setup, and current live-VM evidence are repository
or service settings and therefore remain explicit operator checklist items.

## Media Contract

The deterministic VHS MCP demo will show the actual flow:

1. `sysknife_plan` returns transaction IDs.
2. The agent cannot execute from chat approval alone.
3. The user runs `sysknife approve <transaction-id>` in a terminal.
4. The returned one-time receipt is supplied to `sysknife_execute`.
5. Execution succeeds and receipt reuse is rejected.

The source scripts are the reviewable contract. Generated GIFs must be rebuilt
from those sources and checked into the repository.

## Verification And Review

Completion requires the complete Rust and frontend suites, formatting, clippy,
docs, dependency audits, shell checks, Postgres integration tests, package
rehearsal, and generated-media inspection. Before merge, Claude Code's
`/pr-review` workflow will review `main...HEAD`; each actionable finding will be
validated, fixed with a regression test where applicable, and the complete
verification matrix will run again.
