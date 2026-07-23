# OSS release readiness

This checklist is the launch gate for a public SysKnife release. A green unit
test suite is necessary but not sufficient: privileged system software needs
real-host evidence, recovery evidence, repository controls, and an independent
security review.

## Automated gates

Run these on the exact candidate commit and retain the CI links:

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-features --locked -- -D warnings`
- [ ] `cargo nextest run --workspace --locked`
- [ ] frontend typecheck, 72 tests, production build, and production npm audit
- [ ] live PostgreSQL migration and store contract
- [ ] ShellCheck, YAML lint, repository completeness, release versions, public
      claims, and bootstrap contracts
- [ ] `scripts/release_rehearsal.sh --full` on native x86_64 and aarch64 runners
- [ ] dependency review, RustSec audit, documentation links, and docs build

## Host validation

- [ ] Ubuntu 24.04 LTS full story suite passes on a clean VM for this commit.
- [ ] Ubuntu 22.04 and 26.04 bootstrap, install, daemon, doctor, and uninstall
      smoke tests pass.
- [ ] Fedora Silverblue 44 full atomic VM suite passes before the README badge
      is promoted from **current validation required**.
- [ ] Clean install, preview, terminal approval, execution, audit verification,
      upgrade, rollback/uninstall, and reinstall are exercised with no
      undocumented manual repair.
- [ ] x86_64 and aarch64 release artifacts run on clean supported images.
- [ ] Failure cases are exercised: expired/replayed approval, daemon restart,
      unavailable LLM provider, unavailable audit database, and interrupted
      package operation.

Record image identifiers, architecture, kernel, model/provider, commit SHA,
test command, and result. Do not summarize a historical VM run as evidence for
a new release commit.

## Data and operations

- [ ] SQLite backup plus audit-key restore is tested on an isolated host.
- [ ] PostgreSQL migration and a backup/PITR restore drill both pass against
      the production provider.
- [ ] Audit retention, backup encryption, recovery objectives, restore owner,
      and deletion authorization are documented for operators.
- [ ] Monitoring covers daemon startup, database failures/capacity, dropped
      forwarding events, backup age, restore-test age, and audit-chain failure.
- [ ] Secrets and file permissions are inspected on a clean installation; logs
      and diagnostics do not expose provider keys, database URLs, or receipts.

## Repository and supply chain

- [ ] The public namespace, npm package, crate names, and project links are
      owned and resolve to the intended maintainers.
- [ ] `main` ruleset requires CI, E2E script lint, Postgres contract, approval,
      resolved conversations, and blocks force pushes.
- [ ] npm trusted publishing matches `lacs-project/sysknife` and `release.yml`;
      no long-lived npm token is present.
- [ ] The scoped crates.io token is configured and the non-publishing rehearsal
      packages every public crate.
- [ ] Private vulnerability reporting, immutable releases, signed tags,
      artifact attestations, SBOMs, checksums, and least-privilege workflow
      permissions are enabled and verified.
- [ ] `SECURITY.md`, support policy, contribution guide, code of conduct,
      license, issue forms, and release process are visible from the README.

## Security and launch decision

- [ ] An independent reviewer examines the full `main...candidate` diff with
      emphasis on authorization, receipt binding/replay, command construction,
      audit integrity, migrations, installer privilege boundaries, and CI
      publication permissions.
- [ ] Every actionable review finding is fixed and the full suite is rerun.
- [ ] Known limitations are accurate, externally understandable, and linked to
      issues where maintainers intend to fix them.
- [ ] The demo animation and all public claims match actual behavior.
- [ ] Maintainers explicitly record **go** only after every launch-blocking item
      above is checked. Unchecked items remain blockers, not follow-up polish.

## First 72 hours

- [ ] Monitor install failures, security reports, dependency alerts, audit
      corruption reports, and support questions with a named on-call owner.
- [ ] Be prepared to deprecate installation instructions or publish a fixed new
      version; never replace registry artifacts or move a published tag.
- [ ] Convert repeated setup failures into tested installer diagnostics and
      update the support matrix only from recorded evidence.
