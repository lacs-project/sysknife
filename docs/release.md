# Release process

SysKnife releases are intentionally tag-driven and one way. npm and crates.io
versions cannot be replaced after publication, so a tag is pushed only after
the [release-readiness checklist](release-readiness.md) is complete.

## Version numbering

SysKnife is in the `0.y.z` series. Cargo and npm both treat the leftmost non-zero
component as the compatibility unit, so while the leading zero stands the middle
digit carries breaking changes and the last one carries everything else:

| Change | Bump | Example |
|---|---|---|
| Removing or renaming a public item, changing a signature, changing behaviour a caller relied on | `0.y` | v0.9.0 removed `PRODUCTION_LISTEN_URI` and three dead re-exports |
| Compatible additions, fixes, dependency bumps | `0.y.z` | a new action, a bug fix, a security patch |

A consumer writing `sysknife-core = "0.8"` accepts 0.8.1 and refuses 0.9.0. That
is the whole reason a removal has to move the middle digit: shipping it as a patch
hands the breakage to everyone pinned to the series, and
[the Cargo book](https://doc.rust-lang.org/cargo/reference/semver.html) classifies
removing a public item, a `pub use` re-export included, as a major change.

Behaviour counts, not only types. v0.9.0 also made `sysknife-setup` refuse a
malformed `.mcp.json` that earlier versions overwrote, so a run that used to
succeed now exits 1. No signature changed and it is still a compatibility break.

### After 1.0.0

Once the public API is declared stable the digits take their usual
[SemVer](https://semver.org/) meaning: MAJOR for breaking changes, MINOR for
compatible features, PATCH for fixes.

1.0.0 is not a maturity badge and it is not scheduled. Three things have to be
true first, so the switch is a decision rather than a mood:

1. The daemon protocol is settled. The wire enums and `ChainRow` still gain
   fields, and `chain_version` exists because the encoding is expected to move.
2. The action catalogue naming is settled. [#237](https://github.com/lacs-project/sysknife/issues/237)
   splits the Ubuntu-only actions out of `DEBIAN_ONLY_ACTIONS` and
   [#239](https://github.com/lacs-project/sysknife/issues/239) adds nftables
   vocabulary. Both rename or re-scope public items.
3. Something outside this repository depends on the library crates. Today the only
   reverse dependencies of `sysknife-core` on crates.io are `sysknife-brain`,
   `sysknife-daemon` and `sysknife-cli`, all pinned to the same version, so there
   is no outside consumer to stabilise for yet.

Until then, expect a minor bump whenever a release removes or renames something.

## What the workflow publishes

Pushing a tag matching `vMAJOR.MINOR.PATCH` on `main` starts
`.github/workflows/release.yml`. It:

1. Verifies the tag against every Cargo and npm package version.
2. Builds `sysknife` and `sysknife-daemon` on native Linux x86_64 and aarch64
   runners.
3. Generates SPDX SBOMs, checksums, and GitHub artifact attestations.
4. Publishes `sysknife-setup` to npm through trusted publishing (OIDC).
5. Publishes the public Rust crates to crates.io in dependency order.
6. Creates the GitHub Release and uploads the binaries, SBOMs, and checksums.

Publication is never silently skipped. The release is created only after both
registries accept the packages.

## One-time repository setup

Before the first tag:

- Configure an npm trusted publisher for package `sysknife-setup`, repository
  `lacs-project/sysknife`, workflow `release.yml`, and the exact GitHub owner.
  The npm job uses Node 24 and `id-token: write`; no long-lived `NPM_TOKEN` is
  used. See [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/).
- Add `CARGO_REGISTRY_TOKEN` as a GitHub Actions secret. Restrict the token to
  only the SysKnife crates where crates.io token scopes allow it.
- Protect `main` with a ruleset requiring the CI, E2E, and Postgres contract
  checks, at least one approval, resolved review conversations, and no force
  pushes. See [GitHub rulesets](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).
- Enable private vulnerability reporting and immutable releases in repository
  settings before announcing the project.
- Confirm the GitHub Actions runners and action versions used by the release
  workflow are available to the repository.

## Rehearse without publishing

Run the manual `release-rehearsal` workflow on the exact commit intended for
release. It packages every public crate, packs the npm installer, builds native
binaries, smoke-tests the CLI, and emits checksums without contacting a
registry or creating a release.

The same check is available locally:

```bash
scripts/release_rehearsal.sh --check
scripts/release_rehearsal.sh --full --output dist/rehearsal
```

`release_rehearsal.sh` deliberately refuses `--publish`.

## Cut a release

Use a clean, reviewed `main` checkout. Replace `v0.2.5` with the intended
version.

```bash
cargo nextest run --workspace --locked
bash scripts/check_release_versions.sh v0.2.5
scripts/release_rehearsal.sh --full --output dist/rehearsal

git tag -s v0.2.5 -m "SysKnife v0.2.5"
git push origin v0.2.5
```

The tag pattern does not accept prerelease suffixes. Do not move or reuse a
published tag. If publication partly fails, diagnose and rerun the workflow on
the same commit; do not publish a different tree under the same version.

Tags are signed. SSH signing is configured per repository so it cannot leak into
unrelated work:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/git-signing -C "sysknife git signing"
gh ssh-key add ~/.ssh/git-signing.pub --type signing --title "git signing (sysknife)"
git config gpg.format ssh
git config user.signingkey ~/.ssh/git-signing.pub
git config tag.gpgsign true
```

Verify before pushing: `git tag -v v0.2.15` must report a good signature. An
unverifiable tag on a published release is worse than an unsigned one.

## Manual steps after publication

One directory listing cannot be updated from CI, so the release workflow files a
checklist issue titled `Post-release manual steps for <tag>` and assigns it to
whoever pushed the tag. It carries the exact commands and the real checksum read
from that release's `sha256sums-linux-x86_64.txt`.

- **Glama build spec.** The admin form is browser-only. Only the build steps
  change per release, to the new binary URL and checksum. Leave the
  `mcp-proxy --` prefix in the CMD arguments alone; that is how Glama exposes a
  stdio server over HTTP.

This does not block anyone installing the release. It affects discovery only, so
it is not a release blocker, which is exactly why it needs a ticket rather than a
line in a log nobody reads.

The **official MCP Registry** publish used to sit on that list and no longer
does. The `publish-registry` job runs after `publish-crates` and authenticates
with GitHub Actions OIDC. That ordering is required, because the registry
validator reads the *published* crate's rendered README for the `mcp-name:`
marker, and the OIDC identity is required for a different reason: see
[the registry notes](mcp-registry.md#authentication-namespace-comes-from-the-identity).

## Registry details

### npm

`packages/setup/package.json` runs its `prepublishOnly` smoke test before
upload. For a local package inspection:

```bash
cd packages/setup
npm pack --dry-run
```

Trusted publishing requires the npm package's publisher configuration to
match the GitHub repository and workflow exactly. Keep `id-token: write`
scoped to the npm job.

### crates.io

The public crates are published in dependency order:

```text
sysknife-proto
sysknife-core
sysknife-types
sysknife-brain
sysknife-daemon
sysknife-cli
```

The private `sysknife-daemon-test` and desktop shell crates are not published.

## Verify the published release

After the workflow succeeds:

```bash
npx sysknife-setup --help

gh attestation verify sysknife-vX.Y.Z-linux-x86_64 \
  --repo lacs-project/sysknife
sha256sum --check sha256sums-linux-x86_64.txt
```

Also perform a clean install, `sysknife doctor`, one preview/approve/execute
cycle, and uninstall on the supported OS image before announcing the release.
Keep the release private or draft until these checks pass.
