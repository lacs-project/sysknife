# Release process

SysKnife releases are intentionally tag-driven and one way. npm and crates.io
versions cannot be replaced after publication, so a tag is pushed only after
the [release-readiness checklist](release-readiness.md) is complete.

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
