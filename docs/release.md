# Release Process

This document describes how SysKnife releases are cut and how the
`sysknife-setup` npm package is published.

## Overview

A release is triggered by pushing a version tag of the form `vMAJOR.MINOR.PATCH`
(e.g. `v0.2.0`) to the `main` branch.  The GitHub Actions release workflow
(`.github/workflows/release.yml`) then:

1. Verifies that the tag and every package manifest use the same version.
2. Builds `sysknife` and `sysknife-daemon` for Linux x86\_64 and aarch64.
3. Generates SPDX SBOMs and GitHub/Sigstore provenance attestations.
4. Publishes `sysknife-setup` to npm and the public Rust crates to crates.io.
5. Creates a GitHub Release with binaries, SHA-256 checksums, and SBOMs.

The release fails during preflight if either registry credential is missing;
publication is never silently skipped.

## Cutting a Release

```bash
# Ensure main is clean and all tests pass.
cargo nextest run --workspace --locked
bash scripts/check_release_versions.sh v0.2.5

# Tag and push — the workflow fires automatically.
git tag v0.2.5
git push origin v0.2.5
```

The tag must match `v[0-9]+.[0-9]+.[0-9]+` exactly.  Pre-release suffixes
(e.g. `v0.2.0-rc1`) do not trigger the workflow.

## npm Publishing

### Required Secret

Set a repository secret named `NPM_TOKEN` in
**Settings → Secrets and Variables → Actions**.

The token must have permission to publish the unscoped `sysknife-setup`
package. If the secret is absent, release preflight fails.

### How to Create the Token

1. Log in to <https://www.npmjs.com> as the `lacs-project` org admin.
2. Go to **Account → Access Tokens → Generate New Token → Granular Access Token**.
3. Set **Packages and scopes** → `sysknife-setup` → **Read and write**.
4. Copy the token and add it as the `NPM_TOKEN` secret in GitHub.

### Version Bumping

Before tagging, update all package versions together. npm and crates.io require
a unique version per publish; registries do not allow replacing an existing
version. `scripts/check_release_versions.sh` lists every version-bearing
manifest and rejects drift.

```bash
# After updating manifests and lockfiles:
bash scripts/check_release_versions.sh v0.2.5
```

### Smoke Test

The `prepublishOnly` script in `packages/setup/package.json` runs
`node index.js --help` before npm uploads the package.  If the script exits
non-zero the publish is aborted.  You can run the same check locally:

```bash
cd packages/setup && npm publish --dry-run
```

## crates.io Publishing

The workflow publishes the public workspace crates to crates.io on every tag,
in dependency order. It requires the `CARGO_REGISTRY_TOKEN` secret; if the
secret is absent, release preflight fails. The private `sysknife-daemon-test`
and desktop shell crates are not published.

### Enabling crates.io publish

1. Go to <https://crates.io/me> and generate an API token with the
   **Publish new crates** and **Publish updates** scopes.
2. In the GitHub repo, go to **Settings → Secrets and variables → Actions →
   New repository secret**.
3. Name it `CARGO_REGISTRY_TOKEN` and paste the token value.
4. Re-run the latest release workflow (Actions → release → Re-run all jobs) or
   push a new tag.

### Crate publish order

Crates are published in dependency order so crates.io indexes each one before
its dependents try to reference it:

```
sysknife-proto
sysknife-core
sysknife-types
sysknife-brain
sysknife-daemon
sysknife-cli
```

## Verification

After the workflow completes:

- GitHub Release assets are visible at
  `https://github.com/lacs-project/sysknife/releases/tag/vX.Y.Z`.
- npm package is visible at `https://www.npmjs.com/package/sysknife-setup`.
- `npx sysknife-setup --help` should print the help text and exit 0.
- Download a binary and verify its build provenance:

  ```bash
  gh attestation verify sysknife-vX.Y.Z-linux-x86_64 \
    --repo lacs-project/sysknife
  sha256sum --check sha256sums-linux-x86_64.txt
  ```

The matching `.spdx.json` release asset is the dependency inventory bound to
the binary by a separate SBOM attestation.
