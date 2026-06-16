# Release Process

This document describes how SysKnife releases are cut and how the
`sysknife-setup` npm package is published.

## Overview

A release is triggered by pushing a version tag of the form `vMAJOR.MINOR.PATCH`
(e.g. `v0.2.0`) to the `main` branch.  The GitHub Actions release workflow
(`.github/workflows/release.yml`) then:

1. Builds `sysknife` and `sysknife-daemon` binaries for Linux x86\_64 and aarch64.
2. Creates a GitHub Release with the binaries and SHA-256 checksums as assets.
3. Publishes `sysknife-setup` to the npm registry as `@sysknife/setup` (requires
   the `NPM_TOKEN` repository secret to be set; see below).

## Cutting a Release

```bash
# Ensure main is clean and all tests pass.
cargo nextest run --workspace --locked

# Tag and push — the workflow fires automatically.
git tag v0.2.0
git push origin v0.2.0
```

The tag must match `v[0-9]+.[0-9]+.[0-9]+` exactly.  Pre-release suffixes
(e.g. `v0.2.0-rc1`) do not trigger the workflow.

## npm Publishing

### Required Secret

Set a repository secret named `NPM_TOKEN` in
**Settings → Secrets and Variables → Actions**.

The token must have the **Automation** type and publish permission for the
`@sysknife` npm scope.  If the secret is absent the publish step is skipped
with a workflow notice; the GitHub Release still proceeds normally.

### How to Create the Token

1. Log in to <https://www.npmjs.com> as the `lacs-project` org admin.
2. Go to **Account → Access Tokens → Generate New Token → Granular Access Token**.
3. Set **Packages and scopes** → `sysknife-setup` → **Read and write**.
4. Copy the token and add it as the `NPM_TOKEN` secret in GitHub.

### Version Bumping

Before tagging a release, update the `version` field in
`packages/setup/package.json`.  npm requires a unique version per publish;
attempting to re-publish the same version fails with `403 You cannot publish
over the previously published versions`.

```bash
# Example: bump to 0.2.0
jq '.version = "0.2.0"' packages/setup/package.json | sponge packages/setup/package.json
git add packages/setup/package.json
git commit -m "chore(setup): bump npm version to 0.2.0"
```

### Smoke Test

The `prepublishOnly` script in `packages/setup/package.json` runs
`node index.js --help` before npm uploads the package.  If the script exits
non-zero the publish is aborted.  You can run the same check locally:

```bash
cd packages/setup && npm publish --dry-run
```

## crates.io Publishing

The workflow publishes the workspace crates to crates.io on every tag, in
dependency order.  This step is **gated on a secret** named
`CARGO_REGISTRY_TOKEN`.  If the secret is absent the step is skipped with a
workflow notice; the GitHub Release and npm steps still complete normally.

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
sysknife-types
sysknife-proto
sysknife-core
sysknife-brain
sysknife-daemon
sysknife-daemon-test
sysknife-cli
```

## Verification

After the workflow completes:

- GitHub Release assets are visible at
  `https://github.com/lacs-project/sysknife/releases/tag/vX.Y.Z`.
- npm package is visible at `https://www.npmjs.com/package/sysknife-setup`.
- `npx sysknife-setup --help` should print the help text and exit 0.
