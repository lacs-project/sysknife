# Dependencies

How SysKnife chooses, pins, watches, updates and removes the code it depends
on. The thresholds that block a merge or a release live in
[SECURITY.md](https://github.com/lacs-project/sysknife/blob/main/SECURITY.md#dependencies-static-analysis-and-secrets); this
page covers the process around them.

## What SysKnife depends on

| Kind | Declared in | Resolved in |
|---|---|---|
| Rust crates for the workspace, releases included | each crate's `Cargo.toml` | `Cargo.lock` |
| Rust crates for the fuzz targets | `fuzz/Cargo.toml`, its own workspace | `fuzz/Cargo.lock` |
| The paused desktop app's frontend | `apps/sysknife-shell/package.json` | `apps/sysknife-shell/package-lock.json` |
| Markdown tools for CI | `tools/ci-node/package.json` | `tools/ci-node/package-lock.json` |
| Python tools for CI (yamllint) | `tools/ci-python/requirements.txt` | the same file, by sha256 |
| GitHub Actions | `.github/workflows/*.yml` | a full commit SHA per `uses:` |
| Container base images | `Dockerfile`, `.clusterfuzzlite/Dockerfile` | a digest per `FROM` |

`npx sysknife-setup` (`packages/setup`) has no npm dependencies at all. It runs
on Node's standard library, so installing SysKnife pulls nothing from npm
beyond the package itself.

## Choosing a dependency

Before adding one, check in the pull request that:

- The standard library or a crate already in `Cargo.lock` cannot do the job.
- The project is maintained: a release in the last year, and issues that get
  answers.
- Its licence is permissive and compatible with MIT.
- `cargo audit` reports nothing against it.
- You know what it pulls in. Paste the `cargo tree -e normal -i <crate>` lines
  the change adds.

A new dependency of `sysknife-daemon` gets a closer look than one anywhere
else, because the daemon is the process that runs as the `sysknife` account
with its sudo grants. Say in the pull request why the daemon needs it.

## Pinning

- `Cargo.lock` is committed, and the workspace's builds, tests and release
  publishing run with `--locked`, so a dependency changes only through a
  commit that changes the lockfile. The fuzz build (`.clusterfuzzlite/build.sh`)
  goes through `cargo fuzz`, which reads `fuzz/Cargo.lock` without that flag.
- npm lockfiles install with `npm ci`, which refuses a lockfile that disagrees
  with `package.json` and checks every package against its integrity hash.
  `overrides` in `package.json` force a transitive version past an advisory
  when the direct dependency has not moved yet.
- `tools/ci-python/requirements.txt` installs with `pip install
  --require-hashes`, so pip refuses any package, transitive ones included,
  that does not match a listed sha256.
- Each action is pinned by full commit SHA with its release tag in a comment.
  `scripts/verify-action-pins.sh` checks that each SHA is that tag's commit,
  and `tests/release/action-pin-comments.test.sh` checks the comments.
- Tools a workflow downloads, such as mdBook in `docs.yml`, are checked
  against a sha256 written in the workflow before they run.

## Watching

- Dependabot opens version-update pull requests every week for each
  directory in the table above, with a cooldown of a few days so a release
  gets vetted by others before it reaches SysKnife.
  `tests/release/dependabot-coverage.test.sh` fails when a lockfile has no
  Dependabot entry.
- Dependabot security alerts and security updates are on for the repository
  and skip the cooldown.
- `cargo audit` runs on every pull request (required) and daily on `main`;
  `npm-audit.yml` runs daily; `dependency-review` checks every pull request
  (required).
- OpenSSF Scorecard runs weekly.

## Updating

Dependabot pull requests merge once their checks pass, the same day when
possible. A major version bump gets its changelog read for breaking changes
and for anything that touches how the dependency handles untrusted input,
and the pull request says what was checked. A security update follows the
targets in [SECURITY.md](https://github.com/lacs-project/sysknife/blob/main/SECURITY.md#what-we-will-do).

## Removing

When a change removes the last use of a dependency, the same pull request
removes it from `Cargo.toml` and commits the regenerated `Cargo.lock`; a
stale lockfile fails `--locked` in CI. A dependency that RustSec marks
unmaintained or unsound is listed in
[docs/security/audit-advisories.md](security/audit-advisories.md) with its
reach. One that reaches a released binary gets replaced; one that reaches only
the paused desktop app waits for that app's next round of work.
