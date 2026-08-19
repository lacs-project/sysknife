# Changelog

All notable changes to SysKnife are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the version stays in the `0.y` series the middle digit carries breaking
changes; [docs/release.md](docs/release.md#version-numbering) has the rules.

Releases before `0.2.5` predate the public launch; their notes live in the
[git tag history](https://github.com/lacs-project/sysknife/tags).

## [Unreleased]

### Fixed

- **A gate that could not fail: the credential scanner's "never echo the secret"
  assertion.** ([#262](https://github.com/lacs-project/sysknife/pull/262),
  [#228](https://github.com/lacs-project/sysknife/issues/228)) Under `pipefail`,
  `"$CHECK" file | grep -qF "$leak"` reported the scanner's own exit status even
  when grep matched, so the branch that fails the build was unreachable. The
  assertion now captures the output and greps it separately, and a mutation block
  runs an echoing scanner through the same check to prove it can still fail.
  Thanks to @ITSMERNB.
- **Ten files carrying public claims were never screened.**
  ([#259](https://github.com/lacs-project/sysknife/pull/259),
  [#232](https://github.com/lacs-project/sysknife/issues/232))
  `scripts/check_public_claims.sh` kept its own list of six files while
  `check_evidence_claims.py` knew sixteen, so the prose rules skipped ten of them.
  The shell script now reads `CLAIM_FILES` from the Python module, and refuses to
  report success when that read comes back empty, which `set -euo pipefail` cannot
  catch on its own inside process substitution. Thanks to @Osheun.

### Documentation

- **The README hero is an Ubuntu recording, and the social preview leads with
  Ubuntu.** The demo GIF moved from the Fedora Atomic flow to a new Ubuntu 24.04
  one covering `UfwAllow`, `AptInstall` and `UfwStatus`, with the Atomic recording
  still linked for `rpm-ostree` hosts. The social preview now names Ubuntu 20.04+
  first and describes Fedora as Atomic-only, which is what the support matrix
  says. `assets/demo/README.md` records the render pipeline, including the ffmpeg
  frame-rate step that takes a raw 424-frame VHS render down to 170 frames and
  2.12 MB; that step is load-bearing rather than cosmetic, since `gifsicle` only
  touches the palette.
- Contributors are named in the README, with a pointer at Releases for anyone who
  wants to see their own fix ship.
  ([#265](https://github.com/lacs-project/sysknife/pull/265))

## [0.9.0] — 2026-08-19

The first outside contributions land in this release, and four dead public items
leave with them. Removing published paths is a breaking change under Cargo's 0.x
rules, which is why this is 0.9.0 and not 0.8.1.

### Removed

- **Four verified-dead items, and the public paths they occupied.**
  ([#244](https://github.com/lacs-project/sysknife/pull/244))
  `sysknife_core::PRODUCTION_LISTEN_URI`, the root re-export of `detect`,
  `detect_distro`, `parse_os_release`, `DistroFamily` and `DistroId`,
  `sysknife_brain::action_name::UnknownActionName`, and the
  `DEBIAN_ONLY_ACTION_NAMES` / `FEDORA_ONLY_ACTION_NAMES` aliases in
  `sysknife_brain::prompt` are gone. Every live caller already went through the
  module path, so in-tree code is unchanged, and `sysknife_types::UnknownActionName`
  and `sysknife_core::action_family::{DEBIAN_ONLY_ACTIONS, FEDORA_ONLY_ACTIONS}`
  remain the canonical spellings. The unused direct `prost-types` dependency went
  with them. Thanks to @ITSMERNB.

### Fixed

- **A malformed `.mcp.json` was replaced rather than refused, discarding the
  user's other MCP servers.** ([#243](https://github.com/lacs-project/sysknife/pull/243),
  [#225](https://github.com/lacs-project/sysknife/issues/225))
  `mergeMcpServers` treated unparseable content as an empty config, so the wizard
  wrote a sysknife-only file over a config that still held the user's other
  servers, kept no backup, and reported success. It now refuses, and the refusal
  happens before any integration file is written, so a bad `.cursor/mcp.json` no
  longer leaves `.mcp.json` and three hookify rules already on disk. An empty,
  whitespace-only or BOM-prefixed file is treated as a fresh config instead of a
  failure, valid JSON that is not an object is refused, and the error carries the
  parser's position without echoing file contents, since these files hold provider
  API keys. Thanks to @ITSMERNB.
- **The audit-database migration could half-move, and `--purge` could not see the
  result.** ([#241](https://github.com/lacs-project/sysknife/pull/241))
- **Two plugin registry metadata gaps that cost trust points.**
  ([#220](https://github.com/lacs-project/sysknife/pull/220))

### Security

- **h2 queued unbounded empty HTTP/2 DATA frames (RUSTSEC-2026-0258).**
  ([#245](https://github.com/lacs-project/sysknife/pull/245)) Bumped to 0.4.16.
  `cargo audit` names the advisory without the bump and exits clean with it.

### Changed

- `scripts/check_release_versions.sh` now also checks the internal
  `sysknife-* = { path = …, version = … }` pins against the package version, and
  refuses to report success when its manifest globs match nothing. A bump that
  missed a pin would otherwise publish a crate depending on the previously
  released version of its sibling.
- Dependency bumps: futures 0.3.34 and uuid 1.24.1
  ([#257](https://github.com/lacs-project/sysknife/pull/257)),
  @testing-library/jest-dom 7.0.1
  ([#255](https://github.com/lacs-project/sysknife/pull/255)), the
  `rust:1-bookworm` base image digest
  ([#254](https://github.com/lacs-project/sysknife/pull/254)), and four pinned
  GitHub Actions ([#258](https://github.com/lacs-project/sysknife/pull/258)).

### Documentation

- **How the version number is chosen is now written down.** `docs/release.md`
  explains why a removal moves the middle digit while the leading zero stands,
  names the three conditions for 1.0.0, and `CONTRIBUTING.md` points contributors
  at it alongside the test-baseline artifact they need to regenerate when they add
  a test.
- Five published figures that had drifted past the guards were corrected
  ([#242](https://github.com/lacs-project/sysknife/pull/242)), and three dead ends
  in the contributor path were removed
  ([#214](https://github.com/lacs-project/sysknife/pull/214)).

## [0.8.0] — 2026-08-16

Every Debian-only action now has a live-VM story, and the recording that proves
a run can be reproduced finally reproduces the runs that needed a retry.

### Security

- **A credential in an intent reached disk before the fence refused it.**
  ([#206](https://github.com/lacs-project/sysknife/pull/206))
  `Planner::admit_request` refuses any intent `prefs::contains_sensitive` flags,
  so a Pro token or API key never reaches a provider. The CLI, however, printed
  `→ planning "<intent>"` to stderr *before* calling the planner, and both CI and
  the story harness run with stderr redirected to a file. The one value the fence
  exists to contain was therefore written to disk on its way to being refused.
  Both echo sites now go through `prefs::loggable_intent`, which asks
  `contains_sensitive` the same question rather than keeping a second copy of it.

### Added

- **Twenty-nine user stories, 105 to 133, one per Debian-only action that had
  none.** ([#206](https://github.com/lacs-project/sysknife/pull/206))
  `GetHostState` first: the per-distro prompt split exists because naming
  Fedora's `GetSystemState` on an apt host is what the family fence forbids, so
  something had to answer "what is this host?" on Ubuntu, and nothing exercised
  it end to end. Debian-only coverage is 63 of 63. The Ubuntu family runs 79/79
  on 22.04, 24.04 and 26.04, each with a committed replay twin that reproduces
  the run with zero misses.

- **`ProviderError::is_invalid_tool_call`**, the single classification read by
  both the planner's corrective retry and the cassette's rejection recorder. A
  recorder narrower than the retrier leaves a retried run unreplayable; a wider
  one serves a transient failure back for ever.

### Added

- **`sysknife-setup --uninstall`.** There was no way to remove what the wizard
  installed. `make uninstall` covers the `sudo make install` footprint, which is
  a different set of paths. The audit database, the safety-audit log and
  `~/.config/sysknife` are kept and their paths printed, because removing the
  software should not destroy the record of what it did; `--purge` removes them
  and names each one first. A system service is never touched, since its sudoers
  grants and polkit rules belong to the Makefile that installed them.

### Fixed

- **`--no-binary` wrote a systemd unit pointing at a binary that does not
  exist.** It returned a hardcoded `/usr/local/bin/sysknife` regardless of what
  was installed, and the caller derives the daemon path from it, so anyone who
  built from source into `~/.local/bin` got a unit that crash-looped on
  `status=203/EXEC` every five seconds. It now runs the same probe the download
  path already ran, and says so when it finds nothing.

- **The installer reported a working install as broken.** `systemctl --user
  start` returns once systemd has forked the service, not once it is listening,
  and the wizard probed the socket once immediately afterwards. On a cold
  install its final word was "Daemon socket not yet reachable" for a daemon that
  bound a second later. It now polls for up to six seconds.

- **Cassette v2 records provider rejections, so a retried exchange replays.**
  ([#206](https://github.com/lacs-project/sysknife/pull/206))
  The planner appends a correction and re-asks when a provider rejects a tool
  call, but the cassette stored only successes, so the only entry written was the
  *second* call. A replay started from the first, missed, and re-sent identical
  bytes. That single gap was why all three LTS replay twins reported
  `cassette_audit.verdict` `failed`. v1 files are still read; new writes are v2.

- **A failing story's log now carries the CLI's stderr.** It held the story's
  opening line and nothing else, because every story redirects stderr to
  `/tmp/sysknife-story-<n>-stderr.log` and nothing collected it.

- **A record run paces itself.** The provider ceiling that bites is tokens per
  minute, not requests: roughly 17 kB in per call against 250 k TPM is about 14
  calls a minute, and unpaced the suite issues one every three seconds.

### Changed

- **"Validated" now requires a replay twin that actually reproduced the run.**
  `check_evidence_claims.py` accepted any committed twin, including one whose own
  `cassette_audit.verdict` said `failed`. A pass-rate figure was already refused
  on those grounds; the tier was not.

## [0.7.0] — 2026-08-08

A security release. Five privileged paths that a bounded action could ride into
an unbounded root effect, the operator approval prompt, and an audit verify that
reported a check it never ran.

### Security

- **The `npx` installer no longer stages a root-installed binary at a guessable
  path.** ([#180](https://github.com/lacs-project/sysknife/pull/180))
  `writeBinary`'s sudo fallback wrote the payload to
  `${tmpdir}/sysknife-install-${pid}-sysknife` at mode 0644, then ran
  `sudo install` from it. A predictable name in a world-writable directory means
  any local user could pre-create the file, let the installer write through it,
  and replace the contents before the copy — landing a root-owned 0755 binary at
  `/usr/local/bin/sysknife`. Staging now goes through `mkdtemp`: an unguessable
  0700 directory holding a 0600 payload, removed in a `finally`.

- **`ConfigureLogRotation` is confined to `/var/log`.**
  The `--path` argument becomes the stanza header of a config that root's
  logrotate acts on, so any absolute path turned a Medium-risk, Dev-tier action
  into scheduled root-level truncation, rename, or deletion of an arbitrary file
  (`--path /etc/shadow` with `rotate 0`). Enforced in
  `packaging/sysknife-log-edit` and in the daemon's `validated_log_path`.
  `docs/action-reference.md` already documented this confinement; only the code
  was missing it.

- **`RemoveSwap` is no longer an arbitrary root unlink.**
  The helper charset-checked its `--file` and then `os.unlink`ed it as root.
  Every step in between tolerates a non-swap path — `swapoff` runs with
  `check=False`, and the fstab rewrite is a no-op when nothing matches — so
  `--file /etc/shadow` reached the unlink and deleted the shadow file. Removal is
  now confined to paths the host itself reports as swap files (`/proc/swaps` rows
  of type `file`, or an `/etc/fstab` swap entry), and never a symlink.

- **Removing a kernel argument is screened, not assumed safe.**
  Both boot-line editors checked only the *add* list, on the stated premise that
  "removing a dangerous arg is always safe". The premise inverts the risk: the
  dangerous move is removing a *protective* arg. Deleting `module.sig_enforce=1`
  reaches the same next-boot state as adding an unsigned-module loader, which the
  add path already refuses. `SetKernelArguments` and `GrubSetKargs` now screen
  removals against the KSPP-recommended boot parameters plus the LSM selectors,
  with an explicit escape hatch so an argument that is itself a weakening
  (`mitigations=off`, `selinux=0`) stays removable. `sysknife-grub-kargs-edit`
  enforces the same list independently, since it is directly sudo-invocable.

- **A privileged child is stopped when the daemon loses the ability to read it.**
  A `next_line()` error — `InvalidData` on non-UTF-8 stdout, which one
  oddly-encoded filename produces — or a failed `wait()` returned via `?` without
  reaping, leaving a **root** process group running while the executor reported
  the action failed and the dispatcher considered rollback. All three sites now
  stop the group first. `kill_and_reap` takes a `StopCause` so a read failure is
  not reported to the operator as a timeout.

- **Untrusted text can no longer rewrite the approval prompt.**
  The plan and step summaries are model-written, from a context full of
  host-controlled strings; the preview and result summaries carry command output.
  All were printed raw next to — and immediately before — the prompt. `\x1b[2K\r`
  erases and rewrites its own line, `\x1b[1A` walks back over the risk badge, and
  length alone scrolls the plan out of view before the operator answers. The new
  `operator_text::operator_safe` drops C0, `DEL`, the C1 range (a terminal in
  8-bit mode reads `U+009B` as CSI, so stripping only `ESC` is insufficient),
  bidirectional overrides and isolates, and zero-width characters; collapses
  whitespace; and caps the rendered length. It is applied to eight sites,
  including the prompt string itself.

- **The audit database is created owner-only.**
  SQLite created it `0644 & ~umask`. The 0700 parent hides it in place, but the
  file mode travels with a backup or a `cp`, and SQLite derives the `-wal`/`-shm`
  modes from the main file, so the most recent transactions leaked through the
  WAL too. Narrowed to 0600 at open — tightening only, and non-fatal, so a
  `chmod` that fails on a file owned by another user cannot stop a daemon that
  previously started.

- **`sysknife audit verify` now reads the anchor it reports.**
  `verify_chain` proves the chain is internally consistent and correctly signed.
  It cannot prove the chain is *complete*: deleting the newest rows leaves a
  shorter chain that still verifies. With no anchor configured, verify printed an
  honest caveat saying so. With an anchor configured it printed
  `audit_anchor: {configured: true}` and never read the anchor — leaving an
  operator who had set anchoring up strictly worse informed than one who had not.
  The cross-check now runs, its verdict appears beside the chain verdict, and a
  truncation or rewrite reaches the exit code. An anchor holding no checkpoints
  reports `cannot_verify` rather than `consistent`, because zero checkpoints
  trivially satisfy "every checkpoint agrees".

### Changed

- `RUSTSEC-2026-0097` is no longer ignored in CI. `rand` 0.7.3 has left the
  lockfile and `cargo audit` exits clean unignored; an ignore for a crate that is
  not built protects nothing and would silently re-accept the advisory if a
  future bump pulled it back in.
- `client.rs` documented that *all* daemon string output was ANSI-stripped. Only
  captured and streamed command output is; the envelopes deserialize straight
  through. Corrected, and pointed at the render-boundary guard.

### Fixed

- The planner's action catalogue is scoped per distro, so a distro-agnostic tool
  schema no longer produces plans the daemon will reject.
  ([#176](https://github.com/lacs-project/sysknife/pull/176))
- Published figures derive from `tests/evidence/` rather than being retyped.
  ([#177](https://github.com/lacs-project/sysknife/pull/177))

### Known limitations

The `/usr/bin/sh` and `/usr/sbin/runuser` sudoers grants make the daemon
root-capable. This is unchanged from 0.6.0 and documented in
`packaging/sysknife-sudoers`; the security boundary is the daemon's own
authorization, validation, and audit chain, not the sudoers file. Removing the
grants requires `ConfigureFirewall` and the container/toolbox/ssh-key paths to
move to root-owned helpers, and sudoers wildcards cannot substitute because
sudo-rs permits `*` only as a final argument.

## [0.6.0] — 2026-07-31

### Security

- **A hung privileged action is now force-stopped on timeout, not just detected.**
  ([#142](https://github.com/lacs-project/sysknife/issues/142)) Follow-up to #140. The daemon
  runs unprivileged and elevates through `sudo`, so it cannot signal the root child a `sudo`
  action forks; #140 detected this (`ActionNotStopped`) and vetoed rollback, but the work ran
  on. On timeout the daemon now escalates: after its own SIGTERM/SIGKILL to the process group,
  if the group survives as root-owned it runs a root `sudo -n /usr/bin/kill -s <SIG> -- -<pgid>`
  (reaching the root children via the existing kill grant), or `rpm-ostree cancel` for a
  transaction that runs in `rpm-ostreed`'s own cgroup. `ActionNotStopped` is now a genuine last
  resort — the reaper actually failed — rather than the expected path for every sudo action.
  The same-uid path, the escalation dispatch, and the command construction are unit-tested;
  the cross-uid root-child termination is inherently root-only and must be validated on a live
  VM (per the issue's acceptance).

- **Documented the vsock bearer-token replay risk and its threat model.**
  ([#152](https://github.com/lacs-project/sysknife/issues/152)) The vsock pre-shared token is
  sent in the clear as the first frame and is a replayable bearer credential: an adjacent
  party who can observe one legitimate connection can reuse it to authenticate as
  `SYSKNIFE_TOKEN_ROLE` and mint a fresh receipt. This is inherent to a bearer token over an
  unencrypted channel and cannot be closed at the application layer. `SECURITY.md` (new "vsock
  transport authentication" section) and `docs/vm-daemon-setup.md` now state the threat model,
  the operator mitigations (isolate the vsock namespace, prefer forwarding the Unix socket over
  `ssh -L`, lowest role, rotate the token), and the paths to fully close it (a nonce/HMAC
  challenge, or TLS/WireGuard under vsock). A code comment marks the residual risk at the auth
  site.

- **A stalled connection can no longer pin megabytes of memory with a false length header.**
  ([#150](https://github.com/lacs-project/sysknife/issues/150)) `FramedStream::recv`
  pre-allocated the full claimed body (`vec![0u8; len]`, up to 4 MiB) before reading a
  single byte, so a peer that announced a large body and withheld it held that memory for
  its whole pre-auth deadline — N such connections pinned N × 4 MiB. `recv` now streams the
  body in bounded chunks, growing the buffer only as bytes actually arrive, so a withheld
  body costs nothing. The pre-auth window itself remains bounded by the existing
  `VSOCK_AUTH_FRAME_TIMEOUT_SECS`.

- **`audit verify` warns when the daemon you administered is a different machine, even over a forwarded unix socket.**
  ([#146](https://github.com/lacs-project/sysknife/issues/146)) Completes the partial fix in
  0.5.0. Verification reads a local store, so an operator who tunnels a unix socket to another
  host, acts there, then runs `audit verify` reads their own machine's chain and sees
  `Intact` for a chain that has nothing to do with those actions. The env-only heuristic
  could not tell a forwarded unix socket from a local one. The daemon now reports a salted
  hash of its `/etc/machine-id` (never the raw id), and `audit verify` compares it to this
  host's. Only a **mismatch** is treated as decisive (different machine-id ⇒ different
  machine ⇒ print the caveat); a **match** is inconclusive — cloned VM/container images share
  one `/etc/machine-id` — so it falls back to the existing heuristic and never suppresses a
  warning the heuristic would raise (vsock and explicit `SYSKNIFE_SOCKET` still always warn).
  The query runs only for the unix-`SYSKNIFE_LISTEN_URI` case it can help, so `audit verify`
  stays offline otherwise.

- **`AptAutoremove` binds the deletion set the operator approved.**
  ([#151](https://github.com/lacs-project/sysknife/issues/151)) The approval covered only
  the action name and empty params, but `apt-get autoremove -y` resolves the deletion set
  (which can include kernels and drivers) at run time, so the executed effect was unbound
  by the approval and the request hash. The preview now runs `apt-get -s autoremove`, shows
  the exact packages that would be removed (with a warning when they include
  kernel/driver/bootloader packages), and execution re-simulates immediately before running
  and refuses if the set has drifted since approval. This shrinks the unbound window from
  the whole preview-to-approval period down to request handling; it cannot eliminate it,
  because `apt-get autoremove -y` re-resolves the set itself at run time and cannot be pinned
  to a package list, so an external `apt`/`unattended-upgrades` change in that brief window is
  still possible (and out of SysKnife's control).

- **The audit store refuses a Postgres connection that could leak its credential to a network attacker.**
  ([#149](https://github.com/lacs-project/sysknife/issues/149)) sqlx defaults to
  `sslmode=Prefer`, which silently downgrades to plaintext if the server declines TLS.
  `require` is no better against an active attacker: sqlx accepts any certificate under
  `require`, so a man-in-the-middle can present a self-signed cert and read the credential.
  Both the transaction store and the checkpoint sink now require at least `sslmode=verify-ca`
  (authenticates the certificate chain) for a connection that crosses the network, with an
  actionable error recommending `verify-full` (also checks the hostname). Unix-socket and
  loopback connections are exempt (they never touch the network), so local and packaged
  setups are unaffected. **Potentially breaking:** a remote audit/checkpoint URL below
  `verify-ca` (including `require`) now fails at startup; add `?sslmode=verify-full` to the URL.

- **`AddMount` can no longer mount an attacker share over a symlinked critical path.**
  ([#155](https://github.com/lacs-project/sysknife/issues/155)) `op_mount` checked the
  literal mountpoint string, then `os.makedirs(exist_ok=True)` and `mount(8)` both
  followed symlinks, so `AddMount{mountpoint: '/tmp/x'}` with `/tmp/x -> /etc` mounted
  the share over `/etc`. `assert_mountpoint_safe` now refuses a symlinked or
  critical-resolving mountpoint (also closing the `/etc/` and `//etc` denylist
  bypasses), and `op_mount` materializes the mountpoint with `O_DIRECTORY|O_NOFOLLOW`
  and mounts onto `/proc/self/fd/<fd>` so a symlink swapped in after the check cannot
  redirect the mount (the TOCTOU class `op_addswap` also closes). `op_unmount` gained
  the same symlink refusal so a symlinked mountpoint cannot unmount an unrelated
  critical filesystem.

## [0.5.0] — 2026-07-31

### Security

Hardening from a defensive red-team pass. Each fix has an issue and a test.

- **A Dev-role caller can no longer install an attacker-controlled local package as root.**
  ([#143](https://github.com/lacs-project/sysknife/issues/143)) `apt-get install /tmp/x.deb`
  and `rpm-ostree install /tmp/x.rpm` install a local file and run its maintainer
  scripts as root, and the install actions are Medium-risk (Dev). The package
  validator was the generic safe-arg, which allowed `/`; a strict
  `validated_install_package` now rejects paths, `.deb`/`.rpm` suffixes and globs.
- **A Dev-role caller can no longer activate a root-shell unit.**
  ([#144](https://github.com/lacs-project/sysknife/issues/144)) Starting or enabling
  `debug-shell`/`emergency`/`rescue` yields a root shell; the activation verbs now
  refuse those units.
- **AddAuthorizedKey no longer follows a symlink as root.**
  ([#145](https://github.com/lacs-project/sysknife/issues/145)) The write runs as the
  target user via `runuser`, so a planted `~/.ssh/authorized_keys` symlink cannot
  redirect a root append into another account's files.
- **`audit verify` warns about a forwarded socket configured via config.toml.**
  ([#146](https://github.com/lacs-project/sysknife/issues/146)) The wrong-machine caveat
  read only `SYSKNIFE_SOCKET`; it now resolves the socket the way the client dials
  it, so a `SYSKNIFE_LISTEN_URI` forward no longer verifies an unrelated local chain
  silently.
- **The MCP-registry publish workflow refuses an unmerged ref.**
  ([#147](https://github.com/lacs-project/sysknife/issues/147)) `workflow_dispatch`
  accepted an arbitrary ref under the trusted OIDC identity; it now refuses any
  commit not reachable from the default branch and runs the manifest-coherence gate
  before publishing.
- **The swap-file helper no longer follows a symlink as root.**
  ([#148](https://github.com/lacs-project/sysknife/issues/148)) `sysknife-mount-edit`
  creates the file with `O_EXCL|O_NOFOLLOW` instead of an `os.path.exists` check that
  a dangling symlink defeated.

Deferred, tracked: TLS downgrade on unverified Postgres URLs (#149), vsock
partial-frame DoS (#150), unbound AptAutoremove approval (#151), vsock bearer-token
replay (#152).

### Fixed

- **The action timeout now contains the whole process tree, and reports honestly
  when it cannot.** ([#140](https://github.com/lacs-project/sysknife/issues/140))
  The daemon runs unprivileged and elevates through `sudo`, which forks, so
  SIGKILL to the process it spawned left the privileged work running while the
  deadline reported "killed". Actions now run in their own process group and the
  deadline signals the group (a pid-targeted floor, then SIGTERM, then SIGKILL),
  which genuinely stops non-privileged commands. An unprivileged daemon cannot
  signal a root child, so for a `sudo` action whose work runs as root the group
  cannot be force-killed; the timeout now detects that (the group probe returns
  `EPERM`, not "gone") and returns `ActionNotStopped` instead of a false
  success. Real termination of a root child needs a privileged reaper, tracked
  in [#142](https://github.com/lacs-project/sysknife/issues/142).
- **A rollback is never started over an action that may still be running.**
  A timeout marks the job failed, and a failed rollback-eligible action used to
  trigger `rpm-ostree rollback` immediately, which combined with the bug above
  could put two package transactions on one host. When the action cannot be
  confirmed stopped the daemon now skips the rollback and holds the exclusion
  slot, so no other mutating action can start either, until the daemon is
  restarted. Doing nothing is recoverable; doing both is not.
- **The timeout path can no longer hang.** Every `wait()` on a child that may be
  an unkillable root process is bounded, so the timeout that exists to stop a
  hang cannot itself become one.
- The timeout test asserted only that the call returned a timeout error, which
  is true of a daemon that gives up waiting while the work continues. It now
  asserts the spawned work is gone by exact argv from `/proc`, covers the
  production spawn path, pins the SIGTERM to SIGKILL escalation, and drives the
  rollback veto end to end through the real dispatcher.

## [0.4.0] — 2026-07-30

`sysknife audit verify` now says **why** a row names no account, and refuses to
credit an account it cannot prove.

### Security

- **An unsigned column can no longer manufacture attribution.**
  `caller_principal` enters the signed message only under `chain_version = 3`, so
  on a v1 or v2 row that column is unsigned free space. Anyone able to write to
  the transaction table could set it to `uid:0`, and the chain would still verify
  as `Intact`, because no signature covers it. The census therefore buckets rows
  by the encoding that signed them, not by what the column holds, and reports a
  principal no signature vouches for as `rows_unattested` rather than as an
  account. Losing attribution is a gap; inventing it is a lie, and the report now
  refuses the second even where that means saying less. The same bucket catches a
  value this build cannot read back as one the daemon could have written, and a row
  declaring an encoding this build does not know — the second of which means a
  newer SysKnife wrote it, so the remedy there is a newer verifier, not an
  incident.
- **Attribution counts are marked as claims unless the chain verified.**
  Verification stops at the first broken row while the census spans every row read,
  so when the chain verdict is not `intact` the rows counted include any the
  attacker wrote — and also, usually, authentic rows, since deleting or reordering
  one breaks the link while leaving later signatures valid. The output says exactly
  that instead of implying every surplus row is forged, and it distinguishes a
  detected break from "this build could not check at all", which is a statement
  about the binary or the key rather than a finding about the rows. The new
  `rows_censused` count makes the gap against `rows_checked` measurable. Previously
  the notes stated that rows were "authentic and verified" under every verdict,
  including `CANNOT VERIFY`, where nothing had been checked.

### Changed

- **The attribution report is a census, not a single number.** 0.3.0 reported
  `unattributed_rows`, matching the `caller_principal` column against
  `none:unattributed` on any encoding. A database upgraded from an earlier release
  is full of v1 and v2 rows that carry no principal at all, and those were counted
  nowhere:
  `unattributed_rows: 0` over such a chain read as "every action is attributed"
  when in fact none of them was. `--json` and the `sysknife_audit_verify` MCP
  tool now report `rows_censused`, `attributed_rows`, `unattributed_rows`,
  `rows_without_principal`, `rows_unattested` and `rows_naming_no_account`, and
  the human-readable output prints one summary line plus a note per reason. The
  distinction is operational: an attribution failure is a live `SO_PEERCRED`
  problem to chase, a row older than the column cannot be repaired at all, and an
  unattested principal is something to investigate.
- **`unattributed_rows` narrowed, on purpose.** It now counts only rows whose
  `chain_version = 3` principal is *signed* as `none:unattributed`. The same string
  sitting in the column of a v1 or v2 row is no longer counted there, because
  nothing signed it; those rows report as `rows_unattested`. Anyone alerting on
  this field should know the population changed even though the name did not.
- **`sysknife_audit_verify` reports `chain_status`.** The top-level `status` is the
  worst of three checks, so a broken approval-event chain turned it `broken` while
  the transaction chain was intact, and an agent had no way to recover the chain's
  own verdict — which is the one that decides whether the attribution counts are
  findings or claims.
- **Every attribution field is nullable, and `null` means "not measured".** When
  no rows were read — an unopenable store, a missing key — the counts are `null`
  rather than `0`, so a database nobody could read cannot be mistaken for one
  where nothing was found. The MCP tool previously discarded a census that had
  already been computed on the `cannot_verify` path and published zeros, so it
  disagreed with `sysknife audit verify --json` about the same database.
- **Library API.** `AuditVerification::unattributed_rows: u64` is replaced by
  `AuditVerification::attribution: Option<AttributionCensus>`. The census has
  private fields and one constructor that reads rows, `AttributionCensus::of`, so a
  census cannot state totals that contradict the rows it describes;
  `from_counts_for_tests` exists for renderer tests and is gated behind the new
  `test-support` feature rather than merely hidden from docs. `CallerPrincipal`
  gains `claim` and `classify`, the inverse of `as_signed_str`: `classify` accepts a
  stored string only when the principal it rebuilds renders back to exactly those
  bytes, so `uid:007`, `uid:1000:extra`, `uid:notanumber` and `token:not-vsock` are
  refused rather than credited as accounts.

The chain format is unchanged: no row is rewritten, nothing is backfilled, and
every 0.2.x and 0.3.0 row verifies exactly as before. What changed is what the
report says about those rows.

## [0.3.0] — 2026-07-29

The signed audit chain now records **which account** acted, not only which role.
Schema version 3, with a real migration and no rewrite of existing rows.

### Added

- **`chain_version = 3` signs a caller principal.** A row bound to a
  `CallerRole` could not separate two members of `sysknife-admin`, so the trail
  answered "an Admin did this" and stopped one question short of where an
  investigation starts. Rows now also sign `caller_principal`, resolved by the
  daemon from the same `SO_PEERCRED` read that yields the role and never taken
  from the request body. Three forms, with the scheme signed alongside the value
  because the evidence differs in strength: `uid:<n>` attested by the kernel,
  `token:vsock` for a pre-shared secret that proves possession of a file rather
  than an account, and `none:unattributed` when the daemon could establish
  neither.
- **The principal reaches the SIEM.** Forwarded RFC 5424 events carry a
  `principal` structured-data field, taken from the signed row rather than from
  connection state, so an external monitor sees what the chain committed to.
- **`sysknife audit verify` reports `unattributed_rows`.** A chain of rows that
  name nobody verifies as intact, which is true and incomplete; the count is now
  reported next to the verdict, in `--json`, and on the `sysknife_audit_verify`
  MCP tool.
- Golden on-disk vectors for all three encodings, plus one row exercising the
  escape table, an absent approval id and a non-empty predecessor hash. These
  are the only tests that can notice an encoding drifting, because every other
  test signs and verifies in one process.

### Changed

- **Existing audit logs keep verifying.** v1, v2 and v3 rows coexist in one
  chain and each is re-encoded exactly as it was signed. Migration 3 adds a
  nullable column in both backends and backfills nothing: writing a principal
  into a row signed without one would change its message and report the chain as
  broken.
- `CallerAttribution` replaces a bare `CallerRole` through the dispatcher, with
  private fields and per-transport constructors, so an attribution failure can
  no longer be paired with a privileged role.
- CI lints test targets (`cargo clippy --all-targets`). Without it a duplicated
  `#[test]` attribute, which silently drops the test it was meant for, passed
  every check.

### Fixed

- **A version-aliasing hazard that would have broken every existing audit log.**
  The v2 encoder signed `CHAIN_VERSION_CURRENT` and version dispatch compared
  against the same constant, so the next encoding bump would have re-encoded
  every stored v2 row and reported healthy chains as unverifiable — while the
  unit suite stayed green, because in-memory tests sign and verify under one
  constant. Each generation now signs and dispatches on its own stable literal,
  and the stored `chain_version` is derived from the identity that was signed.
- **A peer outside the daemon's namespaces was signed as a real account.** The
  kernel substitutes the overflow uid (`nobody`) rather than failing when a
  peer's uid is not mappable, and reports pid 0 when the pid is not
  representable. Both were recorded as kernel-attested accounts; both now record
  an attribution failure.
- The missing-field break message named the newest encoding rather than the one
  the row declares, and reported an empty column as `NULL`.

## [0.2.16] — 2026-07-28

A whole-repository review pass (four independent read-only reviewers, one per
lens: UX, security, dead code, and drift between code and docs) followed by the
fixes. Scope for this repository is now stated once and enforced: **Ubuntu is the
supported platform, every release from 20.04 up**, and the Tauri GUI is out of
scope.

### Fixed

- **Ubuntu 20.04 and every interim release were refused as unsupported hosts.**
  `DistroId::is_supported()` accepted exactly `22.04 | 24.04 | 26.04`, and the
  daemon refuses *every mutating action* when that is false — so a user on 20.04,
  25.10 or 26.10 could plan and then be told their host was unsupported.
  Eligibility is now all Ubuntu releases from 20.04 up, separated explicitly from
  VM-validation tier, which stays a narrower per-release claim.
- **The CLI never read `config.toml`.** `docs/configuration.md` said the daemon
  and CLI both read it at startup; only the daemon did, so a configured
  `[daemon] socket` or `[llm]` provider was silently ignored by the CLI *and* by
  the MCP server, which shares the entry point. Startup is now synchronous up to
  the runtime build, because applying the file sets environment variables and
  that is only sound while single-threaded. Environment values still win.
- **Approval was collected before the authoritative preview was shown.** The
  operator saw planner summaries and risk, answered "execute?", and only then did
  the daemon preview — carrying `proposed_change`, `expected_side_effects` and
  `rollback_available` — get printed, immediately before execution. The preview
  was never a decision point. Previews are now fetched and rendered first;
  `--step-by-step` confirms every step against its preview, and the default mode
  re-confirms HIGH risk, the one class `--yes` can never auto-approve.
- **Nine of ten privileged helpers were never installed.** `packaging/` ships
  twelve helper scripts and `sysknife-sudoers` grants ten, but `make
  daemon-install` installed only `grub-kargs-edit`, so sysctl, PAM, auditd,
  mount, fail2ban, logging, sshd-option, scheduled-job and apt-pin actions failed
  at execution time after a source install. A new test derives the required set
  from the daemon's own source, so packaging a helper without installing it now
  fails CI.
- **`--daemon-mode=system` reported success while installing nothing.** The
  branch printed a paragraph about the Makefile and returned, leaving MCP clients
  configured against a daemon that did not exist; the command it printed also
  omitted the `sudo` the Makefile requires. It now returns its outcome, the
  wizard states plainly that the daemon is not installed yet, and the printed
  sequence includes `sudo make install` and the group-membership step.
- **`sysknife audit verify` read the wrong audit store on a system install.**
  `SYSKNIFE_DATABASE_PATH` reaches the daemon through its unit's `Environment=`
  lines, which a CLI run by an operator never sees, so verification looked in
  `~/.local/state` and reported the chain unverifiable on a healthy install. It
  now resolves the system store when no per-user store exists, says which store
  it read, and names the root-owned key case.
- **`doctor` could not recognise socket-permission denial.** `/run/sysknife` is
  `0750 sysknife:sysknife` and a sudo admin is not in that group automatically,
  so every request failed while `systemctl status` looked healthy. `doctor` now
  leads with the `usermod -aG` fix and the required re-login when the failure is
  `Permission denied`.
- **`--non-interactive` was documented as exiting 3**, contradicting both the
  implementation and the exit-code table three rows below it. It is 1.
- **The MCP registry publish check verified a hard-coded old version.** The
  snippet pinned `0.2.14` while `server.json` named `0.2.15`, so the ownership
  marker could pass for an artefact that was not being published. It now reads
  the version from the manifest.
- **The vsock guide configured only the client**, leaving the daemon on its
  default Unix socket so the advertised no-SSH connection could not work. The
  daemon-side `SYSKNIFE_LISTEN_URI` drop-in is now part of the procedure.

### Security

- **Wi-Fi passwords were stored in the audit database.** `credential_keys_for`
  covered only `ProAttach.token`, so a `ConfigureWifi` password was persisted in
  the preview's `proposed_change` and returned in preview output. It is now
  redacted from both params and argv. The argv rule is keyword-anchored rather
  than positional or value-matched, because the `password <pw>` pair is absent for
  open networks and value-matching would clobber a structural element when the
  SSID or the password is itself the word `password`.
- **A silent connection could squat an IPC slot for fifteen minutes.** Each
  accepted connection holds one of `MAX_CONNECTIONS` permits and the accept loop
  *drops* new connections when they are gone, so a member of the socket group —
  needing no role at all — could deny service cheaply. The between-request idle
  bound stays 15 minutes; a connection that has not yet sent its first request
  now gets 30 seconds.
- **`sysknife audit verify` implied more than it proved.** A truncated chain
  verifies: the retained prefix chains correctly and the walk starts from an empty
  predecessor. Because the packaged unit configures no independent checkpoint
  anchor, the default deployment cannot detect that removal, and the verdict now
  says so instead of letting `OK` be read as "nothing was removed".
- **Release-artefact trust is now documented honestly**, and
  `SYSKNIFE_PINNED_SHA256SUMS` lets an operator require a digest obtained
  independently of the release. The installer also prints the digest it accepted.
  A malformed or unreadable pin aborts the install rather than degrading to a
  no-op.

### Added

- MCP `sysknife_plan` steps now carry the daemon's whole preview —
  `current_state`, `proposed_change`, `expected_side_effects`, `reboot_required`,
  `rollback_available` and `warnings` — so an agent can state what it is asking
  the operator to approve. `sysknife_execute` results carry `rollback_ref`, which
  `docs/automatic-rollback.md` already promised.

### Removed

- **`crates/sysknife-daemon/src/distro.rs`**, an entire duplicate distro model
  and parser compiled into the published daemon library with no caller anywhere
  in the workspace. `HACKING.md` §18 pointed contributors at it as the extension
  point for adding a distro, describing a dispatch shape that was never built;
  that section now documents the real routing path through
  `sysknife-core::distro` and `action_family`.
- `InMemoryCheckpointSink` moved behind `cfg(test)` — it was a production-facing
  type documented for "tests and dry runs" with no dry-run consumer.
- The daemon's unused direct `tracing` dependency.

### Changed

- **Named the magic numbers in the validators and the executor.** Field bounds
  (`MAX_DNS_NAME_LEN`, `MAX_DNS_LABEL_LEN`, `MAX_PORT`, `MAX_FSTAB_FIELD_LEN`,
  `MAX_EMAIL_LEN`, …) and tool ceilings (`MAX_PASSWORD_AGE_DAYS`,
  `MAX_LOCKOUT_WINDOW_SECS`, `MAX_FAIL2BAN_WINDOW_SECS`, `MAX_JOURNAL_LINES`,
  `MAX_SWAP_SIZE_MB`) now say where they come from — a standard, or the format
  the value is written into. Three duplications collapsed in the process: the
  rate-limit window was spelled `60` at each of the three sites that define what
  "per minute" means including the retry message, the provider adapters
  truncated log previews at a bare `200` in four places, and `65535` appeared in
  both the port validator and the executor. Values are unchanged; verified by
  inlining every new constant and confirming the resulting literal multiset
  matches the previous revision exactly.
- Calendar-arithmetic constants (`146097`, `719468`, `153`) were deliberately
  left alone: they are only meaningful as part of Howard Hinnant's
  `civil_from_days` algorithm and naming them individually would obscure it.

### Known gaps

- The signed chain still binds rows to the caller's *role*, not to the
  individual account, so two `sysknife-admin` members are indistinguishable in
  the audit trail. Recording the uid means a new signed row encoding across both
  storage backends and is tracked in SECURITY.md rather than bundled here.

## [0.2.15] — 2026-07-28

The install path was broken for every new user: `npx sysknife-setup`, the command
the README leads with, could not fetch release metadata at all. This release
exists to ship that fix, so it is worth taking even though no feature changed.

### Fixed

- **`sysknife_doctor` over MCP reported the socket as Rust `Debug`.** The CLI was
  fixed to print `unix:///run/…` but `mcp_server.rs` kept its own
  `format!("{socket:?}")`, so the two disagreed about the same value and MCP
  clients received `Unix("/run/sysknife/daemon.sock")` — not a string anything can
  put back into `SYSKNIFE_SOCKET`. The field's schema description documented that
  Debug form as its example, which is what an LLM reads. Caught by Glama's build
  harness running a real MCP client against the server, not by this repository's
  own tests. A test now asserts no source file in the crate formats a socket with
  `Debug`, because the same defect was introduced and then half-fixed twice.

- **`npx sysknife-setup` could not install anything, on any platform.** The
  release-metadata request reused the asset-download `Accept:
  application/octet-stream`, and GitHub answers that with **HTTP 415** on the
  metadata endpoint, so the advertised primary install path died at
  `✗ Failed to fetch release metadata` before downloading a byte. Metadata now
  asks for `application/vnd.github+json`. Verified end to end in a clean
  `ubuntu:24.04` container: both binaries download, SHA-256 verify, and install.
- **The wizard crashed with a raw `SyntaxError` on Ubuntu 22.04**, whose
  `apt install nodejs` gives Node 12. `engines` is only a warning to npx, and a
  version check inside `index.js` could never run, because a parse error is
  raised for the whole module before any statement in it executes. The bin
  entrypoint is now a Node-12-parseable guard that explains the requirement and
  offers three ways to get a current Node, or to skip Node entirely.
- **`--no-prompts` silently installed the daemon that cannot do the job.** It
  always answered "user service", which runs as the invoking user, while the
  NOPASSWD grants live in `packaging/sysknife-sudoers` scoped to the `sysknife`
  system user. Since the daemon reaches privileged work through `sudo`, an
  automated install produced something that answered read-only queries and
  failed everything else with `sudo: a password is required`. Unattended runs now
  require `--daemon-mode=system|user|skip`, and choosing user mode prints what
  will not work and how to get a daemon that can.
- **A second daemon silently evicted the first.** The bind path removed any
  existing socket after checking only that it *was* a socket, never that anything
  was behind it, so starting the daemon twice unlinked the live socket and left
  the first process's clients dark with no error, warning, or log line. The path
  is now probe-connected first: a live daemon means refusal, a stale socket is
  still reclaimed.
- **Daemon startup dumped Rust `Debug` at operators.** Binding without
  permission produced `Error: Io("Permission denied (os error 13)")` with no
  path and no hint, the most likely first-run failure and the worst message in
  the codebase. `main` now reports through `Display`, the bind failure names the
  directory and the uid and both ways out, and `listening on …` is printed only
  after the bind actually succeeds rather than before it.
- **`sysknife doctor` was the worst-informed command about the thing it exists to
  diagnose.** It printed neither the socket it dialled (the caller had the label
  in hand) nor any next step, rendered sockets as `Unix("/run/…")`, and `main`
  re-printed the whole sentence underneath. It now reports once, names the socket
  as a URI, and suggests the systemd unit matching the socket's kind — user-mode
  first for a `/run/user/…` socket, and no local unit at all for vsock.
- **`sysknife approve` blamed a flag that does not exist.** Without a TTY it
  returned "plan requires interactive approval but `--non-interactive` was set",
  which cannot be true: `approve` has no such flag. Piping or scripting it now
  says stdin is not a terminal.
- **Planning printed nothing for minutes without a TTY.** `indicatif` hides the
  spinner when stderr is not a terminal, so an ssh or logged run was
  indistinguishable from a hang (173s measured). One stderr line now names the
  provider and model before the request.
- **A keyless environment chose Ollama without saying so**, then failed against a
  port the user had never heard of. The fallback now announces itself and lists
  the keys that would override it.
- Provider errors no longer name an internal dependency (`Rig completion error:`),
  and OpenAI auth failures name `OPENAI_API_KEY` instead of "your API key".
- Authorization refusals name the group that grants the required role and the
  `usermod` command, including that it only applies to a new login. Previously
  they ended at "is not allowed for Observer role" — accurate and a dead end.

### Changed

- **Documented the real build prerequisite, which is not the one CI implied.**
  Every from-source path now states that a C compiler and linker
  (`build-essential`) are required, and that **`cmake` is not**. `.github/`
  installs cmake before building this workspace, so the natural inference was
  that it was needed; clean-container runs disprove it — `aws-lc-sys` builds
  from `gcc` alone, and the only hard failure is `error: linker cc not found`
  with no compiler at all. Build time is stated too: 6m56s on Ubuntu 24.04,
  11m43s on 22.04, about 400 crates.
- `docs/quickstart.md` is now the canonical install page, and README and
  `docs/mcp.md` link to it instead of carrying their own slightly different
  sequences. `docs/mcp.md`'s "Build the binary" is relabelled as the alternative
  it always was, not step 4 of 5.
- `apps/sysknife-cli/README.md` — the page crates.io renders, and therefore what
  someone arriving from the MCP Registry reads — now leads with the fact that the
  crate is half of SysKnife: it plans and dry-runs, and executing needs the
  privileged daemon.
- README carries the Glama server-score badge (currently license A, quality A,
  maintenance B). The badge stopped being a generic placeholder once the server
  had a Glama release built from its own Dockerfile spec.
- The setup wizard's target prompt says "Target" rather than "VM Target" and
  leads with this machine, since the documented headline case is a local install.
  Its socket-unreachable hint now matches the socket's kind rather than always
  naming the system unit.
- `scripts/check_release_versions.sh` covers both `server.json` version fields,
  so a release cannot bump the crates and leave the registry listing pointing at
  a version whose README the validator will not fetch.
- `docs/mcp-registry.md` records the two-call crates.io check that proves the
  marker is live in a given published version, rather than only present in the
  repository.

### Added

- **`server.json`** at the repository root: the manifest published to the
  official [MCP Registry](https://registry.modelcontextprotocol.io) under
  `io.github.lacs-project/sysknife`. It lists the `cargo` package
  `sysknife-cli` with `mcp-server` as a positional argument, which is what the
  registry's cargo validator and `mcp-publisher validate` accept. No new
  package and no version bump: the ownership marker has shipped in the crate
  README since 0.2.6, so the already-published 0.2.14 crate is what gets
  listed.
- `tests/release/registry-manifest.test.sh` guards the listing. The failure it
  exists for is quiet: the validator proves ownership by searching the crate's
  **rendered** crates.io README for a plain-text `mcp-name:` token, and
  crates.io strips HTML comments when rendering, so moving the marker into a
  comment or dropping it during a README rewrite breaks the next publish with
  nothing in the repository looking wrong. The test also pins the registry type,
  base URL, transport, crate identity, and the `mcp-server` argument. It runs in
  CI and in the release preflight.

## [0.2.14] — 2026-07-28

### Added

- **`.codex-plugin/plugin.json`** — the manifest Codex plugin directories read
  to list SysKnife. `hashgraph-online/awesome-codex-plugins` fetches this
  repository's default branch and fails a listing PR when the manifest is
  absent, which is exactly what was blocking
  [their #327](https://github.com/hashgraph-online/awesome-codex-plugins/pull/327).
  It carries the required identity, licence and interface fields, and a
  `composerIcon` pointing at the committed 16KB `assets/raster/sysknife-256.png`.
- `.codex-plugin/mcp.json` declares how to launch the server, with **no `env`
  block**: credentials come from the environment, and a tracked manifest holding
  a placeholder API key is an easy way to commit a real one by accident (the
  root `.mcp.json` is gitignored for that reason). `command` is the bare
  `sysknife` so it resolves from `PATH` after any supported install.

### Changed

- `scripts/check_release_versions.sh` covers the plugin manifest, so a release
  that bumps the crates but forgets it fails CI instead of leaving a plugin
  directory advertising a version that was never shipped.

No behaviour change to any binary; this release exists so the published version
and the manifest a directory reads agree.

## [0.2.13] — 2026-07-27

The last item v0.2.12 deferred: the audit chain could say what was authorised,
but not who asked for it, and nothing signed recorded that an approval ever
happened.

### Added

- **`caller_role` is now part of the signed chain content.** Every transaction
  row commits to the privilege tier the daemon resolved for the connection that
  requested the action (from `SO_PEERCRED`, or the vsock token — never from the
  request body). "Which role asked for this" is the first question any audit of
  a privileged action starts with, and until now no signed record answered it.
- **An approval-event chain.** `approval_granted`, `approval_consumed` and
  `approval_revoked` are recorded in a second forward Ed25519 chain under its
  own domain tag, each event committing in the same database transaction as the
  state change it records. Previously these lifecycle facts lived only in
  `transaction_approvals`, a plain mutable table: deleting a row left
  `sysknife audit verify` reporting `Intact`, so the record that a privileged
  action had been approved was the one part of the trail that could be erased
  without leaving a mark.
- **Cross-chain binding.** Each transaction row signs the approval-event chain
  tip as of its insert. Deleting events from the *end* of the event chain
  leaves a self-consistent remainder that the chain walk cannot see; the
  committed tip catches it. Because checkpoints anchor the transaction chain,
  this extends off-host anchoring to the event chain without a second sink.
- `sysknife audit verify` reports all three checks and fails on any of them.
  A detected tamper (exit `1`) outranks an inconclusive check (exit `2`), so a
  broken chain is never reported as "could not verify". The MCP
  `sysknife_audit_verify` report gains `events_checked`,
  `approval_events_status` and `binding_status`, and its top-level `status` is
  now the worst of the three rather than the transaction chain alone.

### Changed

- **Schema version 2, with a real migration.** Rows carry a `chain_version`
  column and verification reproduces the exact encoding each row was signed
  under, so a chain written by v0.2.12 or earlier still verifies after the
  upgrade and new rows append onto it in the same walk. Backfilling the new
  fields instead would have changed every historical message and reported the
  whole chain as broken — an upgrade that looks identical to a compromise. The
  SQLite backend gained an ordered migration list mirroring the Postgres one;
  its previous `CREATE TABLE IF NOT EXISTS` batch had no way to express "add a
  column to an existing database".
- `CallerRole::as_str` replaces `format!("{role:?}")` for anything that is
  written down. `Debug` carries no stability promise, and this string is inside
  a signature.
- `TransactionStore::revoke_unconsumed_approval` and
  `claim_approved_for_execution` now require the signing key and refuse on a
  read-only store, since both append to the event chain.

- `PlanningError::Provider` carries a `ProviderError` instead of its rendered
  string. The shell recovered the classification by searching that string for
  `"429"` and `"http"`, so editing a `#[error(...)]` format string in
  `provider.rs` could silently reclassify a rate limit as a parse error. The
  three planner tests that all asserted `Provider(_)` now assert the variant.
- New `TransactionId` and `ApprovalReceipt` newtypes.
  `DaemonClient::execute(transaction_id, action_name, params, approval_receipt, …)`
  took three bare `&str` in a row, so transposing two of them compiled and
  surfaced at runtime as a stale-approval error — which reads like an expiry,
  not a call-site bug. `ApprovalReceipt` is a bearer credential, so its `Debug`
  is redacted and it has no `Display`; the one place it is meant to be printed
  calls `as_str()` explicitly. The MCP wire structs keep plain strings so the
  published JSON Schema is unchanged.

- Tests for three paths that had none: the MCP server over real stdio JSON-RPC
  (`initialize` → `tools/list` against the spawned binary — everything else
  called the handlers directly and skipped the wire), the approval gate
  `run_intent` actually runs, and `PostgresCheckpointSink` against a live
  database. The last one immediately caught a real bug: `fetch_chain_rows_from_pool`
  still selected the pre-migration column list, so every Postgres chain read
  would have failed with "no column found for name: chain_version". Both
  backends now build that list from one constant.

### Fixed

- **The MCP server introduced itself as `rmcp`.** `Implementation::from_build_env()`
  resolves `CARGO_PKG_*` at the crate where the macro expands, which is `rmcp`,
  so `initialize` reported the name and version of the transport library rather
  than of SysKnife — the string clients and registry listings display.
- **`describe` had no authorization check.** It renders the exact command an
  action would run, so any caller could enumerate the argv of every privileged
  action on the host. It now applies the same authorization gate and platform
  fence as `preview`; an unknown action is still a `validation_failure`.
- **`query_action` had no platform fence.** A Fedora-only read-only action
  reached the executor on a Debian host and failed as "rpm-ostree: No such file
  or directory" instead of the clean `unsupported_platform` refusal `preview`
  and `execute` return.
- **`[policy.risk_overrides]` no longer leaks into the platform fence.** Whether
  an action mutates the system is a property of the action; the fence now reads
  the compile-time baseline. Previously, raising a read-only action's required
  role also made that read fail whenever the host distro could not be detected.

## [0.2.12] — 2026-07-27

Follow-up to the v0.2.11 review sweep: the findings that release deferred.

### Added

- **The daemon now anchors signed audit checkpoints.** The machinery was
  complete and tested but inert — nothing ever called `sign_checkpoint` or a
  `CheckpointSink`, so tail-truncation detection and rewrite-by-a-key-holder
  detection were only active if an operator ran `sysknife audit checkpoint` on
  a timer of their own. Set `SYSKNIFE_CHECKPOINT_DB` to enable it; when unset
  the daemon now says so at startup rather than letting a documented guarantee
  look active while it is off. The anchoring rules (refuse a chain that does
  not verify, read back after writing, re-verify every anchored checkpoint)
  live in one `anchor_once` shared by the CLI and the daemon.

### Security

- `Plan::assume_authorized` — the one hole in the type-level guarantee that the
  approval gate can never see the LLM's self-reported risk — is now behind a
  `test-support` feature, so constructing an `AuthorizedPlan` from unvalidated
  risk is a compile error outside tests.
- `NewTransaction.approval_id` was a public field used verbatim at insert. That
  value is chain-hashed and then treated as evidence that an approval happened.
  It is no longer settable; the commitment is always derived by the store.

### Changed

- `CallerRole` derives `Ord` from its declaration order and the hand-written
  `role_rank` is deleted — one encoding of privilege order instead of two.
- `ApprovalDecision::ExceedsCeiling` carries the ceiling it matched, removing
  two `.expect()`s that re-derived it at the call sites.
- The four proto-bridge `From` impls are exhaustive matches rather than an i32
  round-trip with `.expect()`, so a drift from the `.proto` is a compile error
  instead of a panic inside a root process.
- `JobStateMachine` is removed. Production calls the free `allowed_transition`;
  the struct was dead code whose ten tests read as coverage of the live
  transition logic. The table is now tested directly and exhaustively.

### Fixed (test coverage)

- The `transient_infrastructure_failure` deny paths had no test at all, so a
  refactor turning an `Err` arm into an implicit allow would have been an
  invisible approval-boundary bypass. Approve-on-a-failing-store is now
  covered, including that the transaction stays Queued.
- Preview is pinned as never reaching the executor.
- New coverage for `revoke_unconsumed_approval` (including that a consumed
  receipt cannot be retracted), approving a non-Queued transaction, two
  concurrent claims on one approval, truncated frame header/body,
  authorized-keys traversal *through `build_action_spec`*, malformed IPs,
  signal-killed exit codes, `--timeout`, `audit verify` exit code 2,
  and the remaining `ProviderError` variants.
- `resolve_caller_role_on_pair_does_not_panic` discarded its result and would
  have passed if the function returned `Boot` for everyone; it now derives the
  expectation from the same inputs the daemon uses.
- `inserted_forged_row_breaks_chain` accepted `seq == 2 || seq == 3` against a
  deterministic fixture. Pinned to 2.

## [0.2.11] — 2026-07-27

Findings from a full review of the daemon, the CLI/MCP surface, and the
Ubuntu action set, with the Ubuntu commands validated against a real
Ubuntu 24.04 VM.

### Security

- **`RemoveAuthorizedKey` no longer builds a regular expression from the
  caller's key.** It deleted the approved line with `sed -i '\|^KEY$|d'`,
  which made the public key a basic regular expression: `ssh-ed25519 .*`
  passes every check in `validated_public_key` and then matched and deleted
  *every* ed25519 key in the file. `sed` exits 0, so the job recorded
  `Succeeded` and the signed audit summary read as a routine single-key
  removal. Both key operations now use `grep -Fxv` with the key passed as a
  positional argument. Blocklisting regex metacharacters was not an option:
  `.` is legal in a key comment.
- **`GrantSudoAccess` can no longer mint `user ALL=(ALL) NOPASSWD: ALL`**, a
  standing passwordless root credential. The unrestricted-plus-passwordless
  combination is refused by both the daemon and the helper; scope the
  commands or keep the password prompt.
- **The vsock token file's permissions are now checked**, mirroring the
  Ed25519 signing key. A token written under a default umask lands at `0644`,
  and any local user who could read it could authenticate over vsock.
- `validated_apt_package` was the only validator without a leading-dash
  guard, so a package name could reach a command in flag position.

### Fixed

- **Every mutating apt action failed on a real Ubuntu host.** The code sent a
  bare `apt-get` while the packaged sudoers grant spells `/usr/bin/apt-get`;
  sudo PATH-resolves only its primary command and matches later tokens
  literally, so the rule never applied and apt fell through to "a password is
  required". `ConfigureWifi` had no `nmcli` grant at all. Both are covered by
  a test that re-implements sudo's matching rule against the packaged file.
- **The PostgreSQL backend signed a malformed timestamp into every audit
  row.** `now_iso()` omitted `%S`, producing `2026-07-27T12:34:.567Z`.
- **Two concurrent apt actions could collide on the dpkg lock.** The
  concurrency gate only engaged for High-risk *reboot-required* actions, so
  `AptUpgrade` claimed nothing. The gate is now keyed by the system lock an
  action actually holds, derived from its argv. Actions holding no shared
  lock are no longer serialised behind a long apt run.
- **Privileged child processes had no deadline.** A hung command wedged its
  connection forever and never released its lock. Now bounded, killed and
  reaped; override with `SYSKNIFE_ACTION_TIMEOUT_SECS`.
- **`dispatch_loop` had no idle timeout**, so an Observer-tier caller could
  hold every connection slot with silent sockets and lock out approvers.
- **The async daemon client had no socket bounds** (only the sync path did),
  so a live-but-silent daemon froze the CLI and any MCP session with it.
- `emit_via_systemd_cat` leaked a zombie per audit record when the pipe write
  failed — one PID per preview and execute until the process table filled.
- `mergeMcpServers` treated an unreadable config the same as malformed JSON
  and then overwrote it, discarding the user's other MCP servers.
- The `unattended-upgrades` helper was missing `NEEDRESTART_MODE=a`.

### Changed

- The concurrency invariant that a reboot-required action must be gated was a
  `debug_assert!`, compiled out of released binaries; it is now a fail-closed
  runtime check.
- `tests/e2e/ubuntu-command-validity.sh` checks that the commands SysKnife
  would run on Ubuntu exist and parse. Against Ubuntu 24.04.4: 33 pass, 0
  fail, 2 skipped (auditd and fail2ban are not installed on a server image).

### Documentation

- Corrected comment rot the review surfaced: the audit-chain formula omitted
  its `ROW_DOMAIN` prefix (an independent verifier copying it would never
  reproduce a valid signature); the journald watermark documented a 64-char
  SHA-256 hash where the field is a 128-char Ed25519 signature; the journal
  module stated FSS tamper protection as automatic when it is opt-in; an MCP
  test comment credited the approval interlock to advisory prompt text rather
  than the receipt check that enforces it; and `apt.rs` described a
  `fuser /var/lib/dpkg/lock` pre-flight that never existed.

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
