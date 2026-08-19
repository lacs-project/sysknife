# Contributing to SysKnife

> **Want help. Want it loud, want it tested, want it shippable.** New
> contributors are the lifeblood of this project. We would rather merge a
> small, well-tested PR than a giant one that needs three rounds of
> review.

## TL;DR

```sh
git clone https://github.com/lacs-project/sysknife
cd sysknife
pip install pre-commit && pre-commit install
cd apps/sysknife-shell && pnpm install && cd ../..

# Run the whole suite (≈ 90s)
cargo nextest run --workspace --locked

# Make a change, open a PR. Conventional Commits style on the title.
```

A PR that passes CI, has tests, and follows the
[trust-boundary rules](docs/architecture.md) is on track.

---

## Where the effort goes right now

**Ubuntu is the active target**, across 22.04, 24.04 and 26.04. Live-VM
evidence, action coverage and security review all point at the Debian-family
path first.

Fedora Atomic 41+ stays eligible and its rpm-ostree, Flatpak and toolbox action
families still pass. It is deprioritized, not dropped, and what it needs is a
current validation run rather than new code. See
[docs/distro-support.md](docs/distro-support.md).

**GUI work is paused.** The Tauri shell under `apps/sysknife-shell/` stays in
the tree and must keep building, so workspace gates still cover it, but it is
not where contributions are wanted today. Please pick something else from the
table below.

## High-impact areas

| Area | Why it matters | Difficulty |
|---|---|---|
| **Ubuntu LTS support** | All three LTS releases are validated against the full story suite on a live VM, each with a committed replay twin that reproduces it: 22.04, 24.04 and 26.04 all at 79/79. `ubuntu-vm.sh` accepts `UBUNTU_RELEASE=jammy\|noble\|resolute`. Remaining: story coverage for the cross-family actions, and five Debian-only ones that still have none: the four fail2ban actions and `GrubSetKargs`. | medium |
| **Distro detection coverage** | Robust `/etc/os-release` parsing for every release we claim to support. Pure-function tests against real fixture files, no integration mocks. The existing fixtures at the bottom of `crates/sysknife-core/src/distro.rs` show the shape. | easy |
| **Action catalogue gaps** | Add a typed action (for example `EnableFirewallZone`). Small and isolated, and every PR carries the policy entry, the risk level and the tests. | easy |
| **E2E story coverage** | Real prompts, real LLM, real daemon. The suite is 133 stories: 54 atomic + 79 Ubuntu. Every Debian-only action now has one. What is left is the cross-family middle: of the action names available on both families, 59 are still untouched by any story, plus 10 Fedora-only and 5 Ubuntu-only ones. See #233 for the clustered map. | medium |
| **Fedora Atomic validation** | The action families exist and `DistroId::is_supported()` returns true for Atomic 41 and up. Nobody has run `tests/e2e/atomic-vm.sh` against a current release. Needs Fedora Atomic hardware or a VM host. | tedious |
| **Demo recording on real hardware** | Replace the bundled demo GIF with a 30-second recording on real Ubuntu 26.04 with rollback visible. | easy |

## Finding something to work on

Issues carry a difficulty label: `easy`, `medium`, `hard` or `tedious`. Filter
the tracker by
[`good first issue`](https://github.com/lacs-project/sysknife/labels/good%20first%20issue)
or [`help wanted`](https://github.com/lacs-project/sysknife/labels/help%20wanted)
to find something self-contained. If the tracker looks thin, open an issue
describing what you want to work on and we will scope it with you.

No CLA and no copyright waiver. The project is MIT.

## Workflow

### 1. Pick or open an issue

For anything substantial, open an issue first. We'll triage and confirm
the design direction before you sink time into a PR. For tiny fixes
(typos, comment improvements, a missing test), skip the issue and go
straight to a PR.

### 2. Branch, code, test

```sh
git checkout -b feat/<short-name>
# … implement …
cargo nextest run --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

**TDD is the project rhythm.** Write the failing test first, watch it
fail, then write the minimum code to make it pass. The test suite is the
contract.

**Adding or removing a Rust test moves a published figure.** The suite size lives
in `tests/evidence/workspace-tests.json`, and `README.md`,
`docs/introduction.md` and `docs/distro-support.md` state it in prose. Regenerate
the artifact and update those three files in the same commit:

```sh
UPDATE_TEST_BASELINE=1 scripts/test_baseline.sh
grep -rn 'Rust tests' README.md docs/introduction.md docs/distro-support.md
```

CI gates both halves, so bumping the artifact alone turns `docs-and-hygiene` red
after `rust` goes green.

**Which release your change lands in.** While SysKnife is in the `0.y` series, a
change that breaks a consumer moves the middle digit and everything else moves the
last one. [docs/release.md](docs/release.md#version-numbering) carries the rules
and the criteria for 1.0.0. Say so in your PR description when you remove or
rename a public item, so it goes out in the right release.

### 3. Commit style

Conventional Commits on the title:

```
feat(daemon): add ConfigureFirewallZone action
fix(brain): retry on transient OpenAI 5xx
docs(readme): replace demo GIF with 26.04 capture
```

Bodies should explain *why*. The diff already says what.

### 4. Pull request

- One PR per logical change. Big multi-concern PRs get split.
- Add or update tests for any behaviour change.
- Update docs alongside the code, not in a follow-up.
- Title in Conventional Commits style. The
  [`semantic-pull-request`](https://github.com/amannn/action-semantic-pull-request)
  CI check enforces this.
- Sign off your commits if your employer asks for DCO; we don't require
  it but we accept it.

### 5. Review

Every PR gets a review pass + a sonnet code-reviewer agent dispatch
(automatic). Security-sensitive PRs (privilege boundary, IPC, validators,
audit chain) also get a red-team agent dispatch. Aim for review turnaround
under 48h; ping in the PR if you've been waiting longer.

## Trust-boundary rules

These are non-negotiable. A PR that breaks them is rejected on principle.

1. **The brain (`sysknife-brain`) MUST NOT make privileged calls.** It
   talks to the LLM and proposes typed actions. That's it.
2. **The shell (`sysknife-shell`) MUST NOT execute actions.** It renders
   plans and captures approval. The daemon executes.
3. **The daemon (`sysknife-daemon`) accepts only typed actions over IPC.**
   No shell strings, no eval, no JSON-RPC method that takes raw command
   bytes.
4. **Every privileged action ships with a risk level and a transaction-store
   row.** Any new D-Bus interaction it requires must be added to the
   central polkit allowlist (`packaging/50-sysknife.rules`). The daemon
   gates D-Bus actions through one allowlist file, not one polkit rule
   per action.
5. **`validated_safe_arg` is the boundary validator.** Any new action that
   interpolates a user-provided string into a command must validate at
   the boundary, not deep inside the executor.
6. **Constant-time compares for any auth-sensitive bytes** (tokens,
   request hashes). The HI-1/HI-2/HI-19 work in PR #179 set the pattern.

If your change touches any of these, expect deeper review. That means the
change is load-bearing.

## Reporting security issues

For privilege escalation, auth bypass, audit-chain forgery, or data
exposure, follow [`SECURITY.md`](SECURITY.md) instead of opening a public
issue. We'll triage privately and credit you in the public advisory once
fixed.

## Code of Conduct

Be kind. Be precise. Disagree on technical merit, never on the person.
Project enforces the
[Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Long-form

The full contributing guide, with every nuance and every "why we do it this
way", lives at
[`docs/contributing/CONTRIBUTING.md`](docs/contributing/CONTRIBUTING.md).

Questions? Open a
[GitHub Discussion](https://github.com/lacs-project/sysknife/discussions).
