# Contributing to SysKnife

> **Want help. Want it loud, want it tested, want it shippable.** New
> contributors are the lifeblood of this project — we'd rather merge a
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

## High-impact areas

These are where contributions move the needle the most. Each links to a
"good first issue" cluster on the issue tracker.

| Area | Why it matters | Difficulty |
|---|---|---|
| **Ubuntu LTS support** ([tracker](https://github.com/lacs-project/sysknife/issues?q=is%3Aopen+label%3Aubuntu)) | Ubuntu 24.04 (noble) is validated with the full story suite; 22.04 (jammy) and 26.04 (resolute) are smoke-tested with the same multi-LTS VM tooling but not yet run against the full suite. `ubuntu-vm.sh` accepts `UBUNTU_RELEASE=jammy\|noble\|resolute`. Remaining: E2E exec stories, additional apt / snap / ufw actions. | Medium |
| **Distro detection coverage** ([tracker](https://github.com/lacs-project/sysknife/issues?q=is%3Aopen+label%3Adistro-detection)) | Robust `/etc/os-release` parsing for every LTS we claim to support. Pure-function tests, no integration mocks. | Easy |
| **Action catalogue gaps** | Add a typed action (e.g. `EnableFirewallZone`) — small, isolated, every PR includes the policy entry + risk level + tests. | Easy |
| **E2E story coverage** | Real prompts, real LLM, real daemon. We have ~10 stories; we want 100+ across both distros. | Medium |
| **GUI polish (Tauri shell)** | TypeScript + React. Real OSS UX, not a thin wrapper around the daemon. | Medium |
| **Demo recording on real hardware** | Replace the bundled demo GIF with a 30-second recording on real Silverblue / Ubuntu 26.04. | Easy (and visible) |
| **Translations** | i18n for the shell. Spanish, German, Japanese, Mandarin in priority order. | Easy |

Filter the issue tracker by
[`good first issue`](https://github.com/lacs-project/sysknife/labels/good%20first%20issue)
or
[`help wanted`](https://github.com/lacs-project/sysknife/labels/help%20wanted)
to find something self-contained.

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

### 3. Commit style

Conventional Commits on the title:

```
feat(daemon): add ConfigureFirewallZone action
fix(brain): retry on transient OpenAI 5xx
docs(readme): replace demo GIF with 26.04 capture
```

Bodies should explain *why*, not *what* — the diff already says what.

### 4. Pull request

- One PR per logical change. Big multi-concern PRs get split.
- Add or update tests for any behaviour change.
- Update docs alongside the code, not in a follow-up.
- Title in Conventional Commits style — the
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
   central polkit allowlist (`packaging/50-sysknife.rules`) — the daemon
   gates D-Bus actions through one allowlist file, not one polkit rule
   per action.
5. **`validated_safe_arg` is the boundary validator.** Any new action that
   interpolates a user-provided string into a command must validate at
   the boundary, not deep inside the executor.
6. **Constant-time compares for any auth-sensitive bytes** (tokens,
   request hashes). The HI-1/HI-2/HI-19 work in PR #179 set the pattern.

If your change touches any of these, expect deeper review. That's a good
thing — it means the change is load-bearing.

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

The full contributing guide — every nuance, every edge case, every
"why we do it this way" — lives at
[`docs/contributing/CONTRIBUTING.md`](docs/contributing/CONTRIBUTING.md).

Questions? Open a
[GitHub Discussion](https://github.com/lacs-project/sysknife/discussions).
