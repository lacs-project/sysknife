# Contributing to SysKnife

Thank you for your interest in SysKnife. Contributions of all sizes are
welcome — from typo fixes to new action families to multi-distro
support. This document explains how to go from idea to merged PR.

## Licensing

SysKnife is released under the **MIT License**. By submitting a pull request
you agree that your contribution will be included under the same MIT terms.

No CLA is required. Optionally, sign off your commits with
`git commit -s` to add a DCO line (`Signed-off-by: Your Name <email>`)
as a lightweight record of your agreement to the Developer Certificate of Origin
(<https://developercertificate.org>).

If you have questions, open a
[Discussion](https://github.com/lacs-project/sysknife/discussions) — we would
rather answer questions than lose a contributor to a misunderstanding.

---

## Before You Start

1. Read the [architecture overview](../architecture.md) to understand
   the four-crate structure and the trust boundary.
2. Read the [developer guide](../developer-guide.md) for prerequisites
   and build instructions.
3. Read the [testing guide](testing.md) for which tests to run and when.
4. Check [open issues](https://github.com/lacs-project/sysknife/issues)
   to avoid duplicating work in progress.
5. For any substantial change, open an issue first and describe what
   you want to build. This prevents wasted effort and keeps the
   architecture coherent.

## Finding Something to Work On

- **`good first issue`** — well-scoped, clear acceptance criteria, and
  a good way to learn the codebase. Start here if this is your first
  contribution.
- **`help wanted`** — higher-impact tasks where outside help is
  especially welcome.
- **`security`** — security issues take priority over everything else.
  See [SECURITY.md](../../SECURITY.md) for the disclosure process.

High-impact areas where contributions are most needed:

- Multi-distro action families (apt / dnf / pacman)
- Integration test hardening against a real daemon socket
- Broader LLM provider support and model testing
- Demo recording on real Silverblue hardware

## Setting Up Your Development Environment

```sh
git clone https://github.com/lacs-project/sysknife
cd sysknife

# Install git hooks (once)
pip install pre-commit
pre-commit install

# Install frontend dependencies
cd apps/sysknife-shell && pnpm install && cd ../..

# Run all tests to verify everything works
cargo nextest run --workspace --locked
cd apps/sysknife-shell && pnpm test && pnpm exec tsc --noEmit && cd ../..
```

See [docs/developer-guide.md](../developer-guide.md) for the full
list of prerequisites (Rust, Node.js 20, pnpm, Tauri system deps).

## Filing Issues

Use one of the issue templates on GitHub. Every issue should have:

- **Title**: one-sentence summary in imperative mood
- **Why**: context and motivation
- **Where**: file paths and function names when known
- **Acceptance criteria**: concrete, testable conditions for "done"

Do not open issues for questions — use GitHub Discussions or tag the
issue with `question`.

## Pull Request Workflow

### 1. Branch

Create a focused branch from a fresh `main`:

```sh
git fetch origin
git checkout -b <issue-number>-<short-slug> origin/main
# Example: git checkout -b 42-apt-action-family origin/main
```

Keep one branch per issue. For larger changes, use a git worktree
to keep your main checkout clean:

```sh
git worktree add ~/.config/superpowers/worktrees/sysknife/<branch-name> -b <branch-name>
```

### 2. Implement

Follow TDD:

1. Write the failing test first.
2. Run it and confirm it fails for the right reason.
3. Write the minimal implementation that makes it pass.
4. Refactor with the tests green.

Keep changes small and reviewable. If a PR does two unrelated things,
split it.

### 3. Check Locally

```sh
# Required before every push
cargo fmt --all --check
cargo clippy --workspace --all-features --locked -- -D warnings
cargo nextest run --workspace --locked

# Frontend
cd apps/sysknife-shell && pnpm test && pnpm exec tsc --noEmit && cd ../..

# All pre-commit hooks
pre-commit run --all-files
```

For changes touching the brain, planning tools, or the prompt:

```sh
# Run the read-only E2E stories (requires a running daemon + LLM)
ANTHROPIC_API_KEY=sk-ant-... tests/e2e/dev-stories.sh
```

### 4. Open the PR

Target `main`. Use the PR template:

```markdown
## Summary

One paragraph on what and why. Reference the issue: Closes #N.

## Changes

- bullet list of what changed

## Test plan

- [ ] what to verify manually
- [ ] what the automated tests cover
```

Title format: `type(scope): short description` — for example:
`feat(daemon): add apt install action`.

Add the `e2e` label if your change touches the brain, daemon IPC,
or the action catalogue — this triggers the CI smoke test.

### 5. Review

Every PR requires at least one review before merge.

- Address every review comment with code or a documented reason not to.
- Do not merge around an unresolved finding.
- CI must be green before merge.
- After merge, delete the remote and local branch.

## Commit Style

Follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): message`

| Type | When |
|---|---|
| `feat` | New user-visible feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `chore` | Build, CI, tooling |
| `test` | Tests only |
| `refactor` | No behavior change |

Subject line under 72 characters. Add a body for non-obvious changes.

## How to Add a New Daemon Action

1. Add the action name to `KNOWN_ACTIONS` in
   `crates/sysknife-brain/src/action_name.rs`.
2. Add the execution spec to
   `crates/sysknife-daemon/src/executor.rs` (`build_action_spec`).
3. Add the preview logic to
   `crates/sysknife-daemon/src/preview.rs` (`preview_action`).
4. Add the rollback spec (if applicable) to
   `crates/sysknife-daemon/src/executor.rs` (`rollback_spec_for`).
5. Add input validation to
   `crates/sysknife-daemon/src/actions/validate.rs`.
6. Add an entry to the system prompt's action catalogue in
   `crates/sysknife-brain/src/prompt.rs` (name, description, params,
   risk level).
7. Write unit tests for the preview and execution logic.
8. Write or extend an E2E story if the action is user-facing.

Keep each step atomic and reviewable as a separate commit if the
implementation is large.

## How to Add an E2E Story

E2E stories live in `tests/e2e/`. Each story is a shell script that:

1. Calls `sysknife --dry-run --json "<intent>"` and captures the plan.
2. Parses the resulting JSON plan.
3. Asserts that the correct action names, risk levels, and parameters
   are present.

Rules for story assertions:

- Assert exact action names — do not accept a superset.
- Assert risk levels — they are part of the contract.
- Never weaken an assertion to accept wrong model behavior.
  If the model produces a bad plan, fix the prompt, not the test.

Run stories locally before opening a PR:

```sh
ANTHROPIC_API_KEY=sk-ant-... tests/e2e/dev-stories.sh <story-number>
```

## Code Standards

- No dead code. Remove superseded workarounds immediately.
- No fallback flags or "just in case" parameters — every line must
  be reachable and load-bearing.
- Prefer explicit types and explicit error handling over `unwrap`.
- Preserve the trust boundary: the daemon is the only privileged
  executor. Brain and shell must not touch the system directly.
- Preserve approval, audit, and rollback semantics on every action.

### Security-sensitive areas

Changes to the following require the `security` label on the PR and
extra reviewer scrutiny:

| Area | File(s) | Why sensitive |
|---|---|---|
| Intent validation | `crates/sysknife-brain/src/planner.rs` (`INTENT_MAX_BYTES`, guards in `plan_intent`) | First line of defense before any LLM call |
| Secret patterns | `crates/sysknife-brain/src/prefs.rs` (`SENSITIVE_PATTERNS`, `SENSITIVE_PREFIXES`) | Controls what the planner and prefs storage will reject |
| Action allowlist | `crates/sysknife-brain/src/action_name.rs` (`KNOWN_ACTIONS`) | Adding a name here makes it proposable by the LLM |
| Role policy | `crates/sysknife-daemon/src/policy.rs` (`min_role_for_action`) | Governs which groups can execute which actions |
| Approval / replay | `crates/sysknife-daemon/src/transactions.rs` | Hash freshness and TOCTOU protection |
| Caller auth | `crates/sysknife-daemon/src/dispatcher.rs` (`resolve_caller_role`) | SO_PEERCRED group-to-role mapping |
| Audit log | `crates/sysknife-brain/src/audit.rs`, `crates/sysknife-brain/src/journal.rs` | Safety fence record and journald forwarding |

When adding a new action to `KNOWN_ACTIONS`, you must also:

1. Add it to `min_role_for_action` in `policy.rs` with the correct
   minimum role. Omitting it causes the daemon to deny the action for
   all callers with a validation-failure error — an obvious regression,
   but better than a silent allow.
2. Add it to the action catalogue in `crates/sysknife-brain/src/prompt.rs`
   with a correct risk level. The LLM uses this catalogue to decide
   what to propose; a wrong risk level produces wrong approval gates.

## Questions

Open a [GitHub Discussion](https://github.com/lacs-project/sysknife/discussions)
or tag your issue with `question`. We are friendly and genuinely want
to help new contributors succeed.
