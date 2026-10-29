# Assurance Case

This document argues that SysKnife meets its security requirements. Each
claim names the code that carries it and the test that fails when that code
stops doing its job. [SECURITY.md](https://github.com/lacs-project/sysknife/blob/main/SECURITY.md) describes the enforcement
layers in full; this page connects them to the threats they answer, the design
principles they apply, and the common weaknesses they counter.

Scope: the two binaries a release ships, `sysknife` (the CLI and the planner)
and `sysknife-daemon`, installed with `npx sysknife-setup` or `make install`.
The desktop app under `apps/sysknife-shell` is paused and no release ships it.

Citations take the form `path::symbol`. `tests/release/assurance-case.test.sh`
fails when a cited file disappears or stops containing the cited symbol, so a
rename has to update this page in the same pull request.

## Security requirements

| Id | Requirement |
|---|---|
| R1 | Only a typed action from the catalogue reaches the host. The model never supplies a command line. |
| R2 | A caller runs only the actions its role permits. |
| R3 | A mutating action runs once, after an authorised human approves the exact action that was previewed. The one exception has to be armed twice, on purpose. |
| R4 | Every parameter that reaches a command is validated at the daemon boundary. |
| R5 | Every action leaves a signed audit record that anyone holding the public key can verify. |
| R6 | A release can be traced to the source commit and the workflow that built it. |

## Threat model

The asset that matters most is root on the managed host. The daemon runs as
the unprivileged `sysknife` account, and that account holds sudo grants which
are root-equivalent by design (see the Security Model in SECURITY.md). After
that: the integrity of the audit trail, the operator's LLM provider keys, and
the integrity of what a release ships.

| Actor | Entry point | What they control |
|---|---|---|
| The language model, or anyone who can put text in front of it | The plan the model proposes; host text that query tools return to it (package descriptions, unit names, log lines) | The proposal, and nothing past it |
| A local user | The daemon's Unix socket | Requests; their Linux groups decide their role |
| A remote client | The vsock transport | Requests, with a pre-shared token |
| Someone on the network path | Provider HTTPS, remote Postgres, audit forwarding | Traffic |
| A contributor | Pull requests | Code and workflow changes |
| A dependency's publisher | crates.io, npm, GitHub Actions | Code SysKnife builds and runs |

Trust boundaries, from [Architecture & Trust Boundaries](architecture.md):
model to planner, planner to daemon (the socket), daemon to the privileged
helpers it calls through sudo, daemon to its store, and CI to the release.

## Claims and evidence

### The planner cannot execute anything (R1)

`sysknife-brain` depends on `sysknife-core` and `sysknife-types` alone
(`crates/sysknife-brain/Cargo.toml`) and starts no process. It returns a plan;
the daemon is the only component that runs commands. ADR
[0001](adr/0001-system-boundaries.md) fixes that split.

### The model cannot invent an action (R1)

An action name the model proposes must appear in
`crates/sysknife-brain/src/planning_tools/propose_plan.rs::KNOWN_ACTIONS`, or
planning fails. The daemon checks again on its side:
`crates/sysknife-daemon/src/policy.rs::action_allowed` returns `false` for any
action its policy table does not list, whatever the caller's role.
Per-distribution fences such as
`crates/sysknife-core/src/action_family.rs::FEDORA_ONLY_ACTIONS` keep one
family's actions out of the other family's prompt.

Tests: `crates/sysknife-brain/src/action_name.rs::unknown_action_rejected`,
`crates/sysknife-brain/src/planning_tools/propose_plan.rs::unknown_action_name_is_rejected`,
`crates/sysknife-daemon/src/policy.rs::unknown_action_denied_for_all_roles`.
`crates/sysknife-daemon/tests/action_consistency.rs` keeps the planner's
catalogue and the daemon's in step.

### The daemon authorises each request by role (R2)

The kernel attests the caller's uid through `SO_PEERCRED`
(`crates/sysknife-daemon/src/auth.rs`), the daemon maps the caller's groups to
a role (`crates/sysknife-daemon/src/auth.rs::role_for_group`), and each action
carries a minimum role derived from its risk level
(`crates/sysknife-daemon/src/policy.rs::min_role_for_action`). A receipt issued
to one account does not let another account execute.

Tests: `crates/sysknife-daemon/src/policy.rs::observer_cannot_call_medium_or_high_risk_actions`,
`crates/sysknife-daemon/src/policy.rs::dev_cannot_call_high_risk_actions`,
`crates/sysknife-daemon/tests/transaction_ownership.rs::a_different_account_cannot_execute_with_a_stolen_receipt`.

### Approval is single-use and bound to the preview (R3)

A mutating action needs a preview, then an approval receipt, then an execute
request carrying that receipt. The daemon checks the receipt against the signed
commitment in constant time
(`crates/sysknife-daemon/src/transactions.rs`, the `ct_eq` on the receipt
digest), and one database transaction verifies it, marks it consumed and moves
the transaction to running, so a second or concurrent execute gets
`stale_approval`. Unattended execution needs both `--dangerously-skip-approval`
and `SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT=1`, and the signed record says no human
approved.

Tests: `crates/sysknife-daemon/src/transactions.rs::approved_receipt_is_required_and_consumed_once`,
`crates/sysknife-daemon/src/audit_chain.rs::approval_receipt_framing_is_injective`.

### Parameters are validated where they enter the daemon (R4)

Every parameter passes a `validated_*` function in
`crates/sysknife-daemon/src/actions/validate.rs` before any command uses it.
`crates/sysknife-daemon/src/actions/validate.rs::validated_safe_arg`, the
general case, refuses an empty or oversized value, a leading `-`, and any
character outside letters, digits and `. _ : / + @ -`. The daemon builds each
command's argument vector itself; a parameter never passes through a shell.

The privileged helpers in `packaging/` (`sysknife-*-edit`,
`sysknife-action-steps`) screen their own input as well, because the sudo
grant lets the `sysknife` account call them directly, past the daemon.

Tests: `crates/sysknife-daemon/src/actions/validate.rs::safe_arg_rejects_starts_with_dash`,
`crates/sysknife-daemon/src/actions/validate.rs::safe_arg_rejects_every_shell_metacharacter`,
`crates/sysknife-daemon/src/actions/validate.rs::safe_arg_rejects_oversized_input`,
and the helper screens in `tests/release/helper-anchoring.test.sh`,
`tests/release/log-edit.test.sh` and `tests/release/sudoers-edit.test.sh`.
ClusterFuzzLite runs `fuzz/fuzz_targets/validators.rs`,
`fuzz/fuzz_targets/action_spec.rs`, `fuzz/fuzz_targets/daemon_request.rs` and
`fuzz/fuzz_targets/frame_recv.rs` on pull requests that touch `crates/`, and a
validator that accepts a value outside its documented contract fails the
fuzzer even without a crash.

### The audit trail is signed and verifiable (R5)

Each transaction row joins an Ed25519-signed hash chain
(`crates/sysknife-daemon/src/audit_chain.rs`), and `sysknife audit verify`
walks it. [The Audit Chain](the-audit-chain.md) documents the format. The chain
detects a modified or reordered row. It cannot, by itself, detect removal of
the newest rows; that needs a checkpoint in an independent store
(`SYSKNIFE_CHECKPOINT_DB`), which SECURITY.md describes and which the default
deployment does not configure.

Tests: `crates/sysknife-daemon/src/transactions.rs::verify_detects_tampered_summary`,
`crates/sysknife-daemon/src/checkpoint_sink.rs::anchor_once_refuses_to_launder_a_tampered_chain`.

### Host text reaching the model is fenced off (R1)

Text a query tool brings back from the host is stripped of invisible
characters and wrapped in an `<untrusted_tool_output>` envelope
(`crates/sysknife-brain/src/sanitize.rs`), and any envelope tag inside it is
neutralised (`crates/sysknife-brain/src/sanitize.rs::neutralise_envelope_tags`)
so the text cannot close its own envelope. What the operator reads before
approving goes through
`apps/sysknife-cli/src/operator_text.rs::operator_safe_block`. The model can
still be persuaded by plain words inside the envelope; the claims above are
what stop a persuaded model from doing anything outside the catalogue, the
caller's role and the operator's approval.

Test: `crates/sysknife-brain/src/sanitize.rs::envelope_wraps_with_tool_name`.

### Network connections are encrypted and verified, with one gap

Provider calls go over HTTPS through rustls, which verifies certificates and
offers TLS 1.2 and 1.3 alone. A remote Postgres store below `sslmode=verify-ca`
is refused (`crates/sysknife-daemon/src/pg_tls.rs`). The gap: audit
forwarding sends RFC 5424 syslog over UDP in clear text, tracked in
[#728](https://github.com/lacs-project/sysknife/issues/728).

Tests: `crates/sysknife-daemon/src/pg_tls.rs::a_remote_tcp_url_with_sslmode_disable_is_refused`,
`crates/sysknife-daemon/src/pg_tls.rs::a_remote_tcp_url_with_sslmode_prefer_is_refused`.

### Releases trace back to their source (R6)

`.github/workflows/release.yml` attests build provenance and an SBOM for each
binary through Sigstore, publishes npm with provenance, and builds from a
signed tag. [Release Process](release.md) shows how to verify a download, and
SECURITY.md how to verify the tag. Byte-for-byte reproducibility is not there
yet: [#726](https://github.com/lacs-project/sysknife/issues/726).

## Secure design principles

Saltzer and Schroeder's principles, and where SysKnife applies or departs from
each.

| Principle | In SysKnife |
|---|---|
| Economy of mechanism | One dispatcher path for every action, and a typed catalogue in place of command strings. The catalogue is large, so `crates/sysknife-daemon/tests/action_consistency.rs` keeps its two copies equal. |
| Fail-safe defaults | An action the policy does not list is denied for every role. A remote Postgres without certificate verification is refused. An unreadable checksum pin aborts the installer. |
| Complete mediation | The daemon checks role and receipt on every execute request, whatever the CLI already checked. |
| Open design | MIT code, a CC0 specification (`lacs-project/specification`), and a public security model. Security rests on keys (the audit signing key, the vsock token), not on the code staying secret. |
| Separation of privilege | Execution needs two things from two parties: a role the kernel attests, and a human approval bound to the previewed action. |
| Least privilege | The daemon runs as `sysknife`, not root, under `ProtectSystem=yes` with two writable paths (`packaging/sysknife-daemon.service`), and its sudo grants name helpers and verbs instead of a shell. The departure, stated in SECURITY.md: package installation through those grants is root-equivalent. |
| Least common mechanism | Planner and daemon are separate processes built from separate crates; the planner links no executor. |
| Psychological acceptability | The preview names the exact action and its risk level before anything runs, `--dry-run` plans without a daemon, and the unattended mode takes two deliberate switches. |

## Common weaknesses countered

| CWE | Weakness | Countered by | Test |
|---|---|---|---|
| CWE-78 | OS command injection | Daemon-built argument vectors; `validated_*` at the boundary | `crates/sysknife-daemon/src/actions/validate.rs::safe_arg_rejects_every_shell_metacharacter`; the validator fuzz target |
| CWE-88 | Argument injection | A leading `-` refused in every free-form parameter | `crates/sysknife-daemon/src/actions/validate.rs::safe_arg_rejects_starts_with_dash`, `crates/sysknife-daemon/src/actions/snap.rs::snap_install_rejects_leading_dash_name` |
| CWE-22 | Path traversal | Helpers confine writes to their own roots | `tests/release/log-edit.test.sh` |
| CWE-269 | Improper privilege management | Grants per helper; `GrantSudoAccess` refuses shell-equivalent passwordless grants | `tests/release/sudoers-edit.test.sh` |
| CWE-862 | Missing authorization | Role check in the daemon on every request | `crates/sysknife-daemon/src/policy.rs::observer_cannot_call_medium_or_high_risk_actions` |
| CWE-294 | Authentication bypass by capture-replay | Single-use receipts, bound to an account | `crates/sysknife-daemon/tests/transaction_ownership.rs::a_different_account_cannot_execute_with_a_stolen_receipt` |
| CWE-367 | Time-of-check time-of-use race | Receipt check, consumption and state change in one database transaction | `crates/sysknife-daemon/src/transactions.rs::approved_receipt_is_required_and_consumed_once` |
| CWE-347 | Improper verification of a cryptographic signature | Ed25519 chain, verified row by row | `crates/sysknife-daemon/src/transactions.rs::verify_detects_tampered_summary` |
| CWE-208 | Observable timing discrepancy | `ct_eq` on the vsock token (`crates/sysknife-daemon/src/auth.rs`) and on receipt digests | None; the code pointer is the evidence |
| CWE-1427 | Improper neutralization of input used for LLM prompting | The untrusted-output envelope, and the catalogue, role and approval checks after the model | `crates/sysknife-brain/src/sanitize.rs::envelope_wraps_with_tool_name`, `crates/sysknife-brain/src/action_name.rs::unknown_action_rejected` |
| CWE-295 | Improper certificate validation | rustls defaults; `verify-ca` for remote Postgres | `crates/sysknife-daemon/src/pg_tls.rs::a_remote_tcp_url_without_sslmode_is_refused` |
| CWE-798 | Use of hard-coded credentials | trufflehog on every pull request and push; GitHub push protection; `scripts/check_no_secrets.sh` in the opt-in pre-commit hook ([#653](https://github.com/lacs-project/sysknife/issues/653) moves it into CI) | `tests/release/no-secrets.test.sh` |
| CWE-319 | Cleartext transmission of sensitive information | HTTPS to providers; audit forwarding is the open gap | [#728](https://github.com/lacs-project/sysknife/issues/728) |

## Known gaps

The Known Limitations table in SECURITY.md lists what the design does not
cover today. The open items from this review: clear-text audit forwarding
([#728](https://github.com/lacs-project/sysknife/issues/728)), releases that do
not reproduce byte for byte
([#726](https://github.com/lacs-project/sysknife/issues/726)), and the planner's
dependency boundary, which ADR 0001 states and no test enforces.
