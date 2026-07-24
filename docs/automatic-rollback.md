# Automatic Rollback

Automatic rollback is one of SysKnife's two hard differentiators (the other
is the [approval-gated, hash-chained audit log](mcp.md)). This page describes
exactly what it does, the mechanism behind it, and — just as importantly —
where it does **not** apply yet.

## What "automatic rollback" means

When the daemon executes a mutating action and that action's process exits
non-zero (or fails to launch), the dispatcher checks two things before
returning a result to the caller:

1. Did the job land in `JobState::Failed`?
2. Does the executed [`ActionSpec`](https://github.com/lacs-project/sysknife)
   carry `rollback_available: true`?

Both conditions are evaluated in `attempt_rollback_if_needed` in
`crates/sysknife-daemon/src/dispatcher.rs`. If both hold, the daemon looks up
a rollback `ActionSpec` for the failed action name via
`executor::rollback_spec_for` and executes it immediately, in the same job,
before the client ever sees a terminal result. There is no separate "approve
the rollback" step — a failed rollback-eligible action rolls back
automatically as part of finishing that job.

If the rollback command itself succeeds, the job transitions to
`JobState::RolledBack` and the `JobResult` carries a `rollback_ref` describing
what was reverted. If the rollback command also fails, the job stays
`Failed` and the response tells the caller the system may need manual
intervention — SysKnife does not retry indefinitely or attempt a different
recovery path.

```admonish note
Rollback only fires for actions the daemon has *positively* marked
rollback-eligible. Read-only queries, additive actions like `AddUserToGroup`,
and `RollbackDeployment` itself (to avoid recursion) are excluded by
construction — `rollback_spec_for` returns `None` for them.
```

**The flag is an equivalence, not a hint, and it's enforced by a test.**
`ActionSpec.rollback_available` means exactly one thing: *the daemon will
automatically revert this action if it fails*. It does not mean "there
happens to be another action that manually undoes this one" — an action can
be perfectly reversible by hand (e.g. `RemovePpa` undoes `AddPpa`) while still
reporting `rollback_available: false`, because undoing it requires the
operator or agent to explicitly issue that second call; the daemon does not
do it for them on failure. `rollback_available_matches_rollback_spec_for_all_actions`
in `crates/sysknife-daemon/src/executor.rs` asserts, for **every** action in
`actions::all_specs()` — not a hand-picked subset — that
`spec.rollback_available == rollback_spec_for(action_name).is_some()`. An
action can't claim automatic rollback it doesn't have, or fail to claim
rollback it does have, without breaking that test.

## The mechanism: `rpm-ostree rollback`

On rpm-ostree-based systems (Fedora Atomic / Silverblue), every mutation to
the base OS is an atomic deployment: the tree that boots next is a new,
separate deployment, and the previously active deployment is retained until
explicitly cleaned up. This gives SysKnife a rollback target it doesn't have
to construct itself.

`rollback_spec_for` in `crates/sysknife-daemon/src/executor.rs` maps every
rollback-eligible action to the same recovery command,
`rpm-ostree rollback`, which swaps the pending deployment back to the one
that was active before the failed action ran:

- `UpdateSystem`
- `InstallPackages`, `RemovePackages`
- `RebaseSystem`
- `SetKernelArguments`
- `AddLayeredPackage`, `RemoveLayeredPackage`, `ReplaceLayeredPackage`,
  `ResetLayeredPackageOverride`, `RemoveBasePackage`

All of these are rpm-ostree deployment mutations — they change what will boot
next, not the currently running root. That's what makes reverting them a
single, well-defined operation instead of an attempt to undo an arbitrary set
of file writes. No pre-change snapshot has to be staged by SysKnife itself:
rpm-ostree's deployment history already holds the "before" state, and
`rollback` is rpm-ostree's own primitive for restoring it.

Some rollback-eligible actions (`RebaseSystem`, `SetKernelArguments`, layered
package changes) also require a reboot to take effect either way — rollback
restores the deployment that will be booted, not a running-process state.

## Honest scope: Ubuntu/apt has no automatic rollback yet

```admonish warning
On Ubuntu and other Debian-family systems, SysKnife does **not** perform
automatic rollback. `apt` operations mutate the live filesystem directly —
there is no equivalent to an rpm-ostree deployment to revert to. SysKnife
still enforces the approval gate and still writes a hash-chained audit
record for every `apt` action, including failures, but a failed `AptInstall`
or `AptUpgrade` is left as-is. Nothing in `rollback_spec_for` maps a
Debian-family action name to a rollback command — the function returns
`None` for all of them, and `DEBIAN_ONLY_ACTIONS` in
`crates/sysknife-core/src/action_family.rs` contains no rollback actions at
all. Every Debian-family/Ubuntu-only `ActionSpec` accordingly reports
`rollback_available: false`, including ones with an obvious manual inverse —
`AddPpa`/`RemovePpa`, `NetplanSet`, `GrubSetKargs`, and `ProAttach`/
`ProDetach` can all be undone by hand (running the paired action, or another
`NetplanSet`/`GrubSetKargs` call), but none of that is automatic, so none of
them set the flag.
```

This matches `docs/distro-support.md`, which states plainly: *"Atomic
rollback applies to rpm-ostree deployment changes. Ubuntu package operations
are mutable and cannot offer equivalent deployment rollback."* Do not
describe SysKnife as rolling back Ubuntu package state in any other doc —
today it gates and audits `apt`, it does not revert it.

## Interaction with the audit chain

Rollback outcomes are not a side channel — they go through the same paths as
every other job result:

- The job's terminal status is written via `update_terminal_status`, so a
  successful rollback lands in the `transactions` table as
  `JobState::RolledBack`, not `Failed`. A query over the audit log shows the
  full story: the action was attempted, it failed, and it was reverted.
- The daemon forwards a status-change event to the configured SIEM sink
  (`forward_status_change_event`) so `RolledBack` is visible to external
  monitoring, not just the local database.
- The `JobResult` returned to the client includes `rollback_ref` (currently
  the literal string `"rpm-ostree rollback"`) so the caller — CLI, MCP tool,
  or GUI — can show what was reverted.

One nuance worth knowing: the Ed25519 hash chain in
`crates/sysknife-daemon/src/audit_chain.rs` signs the **immutable fields**
captured when a transaction row is first inserted (the authorization
decision — who approved what, at what risk level). `status` is a mutable
column and is explicitly excluded from the signed payload — see the
"Status mutations are not in the chain" note in `audit_chain.rs`. That means
a completed rollback is durably recorded and forwarded, but the chain's
tamper-evidence guarantees cover the fact that the risky action was approved,
not the specific fact that it was later rolled back. If your threat model
needs the status transition itself to be tamper-evident, that's tracked as
future work (an append-only `audit_events` table), not something SysKnife
claims today.

## See also

- [Distro Support](distro-support.md) — full support matrix and per-family
  caveats.
- [MCP Server](mcp.md) — how `sysknife_execute` surfaces `rollback_ref` to an
  AI assistant.
- [Architecture](architecture.md) — the planning/presentation/execution
  boundary that rollback lives inside.
