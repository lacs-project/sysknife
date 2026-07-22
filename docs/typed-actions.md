# Typed Actions

Every AI-driven system administration tool has to answer one question: what,
exactly, is the model allowed to make the machine do? Most answer it with an
allowlist or a regex over a shell command string. SysKnife answers it
differently — the model is never given a channel to produce a shell string
in the first place.

## Why string allowlists fail

The independent security research known as **GuardFall** tested AI coding
agents against shell-command guardrails — allowlists and regex filters
applied to the command string the model was about to run — and found that
**10 of 11 agents could be talked into bypassing them**. That is not a bug in
any one guard; it is a structural property of the approach. A string
allowlist has to anticipate every syntactic trick (quoting, encoding,
command substitution, argument smuggling, alias/function shadowing) a
sufficiently motivated or merely creative model can produce, in a language —
shell — that was designed to make exactly those tricks easy. Filtering a
dangerous language after the fact is an arms race you don't get to stop
fighting.

SysKnife's answer is architectural, not defensive: don't give the model the
dangerous language at all.

## The model: typed actions, not shell strings

The brain (`sysknife-brain`) runs the LLM in a tool-use loop against a single
terminal tool, `propose_plan`. That tool's schema is built from
`KNOWN_ACTIONS` in `crates/sysknife-brain/src/planning_tools/propose_plan.rs`
— a fixed, named list of actions such as `InstallPackages`, `StartService`, or
`AptUpdate`, each with a one-line description of its purpose and parameters.
The model can only emit one of these names plus a small parameter object; it
has no field, anywhere in the schema, into which a shell string fits.

```admonish note title="What the model can never do"
There is no `run_command`, no `exec`, no free-text field that reaches a
shell. The typed catalogue *is* the model's entire vocabulary for changing
the system. If an action isn't in the catalogue, the model cannot request it
— it can only fall back to a different, already-typed action, or tell the
user it can't do that.
```

Every proposed action name is checked against `ActionName::parse` before a
plan leaves the brain — this is the safety fence referenced throughout the
codebase. On the daemon side (`sysknife-daemon`), each action is backed by an
`ActionSpec` (`crates/sysknife-daemon/src/actions/mod.rs`) that pins down:

| Field | What it fixes |
|---|---|
| `mechanism` | Exactly one privileged operation: a `Command` with a fixed `program` and a typed argument list, or a scoped `FileWrite` / `FilePatch` / `FileDelete` / `FileScan` |
| `risk_level` | `Low`, `Medium`, or `High` — drives approval UX and policy |
| `reboot_required` | Whether the daemon should warn the caller before proceeding |
| `rollback_available` | Whether a failure triggers automatic rollback |

As of this writing the catalogue defines **182 actions** across families such
as Deployment, Services, Package Layering, Flatpak, Containers, Toolbox,
Network, Identity, SSH Keys, Package Repositories, apt/snap/ufw/netplan/grub
(Debian-family), and rpm-ostree/AppArmor/cloud-init/Pro (Fedora-family). Each
family is also fenced by distro: `crates/sysknife-core/src/action_family.rs`
is the single source of truth for which actions are Debian-only versus
Fedora-only, and that list is shared — not duplicated — across the brain's
prompt construction, the CLI's routing guard, and the daemon's execution
fence, specifically so the three can never silently drift apart.

The daemon is the sole executor and the sole authority. It does not trust the
brain's judgment about parameters — every `ActionSpec`'s mechanism is
re-validated against the actual request before anything runs. A typed action
name plus a parameter object cannot be turned into an arbitrary command line,
because the daemon, not the model, decides which program and argv shape that
action maps to.

## A concrete example

Say a user asks something that sounds routine but is actually destructive:

> "Clean up old kernels, I'm low on disk space."

An allowlist-guarded shell agent has to decide, in the moment, whether
whatever command string it's about to construct is safe — and a determined
or confused model can dress up something worse as "cleanup." SysKnife never
gets to that fork. The brain can only propose the one typed action that
matches this intent:

```json
{
  "action_name": "CleanupDeployments",
  "params": {}
}
```

The daemon looks up `CleanupDeployments` in its catalogue and finds:
`risk_level: High`, `reboot_required: false`, `rollback_available: false` —
because this action permanently deletes the rollback and pending deployments
(`sudo rpm-ostree cleanup --rollback --pending`), it destroys the very safety
net that would undo it. That fact isn't something the model asserts and the
daemon has to believe; it's a property of the fixed `ActionSpec` the daemon
already owns. The risk level and the missing rollback both surface in the
approval prompt before anything executes.

## Composing with approval and rollback

A typed action alone is not the whole safety story — it's the piece that
determines *what can be requested at all*. What happens to a request after
it's typed is covered elsewhere:

- Every preview the daemon issues must be approved before it can be executed,
  and every mutating action — including its risk level and the approval that
  authorized it — is recorded in a forward, Ed25519-signed hash chain. See
  [The Audit Chain](the-audit-chain.md).
- When an action whose `ActionSpec` carries `rollback_available: true` fails,
  the daemon executes its rollback automatically, in the same job, before the
  caller ever sees a terminal result. See
  [Automatic Rollback](automatic-rollback.md).

Typed actions are what make both of those guarantees possible to state
precisely: the audit chain can name an exact `action_name` and `risk_level`
because those are fixed catalogue facts, not free text extracted from a
shell command after the fact; automatic rollback can look up "is there a
rollback for this" because the mapping from action to rollback action is a
lookup table, not a heuristic.

## The tradeoff, honestly

Typed actions are a closed catalogue. If an operation isn't in it, the model
cannot perform it — full stop, no escape hatch. That is the entire point,
but it has a real cost:

- **Adoption cost.** Every new operation SysKnife should support requires an
  engineer to add an `ActionSpec`, wire its mechanism, decide its risk level,
  and — if applicable — its rollback. This is slower than "the model can run
  any command it comes up with."
- **Coverage gaps.** A user's request that doesn't map to any action in the
  catalogue gets a "I can't do that yet" rather than a best-effort shell
  command. `docs/ubuntu-action-gap-analysis.md` tracks known gaps in the
  Debian/Ubuntu action set as one example of this in practice.

SysKnife accepts this tradeoff deliberately: a finite, auditable vocabulary
that the daemon fully understands is worth more than an open-ended one the
daemon can only try to filter.
