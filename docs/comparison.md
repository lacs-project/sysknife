# SysKnife vs. the alternatives

Letting an AI operate a Linux host is now a real category, and several tools
address it. This page is an honest map of that space and where SysKnife sits in
it. The short version: most tools either **filter shell strings** or **watch
after the fact**. SysKnife removes the shell string entirely, gates execution
with a hard interlock, and produces an audit trail anyone can verify with a
public key.

## At a glance

| | generic `mcp-shell` / mcp-firewall | AIShell-Gate | gate-oc-audit | MCP traffic gateways | **SysKnife** |
|---|---|---|---|---|---|
| What the AI emits | shell strings (allowlisted) | typed JSON commands | nothing (observe-only) | proxied MCP calls | **typed semantic actions** |
| Blocks execution on the host | policy filter | yes | **no** (advisory) | at the proxy, not the host | **yes — server-enforced interlock** |
| Audit scheme | logs | **HMAC-SHA256 (symmetric)** | Merkle tree + optional chain anchor | logs / immutable trails | **Ed25519 (asymmetric)** |
| Third-party verifiable | no | **no** — verifier holds the secret | via an external network | varies | **yes — public key alone** |
| Automatic rollback | no | no | no | no | **yes (rpm-ostree)** |
| License | OSS | **proprietary** | Apache-2.0 (audit only) | OSS | **MIT** (spec is CC0) |

The two things nobody else pairs: **public-key-verifiable audit** and
**automatic rollback**. Everything below explains why those matter.

## Typed actions beat string allowlists

The common design is to let the model produce a shell command and then gate that
string with an allowlist or regex. Published red-team work ("GuardFall") found
that the large majority of agents can talk their way past such guards — the
guard is filtering a language rich enough to hide intent.

SysKnife takes the string out of the loop. The model proposes **typed actions**
from a fixed catalog; the daemon builds the command internally and is the sole
executor. There is no shell string to smuggle a payload into. See
[Typed Actions](typed-actions.md) for the mechanism.

## Public-key audit beats symmetric audit

An audit trail is only worth what its verification proves. SysKnife signs the
hash chain with **Ed25519**: verification needs only the **public** key, so a
third party — an auditor, a customer, a court — can confirm the log is intact
and was produced by the holder of the private key, and the signer cannot later
deny it. See [The Audit Chain](the-audit-chain.md).

Symmetric schemes (HMAC-SHA256, as used by AIShell-Gate) use one shared secret
for both signing and verifying. Whoever can verify can also forge, so a "valid"
log convinces no one who did not already hold the secret. It is a good integrity
check for yourself; it is not non-repudiable evidence for anyone else.

## Automatic rollback

On atomic hosts (Fedora/Silverblue via `rpm-ostree`), a failed change is
automatically reverted to the prior deployment. No other tool in this space
does this. Be aware of the scope limit: **on Ubuntu/apt there is no automatic
rollback yet** — SysKnife still gates and audits, but does not undo package
changes. That scope limit is enforced, not just documented: every catalogued
action's `rollback_available` flag is tested against the actual rollback
mechanism, so a Debian-family action (PPAs, netplan, GRUB kargs, Ubuntu Pro
attach/detach included) cannot claim automatic rollback it doesn't have, even
when it happens to have an obvious manual inverse. See
[Automatic Rollback](automatic-rollback.md).

## Open beats closed — especially here

A security and audit tool you cannot read is a contradiction: you are asked to
trust the thing whose entire job is to be trustworthy. SysKnife is **MIT**, the
LACS protocol it implements is **CC0**. You can read the gate, self-host it,
fork it, and verify every claim on this page against the source.

## The field, honestly

- **AIShell-Gate** — the closest peer: typed JSON commands, a hash-chain audit,
  a confirmation model, and an executor-separation design much like SysKnife's
  daemon boundary. But it is **proprietary and license-required**, and its audit
  is **HMAC-SHA256** (symmetric; by its own documentation, with no persistent
  key set, post-hoc verification is not possible). No automatic rollback.
- **gate-oc-audit** (Apache-2.0) — a genuinely good **audit-only** layer:
  tamper-evident records via a Merkle tree, optionally anchored to an external
  network. It validates that this category matters. It does not gate or execute
  and does not roll back — it observes.
- **MCP traffic gateways** (agentgateway, MCPX, Obot, mcp-firewall, and others)
  — these govern the **protocol stream**: routing, authn/z, threat detection,
  and audit at the proxy. They are complementary to SysKnife, not competitive:
  none execute typed actions on the host or roll changes back. You can run
  SysKnife behind one.
- **generic `mcp-shell` servers** — hand the model a shell with an allowlist.
  Lowest friction, weakest guarantee (see the GuardFall result above).

## When SysKnife is the wrong tool

Being honest about the fit:

- You want the AI to run **arbitrary** commands and accept the risk — a generic
  `mcp-shell` server is lower friction. SysKnife's typed catalog is finite by
  design; operations outside it are not (yet) available.
- You only need **observability**, not enforcement — a pure audit layer like
  gate-oc-audit is lighter.
- Your fleet is **Ubuntu/apt and you require automatic rollback today** — that
  is roadmap, not shipped (gate + audit work now).

If you want the AI to change a Linux box while a human stays in control and
every action is provably recorded, that is exactly what SysKnife is for.
