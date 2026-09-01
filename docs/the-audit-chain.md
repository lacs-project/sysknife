# The Audit Chain

Every mutating action SysKnife's daemon runs is recorded in a forward,
Ed25519-signed hash chain. This page covers what is recorded, how the chain
proves tamper and reorder, why the signature scheme is asymmetric rather
than a shared-secret MAC, how signed checkpoints close the one gap a hash
chain cannot close on its own, and how to verify all of it yourself —
independently of the daemon that wrote it. If you are evaluating SysKnife
for a security-sensitive deployment, this is the page to try to break.

## What gets recorded

Each row in the transaction table captures the decision the daemon made about
one action, at the moment it made it. `sysknife history` renders a subset;
`caller_role`, `caller_principal` and `event_tip` are chain fields, read with
`sysknife audit export` (or directly from the database) and checked with
`sysknife audit verify`:

| Field | What it commits to |
|---|---|
| `seq` | Monotonic position in the chain |
| `key_id` | Which signing key generation wrote this row |
| `transaction_id`, `request_id` | Identifiers for the preview/approve/execute round-trip |
| `request_hash` | Commitment to the exact request that was previewed |
| `action_name`, `risk_level` | The action and its policy-assigned risk tier |
| `summary` | Human-readable description of the planned action |
| `approval_id` | Which signed approval receipt authorized execution, if any |
| `warnings_json` | Warnings surfaced to the user before approval |
| `created_at` | When the row was written |
| `caller_role` | Which privilege tier the daemon resolved for the connection that asked |
| `caller_principal` | **Which account** asked: `uid:<n>`, `token:vsock`, or `none:unattributed` |
| `event_tip` | The approval-event chain tip at insert time (see below) |

These fields are serialized into a stable, self-describing byte
string (tag + value pairs, with a prefix-free escape scheme so no field's
content can be crafted to alias another field's boundary), then signed. The
count is per encoding, because the field set grew: v1 signs eleven pairs, v2
fourteen, v3 fifteen — the fields above plus the `chain_version` tag that names
the encoding (see below). The
resulting signature *is* the row's `chain_hash` — there is no separate hash
step, because Ed25519 already commits to the message.

```admonish note title="What is deliberately excluded"
The mutable `status` column (queued → running → succeeded/failed/rolled
back) is **not** part of the signed content. The chain protects the
*authorization decision* captured at insert time, not the live execution
state — a scope decision, not an oversight (see [Limits](#limits-and-honest-scope)).
```

```admonish info title="Three row encodings coexist"
The signed field set grew twice, and each row records which encoding it was
signed under in its `chain_version` column:

| Version | Added | Since |
|---|---|---|
| 1 | the base fields | before v0.2.13 |
| 2 | `caller_role`, `event_tip` | v0.2.13 |
| 3 | `caller_principal` | 0.3.0 |

Verification reproduces the exact encoding each row claims, so an upgraded
daemon appends v3 rows onto a chain that already holds v1 and v2 rows and the
whole thing still verifies in one walk. An upgrade never makes a healthy audit
log look tampered, and older rows are never backfilled: writing a principal
into a row that was signed without one would change the message it was signed
over and report the chain as broken.

The version is not a hiding place in either direction. Relabelling a v3 row as
v2 to erase which account acted makes verification re-encode it without the
principal, so the stored signature no longer verifies. A v3 row whose principal
is missing or blank is reported as broken rather than accepted, because it
claims an encoding that names an account while naming none.
```

```admonish tip title="Role versus principal"
They answer different questions and the distinction is the point of v3.
`caller_role` says **what was permitted**; on a host with two admins it cannot
separate them. `caller_principal` says **which account asked**.

The scheme prefix is signed along with the value because the strength of the
evidence differs: `uid:1000` was attested by the kernel through `SO_PEERCRED`,
while `token:vsock` only proves that someone could read the pre-shared token
file. A bare string would erase that difference. `none:unattributed` appears when the daemon could
not establish an account: `SO_PEERCRED` failed, or returned no usable pid, or the
peer is not representable in the daemon's namespaces, in which case the kernel
reports the overflow uid (`nobody`) rather than failing. Recording that failure
beats inventing a uid, because a signed lie about who acted is worse than a
signed admission of ignorance.

A chain full of `none:unattributed` rows still verifies as intact, and that is
honest but incomplete, so `sysknife audit verify` reports the counts separately.
Intact is a statement about tampering, not about how much the trail can tell you.

Several different things make a row name nobody, and they are counted apart
because their remedies differ:

| Count | Meaning | What to do |
|---|---|---|
| `attributed_rows` | The row's **signed** principal names an account: a non-empty value under the `uid` or `token` scheme that this build can read back as one the daemon could have written. | Nothing, but see the uid caveats above, and remember `token:vsock` proves possession of a file rather than an account. |
| `unattributed_rows` | The row signs `none:unattributed`: the daemon tried to attribute the connection and failed. | Live problem. Check the daemon log for the connections concerned, and whether `SO_PEERCRED` can work on that host. |
| `rows_without_principal` | No principal that the signature covers, normally a row written under `chain_version` 1 or 2, before 0.3.0. | Nothing can be done. Backfilling a principal would change the bytes the signature covers, so the gap is kept rather than hidden. |
| `rows_unattested` | No principal that any signature vouches for. | **Investigate**, unless the cause is a newer encoding; see below. |
| `rows_naming_no_account` | Everything that cannot name an account, that is `rows_censused` minus `attributed_rows`. | Provided so nobody has to add the reasons up and risk missing one. |
| `rows_censused` | Rows counted, which is every row read, verified or not. | Compare with `rows_checked`: a gap means part of the trail was counted but not proven. |

All of them appear in `--json` and on the `sysknife_audit_verify` MCP tool. They
are `null`, never `0`, when the store could not be read at all: a missing
database, an unopenable one, an absent key. A store that opens and holds no rows
reports `0`, which is a different fact and now looks different. The split matters
on an upgraded database: `unattributed_rows: 0` over a chain of pre-0.3.0 rows
would otherwise read as "every action is attributed" when in fact none of them
is.

### Why `rows_unattested` exists, and why the census reads the encoding

`caller_principal` enters the signed message **only** under `chain_version = 3`.
On a v1 or v2 row the column is unsigned free space: someone with write access to
the table can set it to `uid:0` and the chain still verifies as `Intact`, because
there is no signature over that column to break. So the census buckets by the
encoding that signed the row, not by whatever the column happens to hold. A
populated principal on an encoding that does not sign it is counted as
`rows_unattested` and never as an account.

The same bucket catches a value this build cannot read back as one the daemon
could have written (`uid:notanumber`, `uid:1000:extra`, `token:not-vsock`), and a
row declaring a `chain_version` this build does not know, whose signed fields are
unknown here.

This build writes none of them, so the first two are out-of-band writes to
investigate. The third is different: a *newer* SysKnife does write rows this build
cannot read, so the remedy there is to verify with a build at least that new
rather than to open an incident.

### The counts are only as good as the verdict beside them

Verification stops at the first broken row; the census describes every row read.
When the chain verdict is not `intact` the two can therefore disagree, and the
surplus is the part of the trail this command did not vouch for. That is not the
same as proof of forgery: deleting or reordering a row breaks the link while
leaving every later signature valid, so some rows past a break are usually
authentic, and an aggregate count cannot say which. `sysknife audit verify` says
so in words rather than leaving it to be inferred:

```
BROKEN: chain intact for first 4 row(s); row seq=5 (transaction …) does not chain.
  expected: valid ed25519 signature
  actual:   9f2c…
ATTRIBUTION: 96 of 100 row(s) name an account; 4 name nobody.
  These counts describe what the rows claim, not what was proven. A break was
  detected above, so rows past it were not checked by this walk. …
```

The machine-readable side publishes `rows_censused` so the gap is measurable:
compare it with `rows_checked`, which the CLI `--json` nests under `chain` and the
`sysknife_audit_verify` tool reports as a sibling field. Read the chain's own
verdict, not the top-level `status`, when deciding whether the counts are
findings: `status` is the worst of three checks, so a broken approval-event chain
turns it `broken` while the transaction chain and its attribution are intact. The
MCP report carries `chain_status` for exactly that reason.

What a uid does *not* prove: shared logins, `su` into a service account, and uid
reuse after a user is deleted all weaken it. It identifies an account, not a
human.
```

## The hash chain: each entry links to the one before it

Every row also stores `prev_chain_hash`, and the signed message is:

```text
chain_hash = Ed25519-Sign(signing_key, ROW_DOMAIN || canonical(row_fields) || prev_chain_hash)
```

Because `prev_chain_hash` is inside the signed message, a row's signature is
only valid if it was produced with the *exact* preceding row's hash. This
gives verification two independent failure modes to catch tampering:

- **Content tamper** — edit any field of a row after the fact (e.g. change
  `summary` or `risk_level`) and its own signature no longer verifies.
- **Reorder or delete** — remove or reorder a row and the *next* row's
  `prev_chain_hash` no longer matches the actual predecessor, breaking the
  chain at that point even if every individual signature is otherwise valid.

`sysknife audit verify` walks the chain in `seq` order and reports the first
row where either check fails.

## Ed25519, not HMAC — why asymmetric matters

The signing key is a 32-byte Ed25519 seed, generated on first daemon start
and stored at `<db_dir>/audit-key` (mode `0600`, refused if group/world
readable), with `$SYSKNIFE_AUDIT_KEY_PATH` as an override for systemd
deployments. The corresponding public key is written alongside as
`<audit-key>.pub`.

This is a deliberate replacement for an earlier HMAC-SHA256 design. The
distinction matters more than it might look:

- **With a symmetric MAC (HMAC)**, the same secret both produces and checks
  the tag. Anyone able to verify the chain is, by construction, also able to
  forge it. A "verified" HMAC chain is a claim the verifier is making about
  *itself* — it convinces no one who doesn't already trust the verifier's
  custody of the secret.
- **With Ed25519**, the daemon signs with a private key that never leaves
  its host, and verification uses only the corresponding public key.
  Publishing the public key gives an auditor, a central log aggregator, or
  a customer's security team the ability to *prove* the chain is intact and
  unforged — without ever being able to forge an entry themselves. This is
  non-repudiation: a signature that verifies under the daemon's public key
  could only have been produced by whoever holds the private key.

Two more properties fall out of the implementation:

- **Domain separation.** Row signatures, checkpoint signatures, and approval
  receipts each sign under a distinct, prefix-free domain tag
  (`sysknife-audit-row-v1`, `sysknife-checkpoint-v1`,
  `sysknife-approval-receipt-v1`). A signature valid in one context can never
  be replayed as valid in another, even though the underlying key is shared.
- **Determinism.** Ed25519 (RFC 8032) is deterministic — identical inputs
  always produce the identical signature. This makes chain verification
  reproducible without any randomness or nonce bookkeeping on the verifier's
  side.

## The approval-event chain

The transaction chain records what the daemon *authorized*. It says nothing
about whether a human then approved it, whether that approval was spent, or
whether it was retracted — those lifecycle facts used to live only in
`transaction_approvals`, a plain mutable table. Deleting a row from it left
`sysknife audit verify` reporting `Intact`, which made the record that a
privileged action had been approved the one part of the trail an attacker
could erase without leaving a mark.

Approval events are now their own forward Ed25519 chain, under their own
domain tag (`sysknife-audit-event-v1`), with one row per state change:

| `kind` | When it is written |
|---|---|
| `approval_granted` | A receipt was minted for a queued transaction |
| `approval_consumed` | A receipt was spent to move a transaction to `Running` |
| `approval_revoked` | An undelivered receipt was retracted before it could be spent |

Each event and the state change it records commit in the same database
transaction, so a state change without its event (or the reverse) is not a
reachable state. Deleting an event from the middle of the chain breaks the
next event's `prev_chain_hash`, exactly as it does for transaction rows.

**Cross-chain binding.** Deleting events from the *end* of the event chain
would leave a self-consistent remainder, the same tail-truncation blind spot
the transaction chain has. That is what `event_tip` is for: every transaction
row signs the event-chain tip as of its insert. Because signed checkpoints
anchor the *transaction* chain, and transaction rows commit to event tips,
anchoring transitively covers the event chain. `sysknife audit verify`
reports the binding check alongside the two chain walks.

The residual exposure is the same bounded tail every append-only log has:
events appended after the most recent transaction row are not yet bound by
anything, until the next row is written.

## Signed checkpoints: closing the truncation gap

> **The default deployment has no anchor.** Anchoring is opt-in via
> `SYSKNIFE_CHECKPOINT_DB`, and `packaging/sysknife-daemon.service` does not set
> it, so a stock system install **cannot detect tail truncation** — the gap this
> section describes is open until you configure a sink. The daemon says so at
> startup and `sysknife audit verify` repeats it beside every verdict, because
> `OK: N rows verified` would otherwise read as "nothing was removed". Setup
> instructions are in
> [SECURITY.md](../SECURITY.md#audit-anchoring-in-the-default-deployment).

A hash chain alone cannot detect one specific attack: **tail truncation**.
If an attacker with write access to the audit database deletes the most
recent *K* rows, the remaining chain is still perfectly self-consistent —
every row's signature is valid and every `prev_chain_hash` still points to
its (now-final) predecessor. The chain walk reports `Intact`, because
nothing in the remaining rows says how long the chain used to be.

Signed checkpoints close this gap using the same idiom Certificate
Transparency uses for its logs: periodically, the daemon signs a commitment
to the current chain tip —

```text
checkpoint_signature = Ed25519-Sign(signing_key, CHECKPOINT_DOMAIN || seq || chain_tip || created_at)
```

— and anchors `(seq, chain_tip, created_at, signature)` into an independent,
append-only sink (a separate PostgreSQL database via `sysknife audit
checkpoint`). Because the checkpoint lives outside the chain it commits to,
an attacker who can edit or truncate the local chain cannot also reach back
and edit the anchored checkpoint. Verifying anchored checkpoints against the
current chain distinguishes three outcomes:

- **Consistent** — the checkpoint's `seq` is still present in the chain and
  its `chain_hash` at that `seq` matches the anchored tip.
- **Truncated** — the checkpoint's `seq` is no longer present at all (the
  chain is now shorter than a previously anchored tip proves it once was).
- **Tip mismatch (rewrite)** — the `seq` is present, but its `chain_hash`
  no longer matches what was anchored (the row was rewritten in place).

`sysknife audit checkpoint` refuses to anchor a chain that does not already
verify — it never launders a tampered chain into a signed checkpoint.

`sysknife audit verify` performs the same cross-check, read-only, whenever
`SYSKNIFE_CHECKPOINT_DB` is set. It previously reported only that an anchor was
*configured* and verified the chain against itself, which is the one thing a
truncated chain also passes: an operator who had done the work to set anchoring
up got a verdict no stronger than one who had not, and without the caveat that
warns the unanchored case. The cross-check now runs, its result appears beside
the chain verdict, and a `Truncated` or rewritten verdict fails the command
(exit 1) rather than printing under an `OK`.

Two boundary cases are deliberate. An anchor holding **no** checkpoints reports
`cannot_verify`, not `consistent` — zero checkpoints trivially satisfy "every
checkpoint agrees", and calling that success would attest to a chain nothing has
ever committed to. And because anchoring itself is implemented for the SQLite
backend only, a Postgres deployment with `SYSKNIFE_CHECKPOINT_DB` set is told so
explicitly rather than being silently skipped.

```admonish warning title="Checkpoints require an external sink"
The anti-truncation guarantee only holds if the checkpoint sink is actually
external to the host being audited. Anchoring checkpoints into the same
database the chain lives in gives no protection: an attacker with write
access to that database can delete the checkpoint row along with the
truncated chain rows. See [Audit Storage and Recovery](storage-cloud.md)
for how to configure `SYSKNIFE_CHECKPOINT_DB`.
```

## Verifying it yourself

Verification only ever needs the **public** key. You do not need daemon
access, the private signing key, or trust in the machine that produced the
log — only the exported `<audit-key>.pub` file (or its hex contents) and
read access to the transaction database.

Full chain, third-party path:

```sh
sysknife audit verify --pubkey audit-key.pub
```

### Verification is host-local, and that matters over a tunnel

`plan`, `execute`, `history` and `doctor` are daemon requests: they travel over
`SYSKNIFE_SOCKET`, which in the [VM and remote topologies](vm-daemon-setup.md)
points at another machine. **Verification is not a daemon request.** It opens the
transaction store on the filesystem of the machine you run it on.

So this sequence does not do what it looks like:

```sh
ssh -fN -L /tmp/sysknife-web01.sock:/run/sysknife/daemon.sock admin@web01
SYSKNIFE_SOCKET=/tmp/sysknife-web01.sock sysknife "install ripgrep"   # runs on web01
sysknife audit verify                                                 # reads THIS machine
```

The verdict describes your own laptop's chain. If a local store exists, which it
does on any machine that has ever run a user-mode daemon, the answer is a
confident `OK` about actions that happened somewhere else.

The command now says so whenever `SYSKNIFE_SOCKET` is set:

```text
OK: 128 row(s) verified in /home/you/.local/state/sysknife/daemon.sqlite
NOTE: SYSKNIFE_SOCKET is /tmp/sysknife-web01.sock. If that socket is forwarded
from another host (for example `ssh -L`), the actions you took ran there while
this verification read a store on this machine. Verify on the host that owns the
daemon, or copy its database and exported public key out and re-run with
--pubkey <FILE>.
```

The same string travels in `--json` output as `daemon_socket_caveat`, and on the
`sysknife_audit_verify` MCP tool's report under the same name, so an agent cannot
report a clean trail for the wrong host either.

Two correct ways to verify a remote host:

```sh
# On the host that owns the daemon
ssh admin@web01 'sudo sysknife audit verify'

# Or pull the evidence to an auditor's machine: the store plus the public key,
# never the private key
scp admin@web01:/var/lib/sysknife/daemon.sqlite  ./web01.sqlite
scp admin@web01:/var/lib/sysknife/audit-key.pub ./web01.pub
SYSKNIFE_DATABASE_PATH=./web01.sqlite sysknife audit verify --pubkey ./web01.pub
```

The second form is the auditor path the public key exists for: it proves the
chain without granting daemon access or signing ability.

Machine-readable output for CI or a SIEM pipeline:

```sh
sysknife audit verify --pubkey audit-key.pub --json
sysknife audit export --since 2026-08-01T00:00:00Z --limit 500 > audit-rows.json
```

`audit export` emits the stored transaction-chain rows as one JSON array in
ascending `seq` order. It includes both `prev_chain_hash` and the Ed25519
signature stored as `chain_hash`, so an offline consumer has the linkage and
signature bytes without opening SQLite itself. It does not invent `argv`,
`outcome`, or a separate `signature` field that the signed row never stored.
Absent optional columns are JSON `null`, while a value actually recorded as an
empty string remains an empty string.

An export inherits the confidentiality class of the audit database and is not a
redacted artifact. `request_hash` commits to the unredacted parameters as one
unsalted SHA-256, so a low-entropy value such as a Wi-Fi passphrase remains
attackable in an exported file even though the stored preview is redacted.
Handle an export like the `0600` database it came from.

Anchor and check signed checkpoints against an external database:

```sh
SYSKNIFE_CHECKPOINT_DB="postgres://user@host/checkpoints" sysknife audit checkpoint
```

Three checks run: the transaction chain, the approval-event chain, and the
binding between them. All three are reported, and any one of them can fail the
command — a clean transaction chain must never mask a tampered approval trail.

**A clean run looks like:**

```text
OK: 4128 row(s) verified in sqlite
OK: 512 approval event(s) verified
OK: 4128 row(s) still match the approval event they committed to
```

**A detected tamper looks like:**

```text
BROKEN: chain intact for first 891 row(s); row seq=892 (transaction 3f9c1a2e)
does not chain.
  expected: valid ed25519 signature
  actual:   9b1f...c02a
```

or, for a reordered/deleted row, a `prev_chain_hash` mismatch instead of a
signature mismatch — same report shape, different `expected`/`actual`
pair. Either failure is reported at the *first* broken row; rows before it
are still proven intact.

**Deleted approval events look like:**

```text
OK: 4128 row(s) verified in sqlite
OK: 300 approval event(s) verified
BROKEN: transaction seq=4128 committed to approval event 71ac…9d2f, which is
no longer in the event chain — approval events were deleted from the end of
the chain
```

Note that the event chain itself still walks clean there: truncating its tail
leaves a self-consistent remainder. The binding is what catches it.

Exit codes matter for automation: `0` intact, `1` broken (a real tamper was
detected), `2` cannot verify (missing key file, unreadable database, wrong
key generation loaded). The 1-vs-2 split is deliberate — a CI job that only
checks for a nonzero exit code must not silently treat "I couldn't check"
the same as "I checked and it's fine." When the three checks disagree, the
worst wins, and `1` outranks `2`: if anything is provably broken, saying
"could not verify" would understate what is known.

When the store cannot be read, the cross-chain binding status is
`not_checked`, not `consistent`; no transaction or approval-event rows were
available to compare.

## Limits and honest scope {#limits-and-honest-scope}

The chain is strong evidence, not a magic guarantee. Be precise about what
it does and does not prove:

- **Key custody is the trust root.** Anyone who reads the private key file
  can forge *future* entries indistinguishably from real ones. Signed
  checkpoints bound the damage to "after the compromise," since prior
  anchored tips remain unreproducible from a rewritten chain.
- **`status` is out of scope by design.** The chain protects the decision
  recorded at insert time (what was previewed, at what risk level, with
  what warnings), not later execution-status transitions. "Chain verifies"
  does not mean "the action's final status is trustworthy."
- **Truncation needs an external sink to be detectable at all.** Without a
  checkpoint anchored off-host, deleting the tail of the chain is invisible
  to `sysknife audit verify` by construction. The same applies to approval
  events appended after the last transaction row: nothing has committed to
  them yet.
- **Key rotation is manual today.** Every row carries a `key_id` (currently
  always `"v1"`); rotation means regenerating the chain from scratch until
  a planned epoch-aware rotation flow lands.
- **This is a detection control, not a prevention control.** It proves,
  after the fact, that something was altered — it does not stop the daemon
  from executing an authorized-looking but malicious action. That is the
  job of the layered authorization model in
  [`SECURITY.md`](https://github.com/lacs-project/sysknife/blob/main/SECURITY.md).

See also: [Audit Storage and Recovery](storage-cloud.md) for backend
choice, backup procedure, and restore verification; [CLI
Reference](cli.md) for the full `sysknife audit` command surface.
