# The Audit Chain

Every mutating action SysKnife's daemon runs is recorded in a forward,
Ed25519-signed hash chain. This page covers what is recorded, how the chain
proves tamper and reorder, why the signature scheme is asymmetric rather
than a shared-secret MAC, how signed checkpoints close the one gap a hash
chain cannot close on its own, and how to verify all of it yourself —
independently of the daemon that wrote it. If you are evaluating SysKnife
for a security-sensitive deployment, this is the page to try to break.

## What gets recorded

Each row in the transaction table (`sysknife history`) captures the decision
the daemon made about one action, at the moment it made it:

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

These eleven fields are serialized into a stable, self-describing byte
string (tag + value pairs, with a prefix-free escape scheme so no field's
content can be crafted to alias another field's boundary), then signed. The
resulting signature *is* the row's `chain_hash` — there is no separate hash
step, because Ed25519 already commits to the message.

```admonish note title="What is deliberately excluded"
The mutable `status` column (queued → running → succeeded/failed/rolled
back) is **not** part of the signed content. The chain protects the
*authorization decision* captured at insert time, not the live execution
state — a scope decision, not an oversight (see [Limits](#limits-and-honest-scope)).
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

## Signed checkpoints: closing the truncation gap

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

Machine-readable output for CI or a SIEM pipeline:

```sh
sysknife audit verify --pubkey audit-key.pub --json
```

Anchor and check signed checkpoints against an external database:

```sh
SYSKNIFE_CHECKPOINT_DB="postgres://user@host/checkpoints" sysknife audit checkpoint
```

**A clean run looks like:**

```text
OK: 4128 row(s) verified in sqlite
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

Exit codes matter for automation: `0` intact, `1` broken (a real tamper was
detected), `2` cannot verify (missing key file, unreadable database, wrong
key generation loaded). The 1-vs-2 split is deliberate — a CI job that only
checks for a nonzero exit code must not silently treat "I couldn't check"
the same as "I checked and it's fine."

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
  to `sysknife audit verify` by construction.
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
