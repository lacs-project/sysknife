# Security Policy

SysKnife handles privileged local system operations, so security bugs
matter.

## Reporting a Vulnerability

Please do not open a public issue for security-sensitive problems.

Use GitHub's private vulnerability reporting flow for this repository
if it is available.
If a private report is not available in your environment, contact the
maintainers privately before publishing details.

## What to Include

- a short summary of the issue
- affected action family or component
- exact reproduction steps
- expected vs actual behavior
- logs or traces, with secrets removed
- impact assessment

## What We Will Do

We will:

- acknowledge the report
- triage the issue
- work on a fix
- coordinate disclosure timing with the reporter

## Rules for Contributors

- Never paste secrets into issues or pull requests.
- Never disclose a zero-day publicly before coordination.
- Treat approval, authorization, and transaction data as sensitive.

---

## Security Model

SysKnife uses a layered enforcement model. Every layer is independent; a
bypass of one does not bypass the others.

### Layer 1 — Intent validation (sysknife-brain, before LLM call)

Every intent string is checked before it is forwarded to the LLM
provider:

- **Length cap** (`INTENT_MAX_BYTES = 2048`): intents whose byte length
  exceeds 2048 are rejected with `PlanningError::IntentTooLong`. Oversized
  payloads are almost always copy-paste accidents or injection attempts.
- **Secret scan**: the same pattern list used to guard the preferences
  file (`SENSITIVE_PATTERNS` + `SENSITIVE_PREFIXES` in
  `crates/sysknife-brain/src/prefs.rs`) is applied to the raw intent.
  Intents containing API key prefixes (`sk-`, `ghp_`, `xoxb-`, …),
  the words `password`, `token`, `api_key`, and similar are rejected
  with `PlanningError::IntentContainsSensitiveData` before any network
  call is made.
- **Rate limit** (`RateLimiter` in `crates/sysknife-brain/src/rate_limit.rs`,
  `DEFAULT_MAX_RPM = 20` in `planner.rs`): a sliding 60-second window
  caps planning requests per session. When the window is full,
  `plan_intent` and `summarize` return
  `PlanningError::RateLimitExceeded { retry_after_secs }` before any
  network call is made. The default limit is 20 requests per minute,
  applied automatically by `LlmPlanner::from_config`; override with
  `SYSKNIFE_MAX_RPM` (must be ≥ 1). Call timestamps are persisted to
  `$XDG_DATA_HOME/sysknife/rate-limit.log` so the limit survives process
  restarts.

### Layer 2 — Action name allowlist (sysknife-brain, after LLM call)

The `ActionName` newtype in `crates/sysknife-brain/src/action_name.rs`
validates every action name proposed by the LLM against `KNOWN_ACTIONS`
at the type boundary. An action name not in that list (e.g.
`"RunShellCommand"`) is rejected with `UnknownActionName` and the
planning loop returns an error. The LLM cannot invent actions.

### Layer 3 — Role-based authorization (sysknife-daemon)

The daemon resolves the caller's Linux group membership via
`SO_PEERCRED` on the Unix socket and maps it to a `CallerRole`:

| Group | Role | Can call |
|---|---|---|
| `sysknife-observer` | Observer | Read-only actions |
| `sysknife-dev` | Dev | Read + medium-risk mutations |
| `sysknife-admin` or `wheel` | Admin | All including rpm-ostree, reboot |
| `sysknife-boot` | Boot | Everything (reserved for boot-time automation) |

The per-action minimum role is a compile-time exhaustive match in
`crates/sysknife-daemon/src/policy.rs`. Unknown actions return `None` and
are denied unconditionally. The caller's role is never supplied by the
client — it is always derived server-side from kernel credentials.

### Layer 4 — Approval hash (sysknife-daemon)

Every mutating action requires a preview→approve→execute round-trip:

1. The shell requests a preview; the daemon records the action + params
   and returns a content hash.
2. The user approves (checkbox for medium risk; typed action name for
   high risk).
3. The shell sends the approval hash back to the daemon.
4. The daemon verifies `approval_hash == request_hash` before running
   anything.

A captured hash cannot be replayed: the `find_by_request_hash` query
returns only `Queued` transactions within a 15-minute TTL. Once a
transaction transitions to `Running`, `Succeeded`, or `Failed` it is
never returned, closing the replay window.

### Layer 5 — Atomic execution claim (sysknife-daemon)

Concurrent execute requests for the same transaction are blocked by an
atomic `UPDATE WHERE status = 'queued'` SQL statement
(`claim_for_execution` in `crates/sysknife-daemon/src/transactions.rs`).
Only the first request wins; the second gets `stale_approval`.

---

## Deployment — User and Group Setup

The daemon socket lives at `/run/sysknife/daemon.sock` in a directory owned
`sysknife:sysknife 0750`. A user needs two group memberships to use SysKnife:

1. **`sysknife` group** — grants access to the socket directory. Without
   this the connection is refused before any authentication happens.
2. **A role group** — determines what the user can do once connected.
   Omitting this falls back to `Observer` (read-only queries only).

```sh
# Grant a user read-only access:
sudo usermod -aG sysknife,sysknife-observer alice

# Grant a user medium-risk access (services, containers, SSH keys, flatpaks):
sudo usermod -aG sysknife,sysknife-dev alice

# Grant a user full access (rpm-ostree, reboot, kernel arguments):
sudo usermod -aG sysknife,sysknife-admin alice
```

Group changes take effect on next login. To apply without logging out:

```sh
exec newgrp sysknife
```

Members of the `wheel` group are automatically treated as `sysknife-admin`
by the daemon — no explicit `sysknife-admin` membership is needed for
existing `sudo` users. They still need the `sysknife` group to reach the
socket.

The four role groups (`sysknife-observer`, `sysknife-dev`, `sysknife-admin`,
`sysknife-boot`) are created at install time by `systemd-sysusers` via
`packaging/sysknife-sysusers.conf`.

## Audit Trail

### Safety fence log

Every plan rejected by the brain's safety fence (unknown action name,
bad risk level, etc.) is appended as a JSON line to:

```text
$XDG_DATA_HOME/sysknife/safety-audit.jsonl
~/.local/share/sysknife/safety-audit.jsonl  (fallback)
```

Each entry contains `timestamp`, `event`, `intent`, `reason`, and
`raw_plan`.

### Transaction log

Every daemon execution — queued, running, succeeded, failed, rolled
back — is recorded in a SQLite database at the path configured by
`SYSKNIFE_DATABASE_PATH` (default `~/.local/share/sysknife/daemon.sqlite`).
Query with `journalctl` (see below) or directly with `sqlite3`.

### Journald forwarding

On systemd hosts, every safety fence rejection is also forwarded to the
systemd journal as a structured log entry with these fields:

```text
SYSKNIFE_EVENT=safety_fence_rejection
SYSKNIFE_INTENT=<the user's original intent>
SYSKNIFE_REASON=<why the fence triggered>
SYSKNIFE_TIMESTAMP=<RFC 3339 UTC timestamp matching the JSONL entry>
PRIORITY=4   (LOG_WARNING)
SYSLOG_IDENTIFIER=sysknife-brain
```

Query live:

```sh
journalctl -f SYSKNIFE_EVENT=safety_fence_rejection
journalctl SYSLOG_IDENTIFIER=sysknife-brain --since today
```

### Enabling tamper-evident sealing (recommended for production)

systemd's Forward Secure Sealing (FSS) signs each journal entry with a
key that rotates forward — retrospective forgery is computationally
infeasible, and modification of any entry is detectable offline.

Enable FSS once at deployment time:

```sh
sudo journalctl --setup-keys
```

Verify log integrity at any time:

```sh
sudo journalctl --verify
```

Without FSS enabled, journald entries are still useful for querying
but are not tamper-evident. The JSONL file on disk is never
cryptographically protected regardless of FSS status.

---

## Known Limitations

These are acknowledged gaps tracked as open issues. They do not
represent exploitable vulnerabilities in normal use — the downstream
enforcement layers cap their blast radius — but they are relevant for
security certification work.

| Gap | Issue | Notes |
|---|---|---|
| Tool output injection | [#98](https://github.com/lacs-project/sysknife/issues/98) | `query_*` results re-enter the LLM context unsanitized. A crafted service description or package name could attempt prompt injection. Impact is bounded by Layer 2–5. |
| Action param validation | — | Action params are typed per-handler but not validated at a shared schema boundary. A compromised LLM could propose valid action + malicious params (e.g. `AddAuthorizedKey` with an attacker-controlled key). |
