# Storage Backend — Cloud Postgres Reference

SysKnife supports two audit-log backends, selected at daemon startup:

- **SQLite** (default) — single-file local database. **Recommended only for
  testing and sandboxing.** The audit log dies with the host: no off-box
  durability, nothing to forward to a SOC, no centralised retention.
- **Postgres** — managed or self-hosted. **Recommended for production.**

Set the backend in `~/.config/sysknife/config.toml` or via environment
variables before starting the daemon. `npx sysknife-setup` configures the
MCP integration, not the storage backend.

```toml
[storage]
backend = "postgres"
url     = "postgres://sysknife:${PG_PASSWORD}@db.example.com:5432/sysknife_audit?sslmode=require"

[storage.pool]
max_connections          = 8
acquire_timeout_secs     = 10
statement_cache_capacity = 100   # set to 0 for transaction-mode pgbouncer / CockroachDB
```

The same code path serves every supported cloud — only the URL and a couple
of pool knobs change.

## Provider URL reference

### AWS RDS for PostgreSQL + Aurora PostgreSQL

```text
postgres://<user>:<pass>@<id>.<region>.rds.amazonaws.com:5432/<db>?sslmode=verify-full&sslrootcert=/etc/sysknife/rds-global-bundle.pem
```

- Use **`verify-full`** in production. Ship the AWS global CA bundle
  (`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`) so
  cert rotation doesn't break clients.
- **Aurora**: writer endpoint = `<cluster>.<region>.rds.amazonaws.com`.
  Reader endpoint (`<cluster>-ro.<region>.rds.amazonaws.com`) is read-only —
  audit log INSERTs against it fail with
  `cannot execute INSERT in a read-only transaction`.
- **IAM auth** is supported but the 15-minute token lifetime requires a
  rebuild of `PgConnectOptions` per connection — for now use password auth
  with a Secrets Manager rotation job (Phase 2 issue tracks IAM refresh).

### GCP Cloud SQL for PostgreSQL + AlloyDB

**Direct (public IP):**

```text
postgres://<user>:<pass>@<public-ip>:5432/<db>?sslmode=verify-ca&sslrootcert=server-ca.pem&sslcert=client-cert.pem&sslkey=client-key.pem
```

**Auth Proxy / Connector (recommended):** run `cloud-sql-proxy` (or AlloyDB
connector) as a sidecar. Daemon connects to `127.0.0.1:5432` with
`sslmode=disable` because the proxy already terminates mTLS.

```text
postgres://<user>:<pass>@127.0.0.1:5432/<db>?sslmode=disable
```

IAM auth requires the proxy/connector — IAM tokens cannot be passed in a
raw connection string.

### Azure Database for PostgreSQL — Flexible Server

```text
postgres://<user>:<pass>@<server>.postgres.database.azure.com:5432/<db>?sslmode=verify-full&sslrootcert=/etc/sysknife/azure-digicert-g2.pem
```

- TLS 1.2+ required. Azure rotated the **intermediate CAs** under DigiCert
  Global Root in Q1 2026; the recommended trust set is **DigiCert Global
  Root CA + DigiCert Global Root G2 + Microsoft RSA Root Certificate
  Authority 2017** simultaneously, or ship the full Azure root bundle.
- **Microsoft Entra (Azure AD) tokens** supported. Token TTL ~1h; the same
  per-connection rebuild pattern as RDS IAM applies (Phase 2).

### Supabase

**Direct (port 5432, full prepared-statement support):**

```text
postgres://postgres:<pass>@db.<ref>.supabase.co:5432/postgres?sslmode=require
```

**Pooler (Supavisor, port 6543, transaction mode):**

```text
postgres://postgres.<ref>:<pass>@aws-0-<region>.pooler.supabase.com:6543/postgres?sslmode=require
```

When using the **pooler**, set `statement_cache_capacity = 0` in
`[storage.pool]` — transaction-mode PgBouncer rejects sqlx's named prepared
statements. The 5432 endpoint accepts the default cache.

### Neon

```text
postgres://<user>:<pass>@ep-<id>.<region>.aws.neon.tech/<db>?sslmode=require
```

- Auto-suspend means the first connection after idle has 300–800 ms cold
  start. Set `acquire_timeout_secs = 30` and Neon-specific traffic will
  succeed without flaky retries.
- Pooled endpoint (`-pooler` host suffix) supports protocol-level prepared
  statements as of 2025; sqlx's default cache works there too.

### CockroachDB Cloud (Postgres wire-compatible)

```text
postgres://<user>:<pass>@<cluster>.cockroachlabs.cloud:26257/<db>?sslmode=verify-full&sslrootcert=cc-ca.crt&options=--cluster%3D<cluster-id>
```

- Port is **26257**, not 5432.
- Set `statement_cache_capacity = 0` — CockroachDB schema-change
  invalidation can collide with sqlx's per-connection cache.
- `40001` retries are serializable-isolation aborts; sqlx surfaces them as
  errors. SysKnife's audit-log writer is single-row INSERT, so this is rare,
  but client retries are recommended if the pattern emerges.

### Heroku Postgres

```text
postgres://<user>:<pass>@<host>.compute.amazonaws.com:5432/<db>?sslmode=require
```

Standard plans serve self-signed certs → `verify-full` will fail. Use
`sslmode=require` (encryption without verification). For `verify-full`,
upgrade to **Enhanced Certificates** (publicly-signed ISRG certs).

### Self-hosted

```text
postgres://<user>:<pass>@<host>:5432/<db>?sslmode=verify-full[&sslrootcert=...]
```

You decide. Default to `verify-full` with a configurable `ca_file`. Allow
`sslmode=disable` only when the host is loopback.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `SSL connection is required` | Add `?sslmode=require` (or stronger) to the URL. |
| `certificate verify failed: unable to get local issuer` | `verify-full` set without a CA on path. Either `sslrootcert=...` in the URL, or relax to `sslmode=require`. |
| `prepared statement "sqlx_s_1" already exists` | Transaction-mode PgBouncer (Supabase pooler / some self-hosted setups) or CockroachDB. Set `statement_cache_capacity = 0`. |
| `cannot execute INSERT in a read-only transaction` | URL points at an Aurora reader or a CockroachDB follower. Use the writer/cluster endpoint. |
| First write hangs ~600 ms intermittently | Neon scale-to-zero cold start. Raise `acquire_timeout_secs` to 30. |

## Choosing between SQLite and Postgres

Pick **Postgres** unless you have a specific reason to keep audit history
on the host. Configure it in `~/.config/sysknife/config.toml` or with
environment variables before starting the daemon. The daemon validates the
URL by attempting a connection and surfaces TLS / firewall / DNS errors
before it begins normal operation.
