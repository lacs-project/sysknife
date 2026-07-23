# Audit storage and recovery

SysKnife's durable transaction audit log has two backends:

- **SQLite** is the default at `/var/lib/sysknife/daemon.sqlite`. It is suitable
  for a single host when that file and its audit key are backed up.
- **PostgreSQL** is recommended when audit history must survive a host loss or
  be centralized. The live contract is tested against PostgreSQL 17.

Journald and optional RFC 5424 syslog forwarding are complementary operational
signals. They are best effort and are not the database of record.

## PostgreSQL configuration

```toml
[storage]
backend = "postgres"
url = "postgres://sysknife:${PG_PASSWORD}@db.example.com:5432/sysknife_audit?sslmode=verify-full"

[storage.pool]
max_connections = 8
acquire_timeout_secs = 10
statement_cache_capacity = 100
```

Use a dedicated database and role. The role currently needs connection,
schema usage/create, and DML privileges because the daemon applies migrations
at startup. Do not grant cluster administration or access to unrelated
databases. Store the URL in a root-readable environment file or secret
manager, not in a world-readable config file.

On startup, the daemon:

1. Opens a transaction and takes a PostgreSQL advisory transaction lock.
2. Creates `schema_migrations` if needed.
3. Applies each pending migration once and records its version.
4. Refuses to start if the database schema is newer than the binary.

The CI contract verifies migration idempotence, approval claims, history, and
hash-chain validation against a live PostgreSQL server.

Transaction-mode PgBouncer deployments may require
`statement_cache_capacity = 0`. CockroachDB is not currently supported: its
PostgreSQL wire compatibility does not include the migration and concurrency
semantics SysKnife relies on.

## Provider notes

Use a writer endpoint and TLS certificate verification wherever the provider
supports it.

| Provider | Endpoint guidance |
|---|---|
| AWS RDS / Aurora PostgreSQL | Use the writer endpoint with `sslmode=verify-full` and the AWS CA bundle. Do not use an Aurora reader endpoint. |
| GCP Cloud SQL / AlloyDB | Prefer the Auth Proxy or connector sidecar; connect to its loopback endpoint. |
| Azure Database for PostgreSQL | Use Flexible Server with `sslmode=verify-full` and the current Azure CA chain. |
| Supabase | Direct port 5432 supports prepared statements. For a transaction-mode pooler, set the statement cache to 0. |
| Neon | Use TLS; increase `acquire_timeout_secs` if scale-to-zero cold starts exceed the default. |
| Self-hosted PostgreSQL | Use `verify-full`, a private network, restricted role, monitored storage, and tested backups. |

Provider CA bundles and authentication behavior change. Verify current
provider documentation during deployment rather than copying a stale
certificate URL from this guide.

## SQLite backup and restore

Back up the database and audit key together. The key defaults to
`/var/lib/sysknife/audit-key` and should remain mode `0600`.

```bash
sudo systemctl stop sysknife-daemon
sudo sqlite3 /var/lib/sysknife/daemon.sqlite \
  ".backup '/var/backups/sysknife/daemon.sqlite'"
sudo install -m 0600 /var/lib/sysknife/audit-key \
  /var/backups/sysknife/audit-key
sudo systemctl start sysknife-daemon
```

Restore both files while the daemon is stopped, preserve ownership and modes,
then run `sysknife doctor` and `sysknife audit verify`. A database restored
without its matching key cannot validate new signatures against the original
key identity.

## PostgreSQL backup and restore

For production, enable provider-managed point-in-time recovery and retention
appropriate to your incident-response policy. Also take a logical backup
before every SysKnife upgrade that introduces a migration.

```bash
pg_dump --format=custom --no-owner --file=sysknife-audit.dump "$DATABASE_URL"
createdb sysknife_restore_test
pg_restore --no-owner --dbname=sysknife_restore_test sysknife-audit.dump
```

Restore into an isolated database first. Point a temporary SysKnife config at
that database, provide a copy of the matching audit key, then verify:

```bash
XDG_CONFIG_HOME=/tmp/sysknife-restore-config \
SYSKNIFE_AUDIT_KEY_PATH=/secure/restore-test/audit-key \
  sysknife audit verify

XDG_CONFIG_HOME=/tmp/sysknife-restore-config sysknife doctor
```

The temporary config's `[storage]` URL must target the isolated restore, never
the production database.

Do not claim recoverability until a timed restore drill has succeeded and its
recovery point and recovery time are recorded. Database backups and audit-key
backups should have separate access controls so compromise of one system does
not silently permit forged history.

## Forwarding and retention

- The transaction database is authoritative for preview, approval, execution,
  status, and chain history.
- The safety-fence JSONL file records plans rejected before daemon execution.
- Journald receives safety-fence events and audit-chain watermarks where
  available.
- UDP syslog forwarding can lose, reorder, or duplicate messages. Treat it as
  alerting telemetry, not a durable copy.

Define retention, deletion authorization, backup encryption, restore testing,
and SIEM ingestion before production use. Monitor daemon startup failures,
database capacity, backup age, restore-test age, and chain verification.
