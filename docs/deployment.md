# Deployment and Migration Runbook

This runbook covers deploying the server, applying migrations at startup,
rollback limits, backups, retention, and recovery from failed startup.

## Required production configuration

Production startup fails before the listener opens unless the deployment is
safe. `internal/config` returns `config.ErrUnsafeProductionConfig` when any of
these is true:

- `GOWEB_SESSION_COOKIE_SECURE` is not `true`.
- `GOWEB_PUBLIC_URL` does not use `https`.
- `GOWEB_DATABASE_URL` is unset.
- `GOWEB_SESSION_SECRET` is unset (and it must be at least 32 characters).
- `GOWEB_EMAIL_CONFIRMATION_REQUIRED` is `true` but `GOWEB_MAIL_RELAY` is unset.

Every environment also rejects a credential-bearing public URL, a malformed
mail relay, an invalid `GOWEB_TRUSTED_PROXY`, and bootstrap administrator
values in production. See [README configuration](../README.md#configuration)
for the full variable table and the
[bootstrap administrator procedure](bootstrap-admin.md) for first-admin
provisioning. Secret values are redacted from diagnostics and must come from the
platform secret store, never from the repository.

## Deployment order

1. Confirm the release build passes CI and the production environment satisfies
   the required configuration above.
2. Take a database backup (see [Backups](#backups)) and record the current
   migration version shown on `/{language}/admin/system`.
3. Build and publish the new binary from that revision:
   `go build -o bin/goweb ./cmd/web`.
4. Start the new process. Startup order is fixed:
   - `internal/config` validates the environment.
   - `internal/store` opens PostgreSQL and applies pending migrations.
   - `internal/app` composes the dependency graph and seeds the optional
     bootstrap administrator (non-production only).
   - `internal/server` opens the listener and begins accepting requests.
   - the maintenance worker starts with the signal context.
5. Poll `GET /healthz` until it returns `200`. Confirm the migration ledger on
   `/{language}/admin/system` reports the expected versions.
6. Shift traffic to the new instance. Run one instance per migration at a time;
   the runner serializes itself with a PostgreSQL advisory lock.
7. Stop the previous instance with `SIGTERM` so `internal/server` drains active
   requests, then closes registered dependencies.

## Startup migrations

- Migrations live in `migrations/` with sortable
  `NNNNNN_description.up.sql` names.
- Startup records installed versions in the `schema_migrations` ledger, takes a
  transaction-scoped advisory lock, and applies every pending migration inside a
  single transaction. A failure rolls the whole batch back, so the schema is
  never left half-migrated.
- Installed migrations are tracked by version and description parsed from the
  file name; a renamed, renumbered, or removed installed migration is rejected
  with `store.ErrMigrationDrift`. Drift detection keys on the file name, so
  never edit the SQL of an installed migration — add a new forward migration
  instead.
- A migration failure or drift error exits the process non-zero and the database
  handle is closed. The instance never serves requests against a partially
  migrated or drifted schema.
- The migration runner is forward-only. The repository contains only
  `.up.sql` files.

## Rollback limits

- There are no down migrations and no automatic schema rollback. Rolling back
  the binary does not revert the schema.
- An application rollback is only safe when the previous binary tolerates the
  new schema. Additive changes (new nullable columns, new tables, new indexes)
  are backward compatible; destructive changes (dropped columns, narrowed
  types, new `NOT NULL` without a default) are not.
- To undo a destructive migration, restore the pre-deployment backup into the
  target database and redeploy the matching binary. Treat this as a forward
  recovery, not a routine rollback.
- Keep migrations safe for both empty databases and existing installations, and
  include explicit backfills when a new rule needs values in existing rows.

## Backups

- Back up PostgreSQL before every deployment and before running an irreversible
  migration. Use `pg_dump` against the configured connection and store the
  artifact in the platform backup store:
  `pg_dump --format=custom "$GOWEB_DATABASE_URL" > goweb-$(date +%Y%m%dT%H%M%S).dump`.
- Restore with `pg_restore --clean --if-exists --dbname "$GOWEB_DATABASE_URL" <dump>`.
- Verify a restore into a disposable database on a schedule. A backup that has
  never been restored is not a recovery plan.
- Backups contain credentials, sessions, tokens, and account data. Encrypt them
  at rest, restrict access, and never copy them into the repository or CI
  artifacts.

## Retention

Retention is enforced by the maintenance worker using these settings:

| Variable | Default | Effect |
| --- | --- | --- |
| `GOWEB_GUEST_RETENTION` | `720h` | Removes old, empty abandoned guests. |
| `GOWEB_LOGIN_ATTEMPT_RETENTION` | `720h` | Removes old sign-in history. |
| `GOWEB_USAGE_RETENTION` | `2160h` | Removes old usage events. |

The worker runs every six hours (`service.DefaultMaintenanceInterval`) and
registers `guest_cleanup`, `token_retention`, `login_attempt_retention`, and
`usage_retention`. Cleanup only removes expired, consumed, or over-age records,
and historical references are detached rather than cascading away. Current job
status and a manual "run now" action are available on
`/{language}/admin/system`; job status is live process state and never stores
credentials.

## Failure recovery

- **Unsafe or invalid configuration**: startup exits before binding the port
  with a `config` error naming the offending variables. Correct the environment
  and restart. No partial state is created.
- **Migration failure**: the batch rolls back and the process exits. Read the
  `apply migration NNNNNN` error, fix or add a forward migration, and redeploy.
  Do not edit an installed migration; add a new one.
- **Migration drift**: an already-installed migration changed on disk. Restore
  the exact released file for that version. If the change was intentional,
  revert it and ship the change as a new migration.
- **Health check unavailable**: confirm PostgreSQL reachability and that the
  process is running. Startup logs are emitted through structured `slog` with a
  request ID; they never contain credentials, tokens, query strings, or full
  URLs.
- **Data loss or bad migration**: restore the last verified backup and redeploy
  the matching binary.
- **Graceful shutdown**: send `SIGTERM`; the server stops accepting connections,
  drains in-flight requests within its shutdown timeout, then closes the
  database and other registered dependencies. Verify `GET /healthz` fails
  before terminating the instance.

## Quick reference

```sh
go build -o bin/goweb ./cmd/web
pg_dump --format=custom "$GOWEB_DATABASE_URL" > goweb-$(date +%Y%m%dT%H%M%S).dump
curl -fsS "$GOWEB_PUBLIC_URL/healthz"
```
