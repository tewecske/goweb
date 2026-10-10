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
- `GOWEB_MAIL_RELAY` is unset. Confirmation and password-reset mail is
  delivered through this credential-free `smtp://` or `smtps://` relay;
  `GOWEB_MAIL_FROM` sets the sender (default `no-reply@` plus the public host).
- Google sign-in is configured with a non-HTTPS `GOWEB_GOOGLE_REDIRECT_URL`.
- `GOWEB_AUTH_MODE=provider` with a non-HTTPS `GOWEB_SSO_ISSUER_URL`.
- `GOWEB_AUTH_MODE=client` with a non-HTTPS `GOWEB_SSO_ISSUER_URL`,
  `GOWEB_SSO_REDIRECT_URL`, or `GOWEB_SSO_ACCOUNT_URL`. The provider's
  `GOWEB_HYDRA_ADMIN_URL` may use plain HTTP because it must only be reachable
  on a private network.

Every environment rejects `GOWEB_AUTH_MODE` settings that do not belong to the
selected mode, a `provider` or `client` mode without `GOWEB_DATABASE_URL`, and
Google sign-in on a `client` (it belongs on the provider). See
[sso-hydra-plan.md](sso-hydra-plan.md). `provider` requires `GOWEB_HYDRA_ADMIN_URL`
and `GOWEB_SSO_ISSUER_URL`; `client` requires the issuer URL, client ID, and
client secret registered in Hydra. A provider deployment answers Hydra at the fixed paths `/sso/login`,
`/sso/consent`, `/sso/logout`, and `/sso/error`; configure Hydra's `urls.login`,
`urls.consent`, `urls.logout`, and `urls.error` to those paths on the provider's
public URL. The error page maps Hydra's error code to a localized explanation
and never displays Hydra's description, hint, or debug text.

Register each client app in Hydra (see `scripts/hydra-dev-client.sh` for the
exact flags) with:

- redirect URI `<client public URL>/en/oauth/sso/callback`
- post-logout redirect URI `<client public URL>/en/sign-in`
- back-channel logout URI `<client public URL>/oauth/sso/backchannel-logout`
  with `backchannel_logout_session_required`. Hydra must be able to reach it.
  Hydra's outbound SSRF guard only allows public addresses plus loopback,
  RFC 1918, and link-local ranges. It refuses carrier-grade NAT addresses
  (`100.64.0.0/10`, for example Tailscale), and no setting changes that.
- `skip_consent`, `skip_logout_consent`, `client_secret_basic`, and scopes
  `openid email profile`

A client app's existing local account is linked to its single sign-on identity
on first sign-in only when both the local account and the provider vouch for
the same email address (both verified); otherwise sign-in is refused with a
conflict, so resolve such accounts before switching an app to client mode.

Every environment also rejects a credential-bearing public URL, a malformed
mail relay, an invalid `GOWEB_TRUSTED_PROXY`, partially configured Google OAuth
credentials, and bootstrap administrator values in production. When enabling
Google sign-in, register the effective `GOWEB_GOOGLE_REDIRECT_URL` as an
authorized redirect URI in the Google Cloud console. See [README configuration](../README.md#configuration)
for the full variable table and the
[bootstrap administrator procedure](bootstrap-admin.md) for first-admin
provisioning. Secret values are redacted from diagnostics and must come from the
platform secret store, never from the repository.

Behind a reverse proxy, set `GOWEB_TRUSTED_PROXY` to the proxy address or
network and have the proxy append the client address to `X-Forwarded-For`.
Otherwise every client shares the proxy's per-origin sign-in and guest rate
limits, and audit records show the proxy address.

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

## Single sign-on: hosting Ory Hydra

Apps in `provider` and `client` mode need an Ory Hydra deployment
([plan](sso-hydra-plan.md)). Local development uses `compose.yaml`; production
differs as follows.

- **Version.** Pin an exact image tag (the plan records `oryd/hydra:v26.2.0`)
  and read the release notes before upgrading. Do not run `--dev`.
- **Network.** Terminate TLS at a load balancer or gateway in front of Hydra's
  public port (4444). The issuer URL must be the public HTTPS address clients
  and browsers use, exactly as configured in `GOWEB_SSO_ISSUER_URL`. The admin
  port (4445) must never be reachable from the internet or from client
  networks: anyone who can call it can sign in as any user. Only the provider
  deployment reaches it, through `GOWEB_HYDRA_ADMIN_URL` on a private network.
- **Database.** Give Hydra its own PostgreSQL role and database, never the
  application's. Run `hydra migrate sql up -e --yes` as a separate step before
  starting a new Hydra version; do not let several instances race to migrate.
  Start the very first deployment with a single instance, so key generation
  finishes once.
- **Configuration.** Set `urls.self.issuer`, `urls.login`, `urls.consent`,
  `urls.logout`, and `urls.error` to the issuer and the provider's public
  URL. Keep `log.leak_sensitive_values` false.
- **Secrets.** `secrets.system` and `secrets.cookie` must be long random values
  from your secret store, never the development placeholders in
  `compose.yaml`. To rotate either one, prepend the new value to its list and
  keep the old values listed so existing data stays readable: only the first
  entry encrypts, and all entries decrypt. Existing rows are not re-encrypted.
- **Signing keys.** Hydra signs ID tokens with the newest key in the
  `hydra.openid.id-token` key set and publishes all of them at
  `/.well-known/jwks.json`. Rotate with
  `hydra create jwks --endpoint <admin URL> hydra.openid.id-token --alg RS256`;
  client apps refetch the key set when they see an unknown key ID (at most
  every 30 seconds), so no client restart is needed.
- **Cleanup.** Run `hydra janitor` on a schedule to remove expired tokens and
  stale login and consent requests, for example
  `DSN=<Hydra database URL> hydra janitor -e --tokens --requests --keep-if-younger 24h`.
  It deletes in batches, is irreversible, and ran successfully against a copy of
  the development database (it removed the expired access tokens). Try it on a
  restored backup first, and see `hydra janitor --help` for the lifespans.
- **Client registration.** Register each app as described under
  [Required production configuration](#required-production-configuration).
  Client secrets are shown once, at creation.
- **Verification.** `make sso-contract` runs the Hydra contract test against a
  throwaway Hydra; the browser specs in `tests/browser/m10-sso.spec.ts` (`make
  sso-e2e`) exercise a running provider, client, and Hydra.

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

See [backup and retention](backup-retention.md) for the full data inventory and
backup expectations.

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

See [backup and retention](backup-retention.md) for the per-table data inventory
and cleanup behavior. Retention is enforced by the maintenance worker using
these settings:

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
