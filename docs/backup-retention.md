# Backup and Retention

This document records what the application keeps, how long, what cleanup does,
and the expectations for datastore backups. See the
[deployment runbook](deployment.md) for deploy ordering and the
[bootstrap administrator procedure](bootstrap-admin.md) for first-admin setup.

## Data inventory and retention

| Data | Table | Retention setting | Cleanup behavior |
| --- | --- | --- | --- |
| Empty abandoned guests | `users` (`is_guest`) | `GOWEB_GUEST_RETENTION` (`720h`) | `guest_cleanup` removes guests older than the cutoff that own no group membership. |
| Email confirmation tokens | `email_verification_tokens` | not age-based | `token_retention` removes consumed or expired tokens. |
| Password reset tokens | `password_reset_tokens` | not age-based | `token_retention` removes consumed or expired tokens. |
| OAuth flow states | `oauth_states` | not age-based | `token_retention` removes consumed or expired states. |
| Sign-in history | `login_attempts` | `GOWEB_LOGIN_ATTEMPT_RETENTION` (`720h`) | `login_attempt_retention` removes attempts older than the cutoff. |
| Usage events | `usage_events` | `GOWEB_USAGE_RETENTION` (`2160h`) | `usage_retention` removes events older than the cutoff. |
| Administrator audit log | `audit_log` | not automatically removed | Preserved as the historical record of administrator actions. |
| Sessions and external identities | `sessions`, `oauth_identities` | not age-based | Expired and revoked sessions are rejected at lookup; rows are removed when their account is deleted. |

Notes:

- Retention cleanup only removes expired, consumed, or over-age records. A
  negative or missing cutoff is rejected rather than treated as "delete all".
- Guest cleanup locks candidate accounts before checking membership so a
  concurrent join cannot be cascaded away, and deletes only guests with no owned
  group membership, credentials, or sessions left to preserve.
- Account deletion cascades owned credentials (sessions, tokens, claim codes,
  identities, memberships) while historical sign-in, usage, and audit rows
  survive with their account reference set to `NULL`. See `docs/architecture.md`
  and `internal/store/deletion_rules_integration_test.go`.
- The audit log is intentionally not time-limited. If a regulatory retention
  limit applies, export and prune it under a separate, reviewed procedure.

## Cleanup schedule

The maintenance worker runs every `service.DefaultMaintenanceInterval` (six
hours) and registers four jobs:

- `guest_cleanup`
- `token_retention`
- `login_attempt_retention`
- `usage_retention`

Each run is independent: one job failing does not cancel the others, and the
worker keeps its last-run state in process memory. Current status and a manual
"run now" action are available to administrators on
`/{language}/admin/system`. Job state is live process state and never stores
credentials. Retention periods are read once at startup from the environment,
so changing them requires a restart.

## Backup expectations

- Scope: back up the whole database (schema and data). Backups therefore
  contain password hashes, session rows, token rows, and account data.
- Cadence: take a backup before every deploy, before any destructive migration,
  and on a regular schedule that matches your recovery point objective.
- Method: use the PostgreSQL utilities against the configured connection:

  ```sh
  pg_dump --format=custom "$GOWEB_DATABASE_URL" > goweb-$(date +%Y%m%dT%H%M%S).dump
  pg_restore --clean --if-exists --dbname "$GOWEB_DATABASE_URL" goweb-<timestamp>.dump
  ```

- Verify restores: restore into a disposable database on a schedule and run the
  integration suite against it. A backup that has never been restored is not a
  recovery plan.
- Protect backups: encrypt at rest, restrict access to operators, transmit only
  over trusted channels, and never copy them into the repository, CI artifacts,
  logs, or tickets.
- Align backup retention with privacy commitments. Retention cleanup removes
  rows from the live database, but older backups may still contain them; expire
  backups on a schedule that matches the retention promises you make.
- Confirm the restore target satisfies production configuration before serving
  traffic; see the [deployment runbook](deployment.md#required-production-configuration).

## Verifying retention

- Inspect current job status on `/{language}/admin/system`, then run a job
  manually if needed.
- Confirm sign-in and usage history older than the configured period is gone,
  and that audit entries remain.
- Integration coverage lives in `internal/store/postgres/retention_integration_test.go`,
  `internal/store/postgres/guest_integration_test.go`, and
  `internal/store/deletion_rules_integration_test.go`.
