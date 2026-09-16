# Bootstrap Administrator Procedure

This procedure provisions the first administrator account. Non-production
environments may seed one from the environment; production must provision an
administrator without storing credentials in configuration.

## Non-production bootstrap (development and test only)

Set both variables together before starting the server:

```sh
export GOWEB_BOOTSTRAP_ADMIN_EMAIL=admin@example.test
export GOWEB_BOOTSTRAP_ADMIN_PASSWORD='<throwaway password, at least 8 characters>'
go run ./cmd/web
```

Behavior at startup (`app.EnsureBootstrapAdmin`):

- Does nothing when both variables are unset.
- Rejects configuration in production before any write.
- Creates a single confirmed administrator with an Argon2id password hash and
  `is_admin = TRUE`.
- Is idempotent: an existing account with the same normalized email is left
  untouched, and a concurrent duplicate insert is treated as success.
- Never logs, returns, or stores the bootstrap password outside the hash; the
  email and password are redacted from configuration diagnostics.

The bootstrap administrator is confirmed immediately, so it can sign in even
when `GOWEB_EMAIL_CONFIRMATION_REQUIRED` is `true`. Remove both variables after
the first sign-in and rotate the password through the account settings page.
Never configure these variables in production: `internal/config` rejects them
outright, and `EnsureBootstrapAdmin` refuses to run there.

## Production account provisioning

Production deliberately has no environment-based bootstrap. Provision the first
administrator out of band:

1. Decide the administrator's address in advance and record the change in your
   change-management process.
2. Create the account through the normal sign-up flow using the address, then
   complete email confirmation. The operator chooses the password, so it is
   hashed with Argon2id by the application and never appears in configuration,
   source control, or logs. Do not set the password through environment
   variables or a migration.
3. If email confirmation is unavailable during provisioning, create the account
   through an existing administrator instead (once one exists) or confirm it
   through the application; do not hand-write password hashes.
4. Promote exactly one account with a controlled, reviewed statement against the
   production database:

   ```sql
   UPDATE users
   SET is_admin = TRUE, version = version + 1
   WHERE email = lower(btrim('admin@example.test'))
     AND is_admin = FALSE;
   ```

   Confirm exactly one row was affected. The statement matches the normalized
   email enforced by the `users_email_normalized` constraint and bumps the
   revision so any cached optimistic-lock value is invalidated.
5. Sign in as the provisioned account and open `/{language}/admin`. Confirm the
   account list, system overview, and audit log load, then confirm later
   administrator actions are recorded with the actor snapshot.
6. If the promotion is no longer needed, set `is_admin = FALSE` again with the
   same statement shape and sign the account out.

## Verification and hygiene

- Verify the administrator count with a read-only query:
  `SELECT count(*) FROM users WHERE is_admin = TRUE;`
- Keep administrator accounts few and named. Use the account detail page to end
  sessions or remove linked identities when access changes.
- Never store administrator passwords, session identifiers, or tokens in
  configuration, migrations, scripts, tickets, or chat.
- After non-production bootstrap, remove `GOWEB_BOOTSTRAP_ADMIN_EMAIL` and
  `GOWEB_BOOTSTRAP_ADMIN_PASSWORD` from the shell and process manager.

See the [deployment runbook](deployment.md) for deployment order, migrations,
and recovery, and [README configuration](../README.md#configuration) for the
full variable table.
