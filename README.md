# goweb

Server-rendered Go and HTMX application foundation.

## Requirements

- Go 1.26.x

## Run

```sh
go run ./cmd/web
```

Server listens on `:8080` by default. Set `GOWEB_HTTP_ADDR` to use another host and port.

```sh
GOWEB_HTTP_ADDR=127.0.0.1:8080 go run ./cmd/web
```

Health check: `GET /healthz`.

## Configuration

Configuration comes from environment variables. Defaults keep local development runnable:

| Variable | Default |
| --- | --- |
| `GOWEB_ENV` | `development` |
| `GOWEB_HTTP_ADDR` | `:8080` |
| `GOWEB_PUBLIC_URL` | `http://localhost:8080` |
| `GOWEB_SESSION_COOKIE_SECURE` | `true` in production or when `GOWEB_PUBLIC_URL` uses HTTPS, otherwise `false` |
| `GOWEB_EMAIL_CONFIRMATION_REQUIRED` | `false` |
| `GOWEB_SESSION_LIFETIME` | `24h` |
| `GOWEB_GUEST_RETENTION` | `720h` (30 days) |
| `GOWEB_LOGIN_ATTEMPT_RETENTION` | `720h` (30 days) |
| `GOWEB_USAGE_RETENTION` | `2160h` (90 days) |
| `GOWEB_AUTH_RATE_LIMIT` | `10`; sign-in and sign-up attempts per minute, per identifier and per client origin (1 to 10000). Production rejects values above `10`; `make run-provider` uses `600` unless set |
| `GOWEB_MAIL_RELAY` | unset; credential-free `smtp://` or `smtps://` relay that delivers confirmation and password-reset mail. Required in production unless `GOWEB_RESEND_API_KEY` is set; without either, development keeps mail in memory |
| `GOWEB_RESEND_API_KEY` | unset; delivers mail through the Resend HTTP API instead of an SMTP relay (set only one of the two). In production it needs `GOWEB_MAIL_FROM` on a domain verified in Resend |
| `GOWEB_MAIL_FROM` | `no-reply@` plus the public URL host; sender address for outgoing mail |
| `GOWEB_TRUSTED_PROXY` | unset; optional trusted proxy IP or CIDR network. Set it behind a reverse proxy so rate limits, sign-in history, and audit records use the client IP from `X-Forwarded-For` instead of the proxy address |
| `GOWEB_BOOTSTRAP_ADMIN_EMAIL` | unset; non-production bootstrap administrator email |
| `GOWEB_BOOTSTRAP_ADMIN_PASSWORD` | unset; non-production bootstrap administrator password |
| `GOWEB_GOOGLE_CLIENT_ID` | unset; enables Google sign-in when set with the client secret |
| `GOWEB_GOOGLE_CLIENT_SECRET` | unset; Google OAuth client secret |
| `GOWEB_GOOGLE_REDIRECT_URL` | derived as `<GOWEB_PUBLIC_URL>/en/oauth/google/callback` |
| `GOWEB_AUTH_MODE` | `local`; single sign-on role: `local`, `provider`, or `client` ([plan](docs/sso-hydra-plan.md)). `provider` and `client` require `GOWEB_DATABASE_URL` |
| `GOWEB_HYDRA_ADMIN_URL` | unset; provider only. Private Ory Hydra admin API address; plain HTTP is allowed on a private network |
| `GOWEB_SSO_ISSUER_URL` | unset; provider and client. Hydra's public URL (OpenID Connect issuer); the provider sends sign-out through its logout endpoint. HTTPS in production |
| `GOWEB_SSO_CLIENT_ID` | unset; client only. Client ID registered in Hydra |
| `GOWEB_SSO_CLIENT_SECRET` | unset; client only. Client secret registered in Hydra |
| `GOWEB_SSO_REDIRECT_URL` | client only; derived as `<GOWEB_PUBLIC_URL>/en/oauth/sso/callback` |
| `GOWEB_SSO_ACCOUNT_URL` | unset; client only. Provider account settings page linked from the client |

`GOWEB_DATABASE_URL` and `GOWEB_SESSION_SECRET` are optional foundation inputs. Secret values are redacted from formatting and JSON diagnostics; callers must not log or return revealed values.

Google sign-in is optional and only appears on the sign-in and sign-up pages when
both `GOWEB_GOOGLE_CLIENT_ID` and `GOWEB_GOOGLE_CLIENT_SECRET` are set. Register
the effective `GOWEB_GOOGLE_REDIRECT_URL` (HTTPS) as an authorized redirect URI in
the Google Cloud console. Linked accounts are managed in the account settings
page.

Copy [.env.example](.env.example) to `.env` for local example values. It is not a
secret file: every value is a throwaway example. `make run` sources `.env`
automatically when the file exists; without `make`, export it first:

```sh
cp .env.example .env
set -a; source .env; set +a
```

Start the local PostgreSQL from the committed [`compose.yaml`](compose.yaml):

```sh
make db-up
```

Stop it with `make db-down`. The container publishes `POSTGRES_PORT` (default
`55432`) to avoid clashing with a PostgreSQL already on `5432`. `make run`
sources `.env` automatically when the file exists. See
[local development](docs/local-development.md) for the full workflow.

## Verify

```sh
make check
```

## Credits

Theme icons use [Heroicons](https://github.com/tailwindlabs/heroicons) by
[Tailwind Labs](https://tailwindlabs.com), licensed under the
[MIT License](https://github.com/tailwindlabs/heroicons/blob/master/LICENSE).

Copyright (c) Tailwind Labs, Inc. The full license text is reproduced on the
application about page.

## Decisions

- Go 1.26.0 is language baseline; `go1.26.5` is current toolchain pin.
- Runtime uses standard-library packages only.
- Dependency additions follow [dependency policy](docs/dependency-policy.md).
- Package boundaries follow [hexagonal architecture](docs/architecture.md).

The complete application requirements are in [gptsummary.md](gptsummary.md).

See [local development setup](docs/local-development.md) for tool requirements,
database status, development commands, and project conventions. Production
rollout, migrations, rollback limits, backups, and recovery are covered by the
[deployment and migration runbook](docs/deployment.md), and first-admin setup by
the [bootstrap administrator procedure](docs/bootstrap-admin.md). Data
retention and datastore backups are described in
[backup and retention](docs/backup-retention.md), and trust boundaries and
bearer credentials in the [security threat model](docs/threat-model.md).
Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md).
