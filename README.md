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
| `GOWEB_SESSION_COOKIE_SECURE` | `false`, or `true` in production |
| `GOWEB_EMAIL_CONFIRMATION_REQUIRED` | `false` |
| `GOWEB_SESSION_LIFETIME` | `24h` |
| `GOWEB_GUEST_RETENTION` | `720h` (30 days) |
| `GOWEB_LOGIN_ATTEMPT_RETENTION` | `720h` (30 days) |
| `GOWEB_USAGE_RETENTION` | `2160h` (90 days) |
| `GOWEB_MAIL_RELAY` | unset; optional credential-free relay used by the system overview |
| `GOWEB_TRUSTED_PROXY` | unset; optional trusted proxy IP or CIDR network |
| `GOWEB_BOOTSTRAP_ADMIN_EMAIL` | unset; non-production bootstrap administrator email |
| `GOWEB_BOOTSTRAP_ADMIN_PASSWORD` | unset; non-production bootstrap administrator password |

`GOWEB_DATABASE_URL` and `GOWEB_SESSION_SECRET` are optional foundation inputs. Secret values are redacted from formatting and JSON diagnostics; callers must not log or return revealed values.

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
