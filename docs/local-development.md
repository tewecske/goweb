# Local Development

## Required tools

- Git
- Go 1.26.x; the repository pins toolchain `go1.26.5`
- `make` for the documented command shortcuts
- `curl` for the health-check example
- Node.js 20+ and npm for browser acceptance tests
- Docker with the Compose plugin for a local PostgreSQL

Check Go version:

```sh
go version
```

## Start application

Build browser assets after installing npm dependencies:

```sh
npm install
npm run build:css
npm run check:assets
```

The Go server embeds and serves the generated stylesheet at `/static/app.css`.

No database is required for a no-persistence local run. When
`GOWEB_DATABASE_URL` is configured, startup verifies PostgreSQL and applies
pending migrations before serving requests.

```sh
go run ./cmd/web
```

Check health and request correlation:

```sh
curl -i http://localhost:8080/healthz
```

Response includes `X-Request-ID`. Stop the process with `Ctrl-C` or `SIGTERM`;
the server stops accepting requests and drains active requests within its
shutdown timeout.

Use another listen address when needed:

```sh
GOWEB_HTTP_ADDR=127.0.0.1:9090 go run ./cmd/web
```

## Configuration

Configuration uses environment variables. Local defaults are safe for the
development server. See [README configuration](../README.md#configuration) for
the complete variable table.

Copy the committed example to a local `.env` and load it into the shell:

```sh
cp .env.example .env
set -a; source .env; set +a
```

`.env.example` holds throwaway example values only. The application does not
read `.env` itself, so export it with the `source` command above (or your
process manager) before running `go run ./cmd/web`.

Secret-bearing values such as `GOWEB_DATABASE_URL` and
`GOWEB_SESSION_SECRET` must come from the environment or a local secret
manager. Never place them in shell history, source files, logs, test output, or
committed `.env` files. Only `.env.example` is committed; `.env` stays ignored.

## Database startup

PostgreSQL runs through Compose using the committed `compose.yaml`:

```sh
cp .env.example .env
make db-up
docker compose ps
```

Use `make db-down` to stop it without discarding data; `docker compose down -v`
also removes the data volume.

`compose.yaml` reads `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, and
`POSTGRES_PORT` from `.env`, defaulting to the same example values. It publishes
container port `5432` on `POSTGRES_PORT` (default `55432`) so it never collides
with a PostgreSQL already listening on the standard port.

Keep `GOWEB_DATABASE_URL` in `.env` pointing at the same host, port, user,
password, and database, then start the application. `make run` sources `.env`
automatically when the file exists:

```sh
make run
```

Without `make`, export it yourself first:

```sh
set -a; source .env; set +a
go run ./cmd/web
```

Without Compose, run the same image directly:

```sh
docker run --rm --name goweb-postgres \
  -e POSTGRES_USER=goweb \
  -e POSTGRES_PASSWORD=goweb \
  -e POSTGRES_DB=goweb \
  -p 55432:5432 postgres:17-alpine
```

## Reading mail locally

Without `GOWEB_MAIL_RELAY`, confirmation and password-reset mail stays in
memory and cannot be read. `make db-up` also starts Mailpit; point the app at
it to read messages in the browser at `http://localhost:8025`:

```sh
GOWEB_MAIL_RELAY=smtp://localhost:1025 make run
```

Migration files use sortable `NNNNNN_description.up.sql` names. Startup creates
the migration ledger, acquires a PostgreSQL advisory lock, and applies pending
migrations transactionally.

Integration tests use a random PostgreSQL schema and skip when
`GOWEB_DATABASE_URL` is unset:

```sh
set -a; source .env; set +a
go test -tags=integration ./...
```

## Running SSO locally

See [sso-hydra-plan.md](sso-hydra-plan.md) for the design. You run three
processes: Hydra (in Docker), a provider app, and a client app.

```sh
make sso-up        # PostgreSQL, Hydra's role/database, goweb_client database, Hydra, back-channel relay
make sso-client    # registers the dev client app and writes .env.client
make run-provider  # terminal 1: provider (GOWEB_AUTH_MODE=provider)
make run-client    # terminal 2: client (GOWEB_AUTH_MODE=client)
```

By default everything is reachable from this machine only:

| Process | URL |
| --- | --- |
| Provider | `http://localhost:8080` |
| Client | `http://127.0.0.1:8081` |
| Hydra (issuer) | `http://127.0.0.1:4444` |
| Hydra admin API | `http://127.0.0.1:4445` (always loopback only) |

Open the client, choose sign in, and sign in or sign up at the provider; you
return signed in to the client. With the same `GOWEB_BOOTSTRAP_ADMIN_EMAIL`,
both apps seed that administrator, and signing in to the client as the
provider's confirmed administrator links the two.

### Testing from another machine (for example over Tailscale)

The browser talks to all three processes, and Hydra redirects it to the exact
configured URLs, so they must be the addresses the other machine uses. Set in
`.env` (see `.env.example`):

```sh
SSO_DEV_BIND=100.92.5.118                                  # this machine's tailnet IP
SSO_DEV_ISSUER_URL=http://omnissiah.tail17501b.ts.net:4444
SSO_DEV_PROVIDER_URL=http://100.92.5.118:8080
SSO_DEV_CLIENT_URL=http://omnissiah.tail17501b.ts.net:8081
```

Then rerun `make sso-up` (it recreates Hydra), `make sso-client`, and restart
both apps. Rules:

- Provider and client need different host names, because cookies ignore
  ports. Here the provider uses the IP address and the client the MagicDNS
  name.
- Use the same host and port for the issuer everywhere. The client checks
  every token's `iss` against `SSO_DEV_ISSUER_URL`, from both the browser and
  its own server-side calls. Ports stay 4444, 8080, and 8081.
- Hydra's public API, the provider, and the client listen on `SSO_DEV_BIND`
  only. Hydra's admin API stays on `127.0.0.1:4445`, because it can sign
  anyone in.
- Back-channel logout goes through the `sso-backchannel-relay` container on
  `127.0.0.1:4446`. Hydra's outbound SSRF guard refuses Tailscale's
  `100.64.0.0/10` range and has no setting to allow it, so Hydra calls the
  loopback relay, which forwards to the client.
- Everything is plain HTTP. That suits a private tailnet; never use these
  settings on a shared network.

### Notes

- Hydra uses host networking. On Docker Desktop, enable host networking in its
  settings.
- Hydra has its own `hydra` PostgreSQL role and database, and the client app
  its own `goweb_client` database, both created by the one-shot `sso-db-init`
  service inside the existing Compose PostgreSQL.
- `make sso-client` deletes and recreates the `goweb-dev-client` client, so the
  secret changes on every run. It writes the git-ignored, owner-only
  `.env.client`, which `make run-client` loads on top of `.env`. Restart the
  client app afterwards.
- `make db-down` stops Hydra together with PostgreSQL and Mailpit.

## Checks

Run standard checks:

```sh
make check
```

Run race and shuffled tests:

```sh
go test -race -shuffle=on ./...
```

Build all packages:

```sh
go build ./...
```

Build runnable binary:

```sh
make build
```

Remove generated artifacts:

```sh
make clean
```

Run browser acceptance specs after installing npm dependencies:

```sh
npm install
npx playwright install chromium
GOWEB_BROWSER_E2E=1 npm run test:browser
```

Browser specs are skipped without `GOWEB_BROWSER_E2E=1`. Database-backed email
and guest lifecycle scenarios additionally skip unless `GOWEB_DATABASE_URL` is
configured; signed-in settings scenarios require
`GOWEB_BROWSER_DATABASE_FIXTURE=1`. Enabled runs require application routes plus
configured mail and external-provider test fixtures; they never use committed
credentials or token fixtures.
Guest acceptance fixtures may override logical guest routes with
`GOWEB_BROWSER_GUEST_WRITE_PATH`, `GOWEB_BROWSER_GUEST_TRANSFER_PATH`, and
`GOWEB_BROWSER_GUEST_UPGRADE_PATH`. OAuth failure specs default to an
unconfigured provider name; override `GOWEB_BROWSER_OAUTH_PROVIDER` when a
provider is configured in the test environment.

## Project conventions

- `cmd/web` owns process startup and dependency wiring.
- `internal/config` validates deployment values and redacts secrets.
- `internal/adapter/http` owns transport routes and middleware.
- `internal/server` owns listener lifecycle and dependency shutdown.
- `internal/service` contains application use cases.
- Tests stay beside the package they cover; cross-package tests belong in
  `tests/`.
- Migrations, templates, and browser assets live in their named root
  directories.
- Keep interfaces at consuming boundaries and add them only when a second
  implementation or test double needs one.

CI repeats module verification, formatting, vet, race tests, and package build
checks on pushes and pull requests.
