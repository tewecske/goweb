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

Migration files use sortable `NNNNNN_description.up.sql` names. Startup creates
the migration ledger, acquires a PostgreSQL advisory lock, and applies pending
migrations transactionally.

Integration tests use a random PostgreSQL schema and skip when
`GOWEB_DATABASE_URL` is unset:

```sh
set -a; source .env; set +a
go test -tags=integration ./...
```

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
`GOWEB_BROWSER_GUEST_UPGRADE_PATH`.

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
