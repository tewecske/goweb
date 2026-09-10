# Local Development

## Required tools

- Git
- Go 1.26.x; the repository pins toolchain `go1.26.5`
- `make` for the documented command shortcuts
- `curl` for the health-check example
- Node.js 20+ and npm for browser acceptance tests

Check Go version:

```sh
go version
```

## Start application

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

Secret-bearing values such as `GOWEB_DATABASE_URL` and
`GOWEB_SESSION_SECRET` must come from the environment or a local secret
manager. Never place them in shell history, source files, logs, test output, or
committed `.env` files.

## Database startup

M1 uses PostgreSQL through `GOWEB_DATABASE_URL`. Run a local PostgreSQL container
when persistence work needs a database:

```sh
docker run --rm --name goweb-postgres \
  -e POSTGRES_USER=goweb \
  -e POSTGRES_PASSWORD=goweb \
  -e POSTGRES_DB=goweb \
  -p 5432:5432 postgres:17
```

Start the application against it in another shell. Do not commit the URL or
password:

```sh
GOWEB_DATABASE_URL='postgres://goweb:goweb@localhost:5432/goweb?sslmode=disable' go run ./cmd/web
```

Migration files use sortable `NNNNNN_description.up.sql` names. Startup creates
the migration ledger, acquires a PostgreSQL advisory lock, and applies pending
migrations transactionally.

Integration tests use a random PostgreSQL schema and skip when
`GOWEB_DATABASE_URL` is unset:

```sh
GOWEB_DATABASE_URL='postgres://goweb:goweb@localhost:5432/goweb?sslmode=disable' go test -tags=integration ./...
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

Browser specs are skipped without `GOWEB_BROWSER_E2E=1`. Enabled runs require
application routes plus configured mail and external-provider test fixtures;
they never use committed credentials or token fixtures.

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
