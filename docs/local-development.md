# Local Development

## Required tools

- Git
- Go 1.26.x; the repository pins toolchain `go1.26.5`
- `make` for the documented command shortcuts
- `curl` for the health-check example

Check Go version:

```sh
go version
```

## Start application

No database is required for current M0 foundation behavior.

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

M0 does not open a database connection or run migrations. A database process is
therefore not needed to start or test the current application. The
`migrations/` directory is reserved for ordered schema changes; persistence
work will document the engine, container, connection checks, and migration
command when that implementation lands.

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
