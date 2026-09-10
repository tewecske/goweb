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

`GOWEB_DATABASE_URL` and `GOWEB_SESSION_SECRET` are optional foundation inputs. Secret values are redacted from formatting and JSON diagnostics; callers must not log or return revealed values.

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
