# goweb

Server-rendered Go and HTMX application foundation.

## Requirements

- Go 1.26.x

## Run

```sh
go run ./cmd/goweb
```

Server listens on `:8080` by default. Set `GOWEB_HTTP_ADDR` to use another host and port.

```sh
GOWEB_HTTP_ADDR=127.0.0.1:8080 go run ./cmd/goweb
```

Health check: `GET /healthz`.

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
