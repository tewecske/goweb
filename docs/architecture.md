# Architecture

This project uses hexagonal architecture with explicit, manual wiring.

```text
cmd/web                   process entry point and dependency wiring
internal/config           validated deployment configuration
internal/service          application use-case services
internal/adapter/http     HTTP transport adapter
internal/server           HTTP lifecycle and dependency shutdown
migrations                ordered database schema changes
templates                 server-rendered HTML templates
static                    browser assets
tests                     cross-package and integration test support
```

Rules:

- Domain logic does not import HTTP, database, template, or third-party packages.
- Adapters translate external protocols into domain operations.
- Ports belong to the consuming package and stay small.
- Constructors receive dependencies explicitly and return concrete types.
- `cmd/web` owns process lifecycle and does not contain business logic.

Foundation currently exposes only `GET /healthz`. Feature work adds domain behavior and ports as real use cases require them; empty abstraction packages are intentionally avoided.
