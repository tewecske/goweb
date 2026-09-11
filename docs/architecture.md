# Architecture

This project uses hexagonal architecture with explicit, manual wiring.

```text
 cmd/web                   process entry point and dependency wiring
 internal/app              explicit application graph composition
internal/config           validated deployment configuration
internal/locale            supported languages and canonical URL paths
internal/service          application use-case services
internal/adapter/http     HTTP transport adapter
internal/adapter/mail     mail delivery adapters
internal/adapter/http/middleware shared request boundaries
internal/server           HTTP lifecycle and dependency shutdown
internal/store            database connection and migration infrastructure
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
- `internal/app` owns manual service/repository composition and does not close shared resources.
- Configured database connections are opened and migrated before HTTP serving begins; the server closes them during shutdown.

Foundation currently exposes only `GET /healthz`. Feature work adds domain behavior and ports as real use cases require them; empty abstraction packages are intentionally avoided.
