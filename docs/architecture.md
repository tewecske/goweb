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
- Editable records use optimistic locking: reads carry a revision, revision-checked writes report a stale version as a conflict and a vanished record as not-found.
- HTTP handlers render a full document for navigations and a self-contained fragment for HTMX requests. Fragments repeat authorization and carry an out-of-band alerts region so server errors remain visible after a swap.
- Validation failures return `422`; the client is configured to swap those fragments, while other `4xx`/`5xx` responses are treated as errors.

Delivered feature areas:

- `internal/service/settings.go` and `password_settings.go` own profile, password, and locale changes.
- `internal/service/group.go` and `group_join.go` own group creation, listing, membership visibility, invite joining/rotation, role changes, removal, and voluntary leave.
- `internal/service/repository.go` provides `ClassifyStaleWrite`, `IsWriteConflict`, and `ErrRecordNotFound` for revision-checked writes.
- `internal/store/postgres` implements the user, session, token, OAuth, group, and membership ports; `UpdateGroup` persists names and invite codes under a revision check.
- `templates/settings.html`, `templates/groups.html`, and `templates/alerts.html` back the account-settings and group interfaces.
- `internal/service/maintenance.go` owns the interval worker that runs registered cleanup jobs, retains per-job last-run state, and survives an individual job failure. `cmd/web` starts it with the signal context.
- `internal/service/retention.go` and `internal/store/postgres/retention.go` remove expired or consumed tokens, expired OAuth states, and login/usage history past the configured retention.
- `internal/service/system.go` produces the credential-free deployment configuration rendered on `/{language}/admin/system`; connection addresses are reduced to scheme and host.
- Localized routes live under `/{language}/account/settings`, `/{language}/account/theme`, and `/{language}/groups`.

The public foundation route remains `GET /healthz`.
