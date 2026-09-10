# Project Instructions

Before any Go coding, review and load the `samber/cc-skills-golang@golang-how-to` skill first. It routes each task to relevant Go skills.

## Architecture

Use hexagonal boundaries and manual constructor wiring. Keep domain code independent of adapters and third-party packages. Define ports at consuming boundaries only when a second implementation or test double needs them.

Package responsibilities:

- `cmd/web` owns process startup and dependency wiring. Keep business logic out.
- `internal/config` loads typed environment configuration and redacts secrets.
- `internal/locale` owns supported language codes, canonical localized paths, and translation catalogs.
- `internal/service` contains application use cases.
- `internal/adapter/http` owns routes, page rendering, full-page/HTMX responses, and transport adapters.
- `internal/adapter/mail` owns mail delivery adapters; mail ports stay in consuming services.
- `internal/adapter/http/middleware` owns request context, recovery, logging, tracing, authentication, and CSRF boundaries.
- `internal/server` owns listener lifecycle, graceful shutdown, and dependency closure.
- `internal/store` owns database connection settings, migration execution, and persistence adapters.
- `migrations/` stores ordered database schema changes.
- `templates/` stores server-rendered HTML templates.
- `static/` stores browser assets.
- Keep tests beside packages they cover. Use `tests/` for cross-package or integration support.

## Go development

Use Go 1.26 language features only. Prefer standard-library packages. Add third-party dependencies only under the policy in `docs/dependency-policy.md`.

## Runtime and configuration

- Load configuration from environment variables through `internal/config`.
- Validate external values at server boundaries. Do not trust client-side validation.
- Start HTTP through `internal/server` and handle `SIGINT` and `SIGTERM` with graceful draining.
- Close registered dependencies after HTTP shutdown, even when startup fails.
- When `GOWEB_DATABASE_URL` is configured, startup opens PostgreSQL and applies migrations before serving requests. Local no-database startup remains supported until persistence-backed features require the store.

## HTTP and security

- Generate server-side request IDs and return them in `X-Request-ID`.
- Use structured `slog` fields with stable, low-cardinality values.
- Never log or return passwords, hashes, session credentials, tokens, provider identifiers, database credentials, mail credentials, query strings, or other secrets.
- Do not log full URLs. Use safe method, status, duration, and request ID fields.
- Keep security events separately identifiable from ordinary application logs.
- Use `html/template` for user-controlled HTML output. Keep authorization, CSRF protection, and validation server-side.
- State-changing form and HTMX requests require a server-validated CSRF token; compare tokens in constant time.
- Protected routes must use authentication middleware explicitly.

## Tests and CI

Run before submitting changes:

```sh
make check
go test -race -shuffle=on ./...
go build ./...
```

Tests must cover success and failure paths, remain isolated and repeatable, and avoid secret fixtures. GitHub Actions repeats module verification, formatting, vet, race tests, and package builds.

## Frontend

- Use DaisyUI 5 components for frontend UI instead of hand-rolled equivalents.
- Before writing HTML or JSX, load the `daisyui` skill and follow its component, usage, configuration, and color guidance.
- Keep templates semantic and accessible. Preserve stable accessible names and test hooks when adding controls.
- Keep localized URLs explicit and catalog IDs stable; validate catalog completeness and placeholders in tests.
- Anonymous theme preference may use browser storage; authenticated theme preference must persist through a server-side use case and revert UI state when rejected.

## Documentation

Read `docs/architecture.md`, `docs/dependency-policy.md`, and `docs/local-development.md` before changing related boundaries. Update documentation when commands, configuration, or package responsibilities change.
