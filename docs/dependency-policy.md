# Dependency Policy

## Baseline

Runtime code starts with no third-party dependencies.

| Need | Baseline |
| --- | --- |
| HTTP server and routing | `net/http` |
| Server-rendered HTML | `html/template` |
| Embedded templates and assets | `embed` |
| Structured logs | `log/slog` |
| Database contracts | `database/sql` |
| Cryptography and secure randomness | `crypto/*` |
| Tests and HTTP tests | `testing`, `net/http/httptest` |
| Browser interactions | HTMX assets, without a Go runtime dependency |

Use standard-library functionality when it meets requirements. Do not add a package only to shorten small amounts of code.

## Adding a dependency

Every third-party dependency requires:

1. A documented reason that the standard library cannot meet the requirement.
2. Maintainer, license, release, and known-vulnerability review.
3. Direct imports in the smallest possible package.
4. An exact module version selected through normal Go module resolution.
5. `go mod tidy`, `go mod verify`, `go test ./...`, and `go vet ./...` before merge.
6. `govulncheck ./...` before release and after security-relevant changes.

Do not use floating source URLs, vendored copies without review, or dependencies that expose credentials in logs, responses, traces, or diagnostics.

`go.sum` becomes required and must be committed as soon as the first module dependency is added. Until then, an empty dependency graph needs no checksum file.

## Updates

Keep runtime dependencies on supported releases. Prefer patch updates, review transitive changes, rerun all checks, and record breaking upgrades in the change description.
