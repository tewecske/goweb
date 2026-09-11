# Tests

Keep unit tests beside the package they cover. Use this directory for tests
that span packages or require a full application boundary.

Integration tests must use the `integration` build tag and must not contain
credentials, tokens, or other secret fixtures.

`postgres` provides isolated PostgreSQL schemas for integration tests. Tests
using `postgres.New(t)` require `GOWEB_DATABASE_URL`; they skip when it is not
configured.

`fixtures` inserts explicit users, groups, and memberships. Fixture helpers
accept a database or caller-owned transaction and never create transactions
implicitly.

Run integration tests with:

```sh
GOWEB_DATABASE_URL='postgres://goweb:goweb@localhost:5432/goweb?sslmode=disable' go test -tags=integration ./...
```

Browser acceptance tests are opt-in with `GOWEB_BROWSER_E2E=1`. Email and
guest lifecycle specs skip database-backed flows unless `GOWEB_DATABASE_URL`
is configured; no browser credential or bearer-token fixtures belong in this
repository.
