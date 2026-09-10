# Tests

Keep unit tests beside the package they cover. Use this directory for tests
that span packages or require a full application boundary.

Integration tests must use the `integration` build tag and must not contain
credentials, tokens, or other secret fixtures.

`postgres` provides isolated PostgreSQL schemas for integration tests. Tests
using `postgres.New(t)` require `GOWEB_DATABASE_URL`; they skip when it is not
configured.

Run integration tests with:

```sh
GOWEB_DATABASE_URL='postgres://goweb:goweb@localhost:5432/goweb?sslmode=disable' go test -tags=integration ./...
```
