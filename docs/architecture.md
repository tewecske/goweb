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
- `internal/service/group.go` and `group_join.go` own group creation, listing, membership visibility, invite joining/rotation, role changes, removal, and voluntary leave. Site administrators (`users.is_admin`) can list and fully manage every group without joining; their access is never stored or reported as a group membership or role.
- `internal/service/repository.go` provides `ClassifyStaleWrite`, `IsWriteConflict`, and `ErrRecordNotFound` for revision-checked writes.
- `internal/store/postgres` implements the user, session, token, OAuth, group, and membership ports; `UpdateGroup` persists names and invite codes under a revision check.
- `templates/settings.html`, `templates/groups.html`, and `templates/alerts.html` back the account-settings and group interfaces.
- Single sign-on (`GOWEB_AUTH_MODE`, see `docs/sso-hydra-plan.md`): in `provider` mode, `internal/service/sso_provider.go` answers Ory Hydra's login, consent, and logout challenges and revokes an account's Hydra sessions; `internal/adapter/hydra` is the admin API client; `internal/adapter/http/sso.go` serves the fixed `/sso/login`, `/sso/consent`, `/sso/logout`, and `/sso/error` routes and completes a pending login after any sign-in through `finishSignIn`; `internal/store/postgres/sso.go` records Hydra session IDs. `SessionService.SetSSORevoker` makes every account-wide session revocation reach Hydra. In `client` mode, `internal/service/sso_client.go` maps the issuer subject to a local account (`oauth_identities` provider `sso`), creates sessions bound to the Hydra `sid` and ID token hint, and revokes them on back-channel logout; `internal/adapter/oidc` is the standard-library OpenID Connect relying party; `internal/adapter/http/sso_client.go` serves the one-button sign-in page, `/{language}/oauth/sso`, its callback, and `POST /oauth/sso/backchannel-logout`. Client mode registers no local credential routes; `/{language}/guest/upgrade` instead starts the issuer flow bound to the signed-in guest, and `UserRepository.UpgradeGuestWithIdentity` converts the guest, links the identity, and revokes its transfer code in one transaction.
- Single sign-on tests: `tests/hydra_integration_test.go` runs the Hydra admin client and the relying party against a real Hydra (`make sso-contract`, also in CI); `tests/browser/m10-sso.spec.ts` drives provider, client, and Hydra in a browser (`make sso-e2e`, opt-in).
- `internal/adapter/oauth` implements the external identity provider client. Only providers configured through `internal/config` are registered by `internal/app`; the same registry drives sign-in/sign-up buttons and link/unlink controls in account settings.
- `internal/service/maintenance.go` owns the interval worker that runs registered cleanup jobs, retains per-job last-run state, and survives an individual job failure. `cmd/web` starts it with the signal context.
- `internal/service/retention.go` and `internal/store/postgres/retention.go` remove expired or consumed tokens, expired OAuth states, and login/usage history past the configured retention.
- `internal/service/system.go` produces the credential-free deployment configuration rendered on `/{language}/admin/system`; connection addresses are reduced to scheme and host.
- `internal/service/runtime.go` reports live version, uptime, runtime, and migration state on the same page; `internal/app` adapts the migration runner so the HTTP adapter never imports the store package.
- `internal/service/stats.go` and `internal/store/postgres/stats.go` supply cached aggregate data-store counts for the system page while current lockouts stay live.
- `internal/service/rate_limit_admin.go` lists live budgets with redacted key hints and clears them through a separate, confirmed, audited action on `/{language}/admin/ratelimits`.
- `internal/service/usage.go`, `internal/adapter/http/middleware/usage.go`, and `internal/store/postgres/usage.go` record one normalized usage event per request through a bounded queue that applies backpressure and never fails the request. Storage failures are retried with bounded backoff and each event keeps the server request ID that links it back to the originating request.
- `internal/service/usage_report.go` and `internal/store/postgres/usage_report.go` report most-used and least-used normalized routes for a URL-selected window, plus live queue health, on `/{language}/admin/usage`.
- `internal/service/suspicious.go` and `internal/store/postgres/suspicious.go` flag accounts exceeding action-count or distinct-origin thresholds on `/{language}/admin/suspicious`; the page frames the flags as investigation signals.
- `internal/adapter/http/tracer.go` starts one server span per request, continues a valid W3C `traceparent` only from a configured trusted proxy, and logs stable route names. Denied and rate-limited requests emit separately identifiable security events, and usage events keep both the request ID and trace ID that link them to the originating request.
- Localized routes live under `/{language}/account/settings`, `/{language}/account/theme`, and `/{language}/groups`.

The public foundation route remains `GET /healthz`.
