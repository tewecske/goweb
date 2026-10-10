# Plan: Single Sign-On with Ory Hydra

Status: Phases 0–4 done (2026-10-10). Phases 5–6 are not started.

## Goal

Apps created from this template share one sign-in. A user signs in once at an
identity app and is signed in to every other app without re-entering
credentials. Signing out or having sessions revoked by an administrator ends
access everywhere within a bounded time.

Ory Hydra (self-hosted, open source) implements OAuth 2.0 and OpenID Connect.
It stores no users and renders no pages. This template supplies the users,
sign-in pages, and claims.

## Decisions

1. **One codebase, three modes.** `GOWEB_AUTH_MODE` selects the role of a
   deployment:
   - `local` (default): today's behavior. A standalone app with its own
     accounts. Existing deployments keep working unchanged.
   - `provider`: the identity app. It keeps every current account feature
     (password, Google, confirmation, reset, lockout, guests, user
     administration) and also serves Hydra's login, consent, and logout
     endpoints. Exactly one provider deployment exists per SSO realm.
   - `client`: an app that delegates sign-in to the provider through Hydra.
     Password, sign-up, reset, confirmation, and Google routes are not
     registered.
2. **Hydra is one more OAuth provider in client mode.** It is registered in
   the existing `service.ProviderRegistry` under the name `sso`. The existing
   `OAuthSignInService` flow (single-use hashed state, `HttpOnly` state cookie,
   PKCE S256, session rotation) and the `oauth_identities` table map the
   provider's subject to a local `users` row. Groups, audit, and usage keep
   their foreign keys to the local `users.id`. No schema split is needed.
3. **Subject = provider `users.id` as a decimal string.** It is public, stable,
   and requires no migration.
4. **Identity data is owned by the provider; app data stays local.** In client
   mode, email and display name are refreshed from ID token claims at every
   sign-in and are read-only locally. Theme, locale preference, groups, and
   `is_admin` stay local to each app. Site-admin rights are **not** propagated
   through claims. Each app grants its own administrators.
5. **Guests stay local to each client app.** A guest keeps their data by
   signing in through SSO, which turns the guest row into a full account linked
   to the SSO subject.
6. **Revocation uses back-channel logout by session ID.** The provider records
   each Hydra login session ID (`sid`) it sees. Administrator revocation,
   password change, password reset, and account deletion revoke each recorded
   `sid` in Hydra, and revoke consent sessions, which invalidates tokens. Hydra
   then calls each client's back-channel logout endpoint. Revoking by `subject`
   alone does not trigger back-channel logout, so it is not enough. Client
   session lifetime remains the upper bound if a back-channel call is lost.
7. **No new Go dependencies.** The Hydra admin API is called with `net/http`
   and `encoding/json`. ID and logout tokens are verified for RS256 only, using
   `crypto/rsa`, `crypto/sha256`, and `encoding/base64` against Hydra's JWKS.
   The verifier rejects every other `alg`. Revisit this through
   `docs/dependency-policy.md` if more algorithms are ever needed.
8. **Your own apps only.** Every client is a trusted app with
   `skip_consent` and `skip_logout_consent`. Third-party clients and real
   consent screens are out of scope.

## Target architecture

```text
                       ┌───────────────────────────────┐
  browser ────────────▶│ Hydra public :4444 (issuer)   │
     │                 │  /oauth2/auth /oauth2/token   │
     │                 │  /.well-known/* /oauth2/sessions/logout
     │                 └──────┬────────────────▲───────┘
     │   login/consent/logout │ redirects      │ admin API :4445 (private)
     │   challenges           ▼                │
     │                 ┌───────────────────────┴───────┐
     ├────────────────▶│ goweb, GOWEB_AUTH_MODE=provider│
     │                 │ sign-in/up, reset, Google,     │
     │                 │ /sso/login /sso/consent        │
     │                 │ /sso/logout, user admin        │
     │                 └───────────────────────────────┘
     │                 ┌───────────────────────────────┐
     └────────────────▶│ app from template, mode=client │◀── back-channel logout
                       │ /oauth/sso, /oauth/sso/callback│    (Hydra → app)
                       │ local session, local data      │
                       └───────────────────────────────┘
```

Databases: Hydra has its own database (a separate database in the same
PostgreSQL server is fine). The provider and each client have their own
application databases.

## Phase 0: Spike results (done)

The spike ran Hydra from Phase 1's compose setup, a throwaway login/consent
provider on `localhost:8080`, and a throwaway relying party on
`127.0.0.1:8081`, then drove real flows with `curl`. The spike code was
discarded. Results:

| Question | Result |
| --- | --- |
| Release and license | Pinned `oryd/hydra:v26.2.0` (built 2026-03-20). Apache-2.0. Versioning changed from `v2.3.0` to year-based tags. The image has `sh` and `wget`, and runs as `nonroot`. |
| Discovery | `backchannel_logout_supported` and `backchannel_logout_session_supported` are true. `id_token_signing_alg_values_supported` is `["RS256"]`. PKCE `S256` is supported. |
| JWKS | Two RS256 keys are published (ID token and access token key sets). Verifiers must select by `kid`. |
| ID token | RS256, `aud` is an **array**, and the claims include `sub`, `sid`, `auth_time`, `at_hash`, and every custom claim set at consent. Verification with `crypto/rsa` and `crypto/sha256` only succeeded. |
| Where the `sid` is visible | Both the login request (`session_id`) and the consent request (`login_session_id`) carry the same value as the ID token `sid`. |
| Repeat sign-in | The second flow in the same browser returns a login request with `skip=true` and the remembered `subject`. No form is needed: SSO works. |
| Consent with `skip_consent` | Hydra **still redirects to the consent endpoint** (with `skip=true`). The provider must accept every time and resend the claims. |
| Revoke login sessions by `subject` | 204. **No** back-channel logout, and the access token stays active. |
| Revoke login sessions by `sid` | 204 and an immediate back-channel logout to the client. The access token **stays active**. |
| Revoke consent sessions (`subject`, `all=true`) | The access token becomes inactive. No back-channel logout. |
| Logout token | RS256 with `iss`, `aud` (array), `iat`, `jti`, `sid`, and `events` = `{"http://schemas.openid.net/event/backchannel-logout":{}}`. No `sub`, `exp`, or `nonce`. Verified with the standard library. |
| RP-initiated logout with `client_id` only | **Rejected**: "post_logout_redirect_uri is set but id_token_hint is missing". |
| RP-initiated logout with `id_token_hint` | Hydra still calls the provider's logout endpoint (`rp_initiated=true`, even with `skip_logout_consent`), sends a back-channel logout to the client that started it as well, and redirects to `post_logout_redirect_uri` with `state`. |
| Back-channel logout to a client that is down | The admin call returns 204 in about 30 ms. Delivery is asynchronous: 3 attempts about 2 s apart, then Hydra logs "giving up". |
| Challenge sizes | Login about 1.3 KB, consent about 1.4 KB. They fit a cookie and stay far below the server's request limits. |

Consequences for the later phases (already applied below):

- Revocation must call **both** revoke-by-`sid` (for back-channel logout) and
  revoke-consent (for tokens).
- Client sessions must store the ID token, because sign-out with a return URL
  requires `id_token_hint`.
- The provider's consent and logout endpoints are always required, even for
  trusted clients.

## Phase 1: Local Hydra infrastructure (done)

- `compose.yaml`, with all Hydra services under the `sso` profile so `make db-up`
  is unchanged:
  - `hydra-db-init`: a one-shot `psql` that creates a dedicated `hydra` role
    and database inside the existing Compose PostgreSQL. It is idempotent and
    works with existing data volumes. Hydra never uses the application's
    superuser.
  - `hydra-migrate`: a one-shot `migrate sql up -e --yes`.
  - `hydra`: `serve all --dev`, with a health check on `/health/ready`.
  - Hydra uses **host networking**, so the issuer, the browser, and
    back-channel calls to apps on the host all use the same loopback
    addresses. Its config binds both ports to `127.0.0.1` only. Docker Desktop
    users must enable host networking.
- `deploy/hydra/hydra.yml`:
  - Issuer `http://127.0.0.1:4444`; login, consent, and logout at
    `http://localhost:8080/sso/*`; `post_logout_redirect` at the provider
    sign-in page.
  - `oidc.subject_identifiers.supported_types: [public]`,
    `log.leak_sensitive_values: false`.
  - TTLs: auth code 10m, ID token 1h, access token 1h, login and consent
    request 30m.
  - Secrets (`SECRETS_SYSTEM`, `SECRETS_COOKIE`) and the DSN come from the
    environment, with development-only fallbacks in `compose.yaml`.
  - `urls.error` points to the provider's `/sso/error` page (added after
    Phase 4). It shows a localized message chosen by the OAuth error code and
    a way back to sign-in; Hydra's free text is never echoed.
- `scripts/hydra-dev-client.sh` (`make sso-client`) recreates the
  `goweb-dev-client` client:
  - redirect `<client>/en/oauth/sso/callback`, matching how the Google
    redirect URL is derived
  - post-logout `<client>/en/sign-in`
  - back-channel `<client>/oauth/sso/backchannel-logout` with `sid` required
  - `skip_consent`, `skip_logout_consent`, `client_secret_basic`, and scopes
    `openid email profile`

  It prints the client credentials; it never writes them to files.
- `Makefile`: `sso-up`, `sso-client`; `db-down` also stops the `sso` profile.
  A `run-client` target moves to Phase 4, when client mode exists.
- Docs: a "Running SSO locally" section in `docs/local-development.md`, and
  `HYDRA_*` placeholders in `.env.example`.
- Dev host names: run the provider on `http://localhost:8080` and clients on
  `http://127.0.0.1:<port>`. Cookies ignore ports, so the same host name would
  make provider and client session cookies overwrite each other.
- Later addition, for testing from another machine: the `SSO_DEV_BIND`,
  `SSO_DEV_ISSUER_URL`, `SSO_DEV_PROVIDER_URL`, and `SSO_DEV_CLIENT_URL`
  settings, with `make run-provider` and the `sso-backchannel-relay`.
  - Hydra's issuer and redirect URLs now come from `compose.yaml` environment
    variables instead of `hydra.yml`.
  - Hydra v26.2.0's outbound SSRF guard hard-codes the allowed private ranges
    (loopback, RFC 1918, link-local) and refuses Tailscale's `100.64.0.0/10`,
    even for URLs listed in `clients.http.private_ip_exception_urls`. The dev
    client's back-channel logout therefore targets a loopback socat relay.
  - Production client apps must have back-channel URLs Hydra may call:
    public, or in an allowed private range.

Verified: `make sso-up` starts a healthy Hydra (224 migrations applied).
Discovery returns the configured issuer. Both ports listen on `127.0.0.1`
only. The registered client has the expected URIs and flags.

## Phase 2: Configuration and mode switch (done)

`internal/config` (`applyAuthMode`, `ErrInvalidAuthMode`):

- `GOWEB_AUTH_MODE` = `local|provider|client`, case-insensitive, default
  `local`.
- Provider mode requires `GOWEB_HYDRA_ADMIN_URL`: absolute http(s), no
  credentials, query, or fragment.
- Client mode requires `GOWEB_SSO_ISSUER_URL`, `GOWEB_SSO_CLIENT_ID`, and
  `GOWEB_SSO_CLIENT_SECRET` (a `config.Secret`). `GOWEB_SSO_REDIRECT_URL` is
  derived as `<GOWEB_PUBLIC_URL>/en/oauth/sso/callback`, matching the
  registered dev client. `GOWEB_SSO_ACCOUNT_URL` is optional.
- Every environment rejects:
  - settings that belong to another mode (instead of silently ignoring them)
  - `provider` or `client` without `GOWEB_DATABASE_URL`
  - Google sign-in on a client, because it belongs on the provider
- Production (`ErrUnsafeProductionConfig`) requires HTTPS for the client's
  issuer, callback, and account URLs. The provider's Hydra admin URL may stay
  plain HTTP, since it must only be reachable on a private network.
- Redaction tests cover the client secret. `/{language}/admin/system` shows the
  sign-in mode, and shows the issuer and Hydra admin rows (scheme and host only)
  when they are set.

Scope change: until a mode's endpoints exist, `app.New` rejects `provider` and
`client` with `app.ErrAuthModeNotImplemented`, so a deployment never runs
half-wired. Phase 3 removed the guard for `provider`, and Phase 4a removed the
guard entirely.
Route registration per mode moved to Phase 4, where the SSO routes that
replace the local sign-in routes are built and testable.

Verified:
- `go test -race -shuffle=on ./...` and `go vet ./...` pass.
- The built binary prints clear, secret-free startup errors for each invalid
  mode setting, and the guard error for a valid `provider` configuration.
- The rendered system page shows "Sign-in mode: local" in a local run. A
  handler render showed the client and provider rows.

## Phase 3: Provider mode (done)

What was built, keeping the hexagonal boundaries:

- `internal/adapter/hydra` (`AdminClient`): the admin API over `net/http`.
  - Covers get, accept, and reject for login and consent; get and accept for
    logout; revoking login sessions by `sid`; revoking consent by subject with
    `all=true`.
  - 10 s timeout and a 1 MiB response cap. Redirect targets must be absolute
    http(s). 404 and 410 map to `ErrSSOChallengeExpired`, other failures to
    `ErrSSOUnavailable`. It never logs, and errors never include response
    bodies, challenges, subjects, or session IDs.
- `internal/service/sso_provider.go` (`SSOProviderService`, `SSOAdmin` port):
  - `BeginLogin` accepts Hydra's remembered subject on `skip` (rejected if the
    account was deleted or is no longer eligible). It also accepts at once for
    a browser already signed in to the provider; otherwise it asks for the form.
  - `CompleteLogin` runs after any sign-in.
  - `Consent` runs on every sign-in. It records `(login_session_id, user)`;
    when that fails, it refuses rather than issue an unrevocable session. Claims
    follow the scopes: `email` gives `email` and `email_verified`; `profile`
    gives `name` (display name, else username) and `locale`.
  - `Logout` forgets the `sid`.
  - `RevokeUser` revokes every recorded `sid`, then consent. Records whose
    revocation failed are kept for a retry.
  - Eligible accounts exist, are not guests, and have a confirmed email when
    confirmation is required.
  - The subject is the account ID in canonical decimal. Hydra remembers the
    session for `GOWEB_SESSION_LIFETIME`.
- Migration `000012_create_sso_login_sessions` and
  `internal/store/postgres/sso.go`:
  - A repeat sign-in keeps the later expiry.
  - A `sid` already recorded for another account is never taken over.
  - Rows cascade with the account and expire through the existing token
    retention job (`DeleteExpiredSSOLoginSessions`); no new job or setting.
- Revocation: `SessionService.SetSSORevoker` makes `RevokeUser` (administrator
  revocation, password change, password reset) also revoke Hydra sessions.
  Administrator account deletion now revokes before deleting, because the
  cascade removes the recorded `sid`s; a failed revocation blocks the deletion.
- HTTP (`internal/adapter/http/sso.go`), registered only in provider mode:
  - `GET /sso/login`, `/sso/consent`, `/sso/logout`.
  - The pending challenge lives in the `goweb_login_challenge` cookie
    (`HttpOnly`, `SameSite=Lax`, 30 minutes).
  - `finishSignIn` completes it after password sign-in and sign-up. The Google
    callback now goes through `finishSignIn` too, with unchanged behavior
    outside provider mode. It uses `HX-Redirect` for HTMX forms.
  - An expired challenge falls back to `/home`. Failures on `/sso/*` land on
    `/sign-in?sso=expired` with a localized alert.
- Provider sign-out sends the browser to Hydra's `/oauth2/sessions/logout`,
  so the single sign-on session ends as well. Without this, client apps would
  keep signing the browser in. That is why provider mode now also requires
  `GOWEB_SSO_ISSUER_URL`, which must be HTTPS in production.

Findings while building:

- Hydra challenges are **padded** base64url, so `=` appears depending on the
  length. The first strict validator rejected some consent challenges.
- Logout CSRF (a third-party page forcing logout) is accepted as low impact
  and recorded in the threat model.

Verified:
- Unit tests cover the service (skip versus local session, ineligible
  accounts, claims per scope, `sid` recording and record failure, revocation
  with partial failure), the adapter (paths, bodies, error mapping, redirect
  validation), and HTTP (route presence per mode, cookie attributes,
  `CompleteLogin` receiving the session's account, HTMX, expired fallbacks,
  logout, sign-out through Hydra).
- An integration test checks the repository against PostgreSQL.
- An end-to-end run with Playwright against the real Hydra (`v26.2.0`) passed
  17 checks:
  - A visitor signs up during the flow, and the client gets a code.
  - `sub` is the account ID, and the email claims are present.
  - The `sid` is recorded and the challenge cookie cleared.
  - A second sign-in skips the form within the same Hydra session.
  - Administrator "revoke sessions" removes the records, makes the access
    token inactive, and triggers back-channel logout; the next sign-in asks
    for credentials.
  - A password sign-in completes a pending flow.
  - Provider sign-out goes through Hydra and back, and both the provider and
    Hydra sessions are gone afterwards.
- The provider log contained no challenges, session IDs, or authorization
  codes.

## Phase 4a: Client mode (done)

What was built:

- `internal/adapter/oidc` (`Client`): a relying party using only the standard
  library.
  - Discovery on first use. The document's `issuer` must equal the configured
    issuer exactly.
  - The key set (JWKS) is cached by `kid`. An unknown `kid` refreshes it at
    most every 30 s.
  - Only RS256 keys of at least 2048 bits are accepted; `alg` must be RS256
    and the `crit` header is rejected.
  - ID token checks: exact `iss`; `aud` contains the client, with `azp` equal
    to the client when there are several audiences or when present; `exp` and
    `iat` with 60 s of clock skew; a `sub` is present; and an `events` claim
    is rejected so a logout token cannot pass as an ID token.
  - Logout token checks (Back-Channel Logout 1.0 §2.6): `iss`, `aud`, `iat`
    within 5 minutes, `jti`, the back-channel event as an object, `sid`, and
    no `nonce`.
  - The code is redeemed with `client_secret_basic`, credentials form-encoded
    per RFC 6749 §2.3.1.
- `internal/service/sso_client.go` (`SSOClientService`, `SSORelyingParty`
  port). This is deliberately not a generic provider in `OAuthSignInService`:
  client mode must bind sessions to the `sid`, accept accounts whose email the
  provider has not verified, and link by verified email.
  - `Start` reuses the hashed one-time OAuth state with PKCE (provider `sso`).
  - `Callback` maps the subject through `oauth_identities` and refreshes the
    email and name the provider owns (a failed refresh never blocks sign-in).
    On first sign-in it creates the account, or links an existing local
    account only when both sides have a verified email; otherwise it refuses
    with `ErrOAuthEmailConflict`. It then calls `SessionService.CreateSSO`.
  - `BackChannelLogout` revokes every session bound to the `sid`.
  - `SignOutURL` builds Hydra's logout URL with the stored `id_token_hint`.
- Migration `000013_session_sso_binding`: `sessions.sso_sid` (indexed) and
  `sessions.sso_id_token`. `Session` gains write-only `SSOSessionID` and
  `SSOIDToken`; `CreateSSO` never returns the token.
- HTTP, in client mode:
  - `/sign-in` renders one "Continue to sign in" button (with `?sso=error`
    and `?sso=expired` alerts). `/oauth/sso` starts the flow, and its callback
    requires the browser-bound state cookie.
  - `POST /oauth/sso/backchannel-logout` is exempt from CSRF through the new
    `middleware.WithCSRFExemptPath`, which matches one exact path.
  - Sign-out reads the hint first, revokes locally, then sends the browser to
    Hydra's logout.
  - Not registered in client mode: sign-up, password sign-in, password
    recovery, confirmation, guest upgrade, and password, profile, and identity
    settings.
  - Admin pages hide account creation, confirmation controls, and identity
    removal.
  - The settings page shows an account card linking to
    `GOWEB_SSO_ACCOUNT_URL`. The layout hides "Create account".
- The client guard (`app.ErrAuthModeNotImplemented`) is removed. Production
  still requires HTTPS for the issuer, callback, and account URLs.
- Dev tooling:
  - `sso-db-init` (renamed from `hydra-db-init`) also creates the
    `goweb_client` database.
  - `make sso-client` writes the git-ignored, owner-only `.env.client`.
  - `make run-client` starts the client on `127.0.0.1:8081`.
- Bootstrap administrators need nothing new. The client seeds its own
  administrator from `.env`. Signing in to the client as the provider's
  confirmed administrator with the same email links the accounts through the
  verified-email rule.

Verified:
- Unit tests for the relying party, using real RSA keys and a fake issuer:
  - `alg` none, HS256 signed with the public key, tampered claims, unknown
    `kid`, a 1024-bit key, `crit`, wrong `iss` or `aud`, expiry and skew,
    several audiences without `azp`, and a logout token offered as an ID token
    and the reverse.
  - Every logout-token rule.
  - Key rotation honouring the refresh pause, an issuer mismatch at
    discovery, and secret redaction.
- Service tests cover new, refreshed, linked, and conflicting accounts;
  rejected states and identities; back-channel logout; and the sign-out URL.
- HTTP tests cover the routes absent in client mode, the sign-in page, the
  state cookie, the callback branches, the back-channel endpoint (and its
  absence elsewhere), sign-out ordering, and the settings page.
- PostgreSQL integration tests cover the binding columns and revocation by
  `sid`.
- An end-to-end run of provider, client, and Hydra `v26.2.0` passed 16 checks:
  - Sign-up at the provider during a client sign-in, with the client account
    linked to the subject and the session bound to the `sid`.
  - The SSO settings card.
  - A silent second sign-in.
  - Provider administrator "revoke sessions", which reached the client
    through back-channel logout.
  - Client sign-out, which ended the client, provider, and Hydra sessions.
  - Provider sign-out, which reached the client through back-channel logout.
  - Administrator linking by verified email, and the trimmed admin controls.
- Neither app's log contained tokens, codes, challenges, or session IDs.

## Phase 4b: Guest upgrade through single sign-on (done)

- In client mode, `/{language}/guest/upgrade` shows a "Sign in to keep this
  account" button instead of the email and password form. It is a plain,
  CSRF-protected POST because the browser has to navigate to the issuer.
- `SSOClientService.StartUpgrade` checks that the account is a guest and stores
  a one-time state with the existing `link` action, bound to the guest's ID. No
  migration was needed.
- `Callback` now receives the account signed in to the browser presenting the
  callback. A `link` state completes only for that same guest; any other
  browser account, or none, is refused before the code is redeemed.
- `upgradeGuest` refuses, leaving the guest untouched, when:
  - the issuer identity already has an account here (`ErrSSOGuestIdentityTaken`;
    accounts are never merged)
  - the email belongs to another account (`ErrOAuthEmailConflict`)
  - the account is no longer a guest
- Otherwise it calls `UserRepository.UpgradeGuestWithIdentity`. In one
  transaction, and only while the account is still a guest at the expected
  version, that call:
  - converts the guest, keeping its ID, theme, locale, and data
  - sets the email (verified when the issuer says so) and the display name
  - links the identity
  - revokes the transfer code

  Races still map to the same refusals. Every guest session is then revoked,
  and this browser gets a new session bound to the Hydra session.
- When the callback fails for a guest browser, it returns to the upgrade page
  with an alert (`?sso=taken`, `conflict`, or `error`). A guest only reaches the
  issuer through this flow.

Verified:
- Service tests check that the guest's preferences survive, the identity and
  the code revocation, the session revocation and the new bound session, and
  every refusal (other or no browser account, no longer a guest, identity
  taken, email taken, and both races).
- HTTP tests check the button page and alert, starting only for a guest, the
  state cookie, the callback passing the signed-in account, and failure
  redirects.
- A PostgreSQL integration test checks success and all-or-nothing behaviour:
  a taken subject, a taken email, or a stale version leaves the guest, its
  transfer code, and the identities unchanged.
- An end-to-end run of provider, client, and Hydra passed 9 checks:
  - A client guest joined a group, chose "Sign in to keep this account", and
    signed up at the provider. The same account ID came back as a full account
    with the email, the identity linked to the provider subject, the group
    membership kept, the old guest session revoked, a new session bound to
    Hydra, and the SSO settings card.
  - A second guest signing in as that existing account was sent back with the
    "already has an account" alert and stayed a signed-in guest.

## Phase 5: End-to-end verification and docs

- Browser spec `tests/browser/m10-sso.spec.ts`, opt-in like the others, with
  the provider on `:8080`, a client on `:8081`, and Hydra from compose. It
  covers:
  - First visit to the client leads to the provider sign-in and back, signed
    in.
  - A second client visit is silent: no form shown.
  - Sign-out at the client also ends the provider session.
  - An administrator "revoke sessions" at the provider makes the client's next
    request unauthenticated.
  - Password reset at the provider has the same effect.
  - A guest upgrade on the client keeps the guest's groups.
- CI: keep the browser spec opt-in. Add a Go integration test that runs only
  when `GOWEB_HYDRA_TEST_ADMIN_URL` is set.
- Docs to update:
  - `architecture.md`: modes, new packages, the SSO flow.
  - `threat-model.md`: new trust boundaries (browser ↔ Hydra, provider →
    Hydra admin, Hydra → client back-channel) and new credentials (login
    challenge cookie, `sid`, client secret, ID and logout tokens, Hydra
    system secret).
  - `deployment.md`: Hydra hosting, migrations, key rotation, client
    registration procedure, keeping the admin port private.
  - `local-development.md`, `bootstrap-admin.md`, `backup-retention.md` (Hydra
    database backups), `.env.example`, `AGENTS.md` runtime section.

## Phase 6: Production rollout

1. Deploy Hydra behind TLS. Keep the admin API on a private network only,
   because whoever reaches it can sign in as anyone. Use separate system and
   cookie secrets stored in the secret manager. Back up the Hydra database
   like the application database.
2. Switch the identity deployment from `local` to `provider`. It is
   backward-compatible: its own users and sessions are untouched.
3. Register each client app with production URLs. Store the client secret
   through the platform's secret store.
4. New apps from the template start in `client` mode. Converting an existing
   `local` app requires its users to exist at the provider. Import them, or
   rely on verified-email linking from Phase 4, and run a dry-run report of
   emails that would conflict.
5. Run the OpenID Foundation conformance suite against Hydra's configuration
   for the relying-party flows before the first production client.

## Risks and open questions

- **Lost back-channel calls.** Hydra makes 3 delivery attempts about 2 s
  apart, then gives up (Phase 0). If a client is down during revocation, its
  local session lives until expiry. Mitigation: keep `GOWEB_SESSION_LIFETIME`
  short in client mode (for example 8h), and let expiry re-authenticate
  silently through Hydra while the provider session is alive.
- **Hydra version churn.** The versioning scheme changed after `v2.3.0`. Pin
  exact tags and read release notes before upgrades.
- **Shared locale and theme.** These stay per app by design. Revisit if users
  expect them to follow them across apps.
- **Admin roles across apps.** These stay per app by design. A future
  `roles` claim would need its own decision.
- **Rate limits** remain in process memory per instance. This is unchanged
  but matters more once the provider serves every app's sign-ins.

## Out of scope

Third-party clients and consent screens, mobile or SPA public clients,
API access tokens for service-to-service calls, pairwise subjects, MFA, and
social providers on client apps (they belong on the provider).
