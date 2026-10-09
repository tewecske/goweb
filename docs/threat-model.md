# Security Threat Model

This document records the trust boundaries, bearer credentials, abuse controls,
data ownership, and operational assumptions for the server-rendered Go and HTMX
application. It describes the system as implemented; update it when boundaries,
credentials, or controls change.

## Scope and assets

In scope: the HTTP application (`internal/adapter/http`), application services
(`internal/service`), persistence adapters (`internal/store`), the PostgreSQL
database, configured mail relay, external identity providers, and the
administrator surface.

Assets to protect:

- Account credentials: password hashes and current passwords.
- Session credentials and the authority they carry.
- Single-use bearer credentials: email confirmation, password reset, guest
  transfer codes, and group invite codes.
- OAuth flow state and external provider subjects.
- Administrator audit history and sign-in history.
- Deployment secrets: database URL, session secret, bootstrap administrator
  password, mail relay.
- Operational data: usage events, request IDs, trace IDs.

## Trust boundaries

| Boundary | Crosses from → to | Controls |
| --- | --- | --- |
| Browser → HTTP adapter | Untrusted input | Server-side validation, `html/template` escaping, CSRF, cross-origin request rejection, authorization middleware, size-bounded lists, 256 KiB request bodies, server read/write/idle timeouts; Content-Security-Policy allows same-origin scripts and styles only and forbids framing |
| Reverse proxy → HTTP adapter | Network metadata and trace context | `X-Request-ID` generated server-side; incoming W3C `traceparent` continued only from `GOWEB_TRUSTED_PROXY`; client IP taken from the right-most untrusted `X-Forwarded-For` hop only when the peer is `GOWEB_TRUSTED_PROXY`, otherwise the peer address without its port |
| HTTP adapter → services | Principal and request data | Authentication and authorization checked in each handler/fragment; principal carries only ID and admin flag |
| Services → PostgreSQL | Query parameters and secrets | Parameterized queries via `database/sql`, adapter maps errors without echoing bearer values |
| Services → mail relay | Message content | Plain-text messages; tokens may appear in the message body but never in logs, traces, metrics, or diagnostics |
| Services → external providers | OAuth redirect and state | Top-level browser navigation; single-use server-side state; provider failure returns to a readable sign-in/settings state |
| Operators → administrator surface | Administrative authority | Shared admin authorization guard, per-action audit records mirrored to a separate security log stream with actor and target IDs; privilege grants, revocations, and password resets have their own action codes; site administrators' changes to groups they do not administer are audited; a record that cannot be stored is still reported to the security stream as failed |
| Application → logs/traces/usage | Diagnostic output | Stable low-cardinality fields; no passwords, hashes, sessions, tokens, provider subjects, query strings, or credentials |

## Bearer credentials

| Credential | Form and storage | Exposure window | Controls |
| --- | --- | --- | --- |
| Session cookie | `goweb_session`, opaque 32-byte random hex; server-side `sessions` row | Until expiry or revocation | `HttpOnly`, `SameSite`, `Secure` outside development; server validates expiry and revocation on every request |
| CSRF token | `goweb_csrf` cookie plus `_csrf` field / `X-CSRF-Token` header | Per browser session | Double-submit, constant-time compare, `HttpOnly`, `SameSite=Strict`, `Secure` whenever session cookies are, malformed cookies replaced; required on every state-changing request after `http.CrossOriginProtection` rejects cross-origin and sibling-subdomain browser requests |
| Email confirmation token | 32-byte token stored as its SHA-256 digest in `email_verification_tokens` | Single use, default 24h | Consumed atomically; expired/consumed tokens rejected; never logged |
| Password reset token | 32-byte token stored as its SHA-256 digest in `password_reset_tokens` | Single use | Consumed atomically; expired/consumed tokens rejected; never logged |
| Guest transfer code | Single active code per guest, partial unique index | Until revoked or used | One active code per guest; revocable; redeemed atomically; never logged |
| Group invite code | 12-character code, unique per group | Until rotated | Administrators can rotate; unique constraint; join is rate limited and idempotent |
| OAuth state | 32-byte random state stored as its SHA-256 digest in `oauth_states`, mirrored in the `goweb_oauth_state` browser cookie | Single use, expiring | Action allowlist, atomic consumption with a single winner; the callback must present the matching `HttpOnly` cookie from the browser that started the flow; a link completes only for the signed-in account that started it; a per-state PKCE S256 code verifier is required to redeem the authorization code |
| Password hash | Argon2id encoded hash in `users.password_hash` | Stored indefinitely for the account | Never returned or logged; stripped from public user values |
| Provider subject | `oauth_identities` unique `(provider, subject)` | Stored with the linked account | Never rendered or logged; removed on unlink or account deletion |
| Deployment secrets | `config.Secret` values from environment | Process lifetime | Redacted from formatting and JSON; production startup rejects unsafe configuration |

Additional sources of authority: server-generated request IDs, single-use OAuth
state, and revision-checked writes. None are trusted from the client.

## Abuse controls

- **Authentication rate limits**: independent fixed-window budgets for
  `signin.identifier` and `signin.origin`; successful authentication clears both.
- **Sign-up limits**: a `signup.origin` budget bounds account creation and
  probing for registered emails.
- **Password hashing**: concurrent Argon2id derivations are capped so floods
  of sign-in, sign-up, or reset requests cannot exhaust memory; password reset
  hashes only after its token is consumed.
- **Email confirmation**: when `GOWEB_EMAIL_CONFIRMATION_REQUIRED` is true,
  sign-up sends the confirmation link and issues no session until the email is
  confirmed. OAuth sign-up requires an email the provider has verified.
- **Guest limits**: separate `guest.create` and `guest.redeem` origin budgets.
- **Invite limits**: `group.invite.join` budget on invite redemption.
- **Bounded limiter state**: limiter key counts are capped to prevent unbounded
  memory growth; at the cap the oldest key that is not blocked is evicted, so
  flooding with fresh keys cannot lock out other callers or lift an active
  block; keys are redacted in administrator diagnostics.
- **Origin keys**: origin budgets use the client IP without the source port, so
  new connections do not get fresh budgets; IPv6 clients share one budget per
  /64 prefix.
- **Lockout visibility**: administrators can read and clear live lockout state;
  clearing is confirmed, authorized, and audited.
- **Suspicious-account signals**: accounts exceeding action-count or
  distinct-origin thresholds are surfaced as investigation flags, not
  automatic enforcement.
- **Optimistic locking**: revision-checked writes reject stale edits as
  conflicts and vanished records as not-found.
- **Session revocation**: a user or administrator can end sessions immediately;
  the next request re-authenticates server-side. Changing a password in account
  settings, redeeming a reset link, or an administrator password reset ends
  every session for the account; a settings change issues a new session to the
  requesting browser. An account without a password can set its first password
  only from a session signed in within the last 10 minutes.
- **CSRF and authorization**: repeated on fragments, not only full pages.
- **Bounded work**: list page sizes, search lengths, and sort keys are validated
  and clamped server-side; query strings never reach logs, traces, or usage rows.
- **Backpressure**: the usage-event queue applies bounded backpressure and never
  fails the user request; a full queue drops observation rather than data.

## Data ownership and lifecycle

- Owned credentials cascade on account deletion: sessions, OAuth identities,
  confirmation and reset tokens, guest claim codes, memberships, and OAuth
  states.
- Historical records survive account deletion with a nulled reference:
  `login_attempts`, `audit_log`, `usage_events`, and `groups.created_by`. Shared
  groups are not deleted when their creator is removed.
- The administrator audit log is preserved deliberately as the record of
  administrator action. Retention cleanup does not remove it.
- Old, empty abandoned guests are deleted only when they own no group
  membership and hold no credentials to preserve.
- See [backup and retention](backup-retention.md) for periods and schedules.

## Operational assumptions

- TLS terminates before the application; production startup requires a
  `https` public URL and secure session cookies.
- Secrets are provided by the platform secret store and never committed.
- Database access is restricted to the application and operators; backups are
  encrypted and access-controlled.
- Only one instance performs startup migrations, serialized by a PostgreSQL
  advisory lock; the schema is forward-only.
- The host clock is trustworthy; session, token, and rate-limit windows depend on
  it.
- Log aggregation is access-controlled. Security events are separately
  identifiable but still contain only stable, non-secret fields.
- The mail relay is referenced by host only and is required in production;
  `smtp://` relays upgrade with STARTTLS when offered and `smtps://` relays use
  implicit TLS. The application does not store SMTP
  credentials and does not log message bodies.

## Threat analysis

| Threat | Boundary | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Credential stuffing / brute force | Browser → adapter | Per-identifier and per-origin rate limits, lockout diagnostics, durable sign-in history | Distributed multi-instance deployments get per-instance budgets |
| Session theft | Browser ↔ adapter | `HttpOnly`/`SameSite`/`Secure` cookie, server-side revocation and expiry | Malware on the client or a compromised proxy |
| CSRF | Browser → adapter | Double-submit token on every state-changing request, constant-time compare | XSS would defeat any token scheme |
| Token replay | Browser → adapter | Single-use atomic consumption, expiry, uniform failure messages | A stolen link used before the legitimate user |
| Account enumeration | Public forms | Uniform failure responses for unknown account and wrong password | Timing differences outside the response shape |
| Stale-write data loss | Adapter → database | Optimistic locking; conflicts distinguished from not-found | Concurrent editors must reload |
| Data leakage via logs/traces | App → observability | Secret-free structured fields, query-string stripping, redaction tests | Misconfigured downstream pipeline |
| Administrator action repudiation | Admin surface | Per-action audit records with actor, target, time, origin, mirrored to security stream | Audit store compromise |
| Database compromise | Services → PostgreSQL | Least-privilege DB access, encrypted backups, parameterized queries; sessions, confirmation and reset tokens, and OAuth state stored only as SHA-256 digests | Full-database access exposes password hashes and guest transfer codes |
| Provider compromise | Services → provider | Top-level navigation, single-use state, readable failure recovery | Provider-side account takeover |
| Denial of service | Browser → adapter | Bounded queues, clamped inputs, graceful shutdown | No in-app WAF; rely on the edge |

## Out of scope

- Multi-factor authentication and hardware keys.
- Distributed rate limiting across instances.
- Edge controls (WAF, DDoS protection, HSTS) owned by the deployment platform.
- Compromised operator credentials or a compromised database host.
- Email deliverability and relay provider security.
