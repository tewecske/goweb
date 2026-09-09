# Web Application Feature Template

## Purpose

This is a private, account-based web application foundation. It provides the account, security,
administration, collaboration, preference, and operational features that many web applications need.

The application is designed around these principles:

- The server enforces every permission and validation rule.
- The user interface explains failures near the affected action or field.
- Administrators manage accounts and system health, not private user-owned content.
- Historical security records remain useful after an account is deleted.
- Secrets and credentials never appear in responses, logs, traces, or diagnostic screens.
- Client and server behavior stays consistent through shared validation and interface contracts.

## Authentication

### Account creation

- Visitors can create an account with an email address and password.
- Email addresses are unique without regard to case or surrounding spaces.
- Passwords have a minimum and maximum length.
- Passwords are stored only in an irreversible password-specific form.
- Passwords are never shown, returned, or logged.
- A duplicate email address produces a clear duplicate-account error.
- Optional usernames provide a second sign-in identifier.
- Usernames are normalized, unique without regard to case, and cannot contain `@`.
- Optional display names identify an account in the interface.

### Sign-in

- Users can sign in with an email address or username and password.
- Users can sign in through configured external identity providers.
- An unknown account and a wrong password produce the same normal sign-in failure.
- A successful sign-in creates a session that lasts for a fixed period.
- Signing out ends the current session immediately.
- Signing out without a session is harmless.
- Expired or revoked sessions cannot authenticate.
- A page that needs authentication redirects an unauthenticated visitor to sign-in.
- A signed-in user visiting an anonymous-only page is redirected to an appropriate signed-in page.
- A signed-in non-administrator visiting an administrator page receives an access-denied result.

### Session protection

- Sessions use opaque credentials that are not meaningful outside the server.
- Session credentials are protected by secure cookie settings.
- State-changing requests require proof that they came from the application itself.
- Each authentication action has its own rate-limit budget.
- Sign-in attempts are limited both per account identifier and per request origin.
- Successful sign-in clears the relevant failed-attempt state.
- A lockout reports its cause and retry time without exposing account existence unnecessarily.
- Security-related events are recorded separately from ordinary application logs.

### Email confirmation

- Password account creation can send a confirmation link.
- A confirmation link expires after a fixed period and can be used once.
- Unknown, expired, and already-used links have the same response.
- Resending a link uses its own rate limit.
- Resending produces the same result for unknown, confirmed, and existing unconfirmed addresses.
- Whether confirmation is required before sign-in is a deployment setting.
- When confirmation is required, the password is checked before reporting an unconfirmed address.
- A user refused for this reason can request another link.
- Accounts created by administrators start confirmed.
- External sign-in starts confirmed only when the provider confirms the address.
- Expired and used confirmation records are removed by maintenance.

### Password recovery

- A visitor can request a password reset without signing in.
- Unknown and known addresses receive the same response.
- Reset requests have their own rate limit.
- Reset links expire and can be used once.
- Unknown, expired, and used reset links have the same response.
- A reset replaces the password and invalidates all existing sessions.

### External identity providers

- Each provider is configured independently.
- An unconfigured provider is absent from all screens and cannot be reached by guessing its route.
- A provider's permanent account identifier, not its reported email, selects an existing account.
- An unknown provider identifier for an already-used email is refused rather than merged.
- An unknown provider identifier for an unused email can create an account.
- The same provider identifier always selects the same account.
- A signed-in user can attach a provider from account settings.
- Attaching an already attached identity is refused.
- Attaching a provider confirms the address only when it confirms the same address.
- A user cannot remove the last remaining sign-in method.
- Removing an identity that is not attached is an error.
- Provider failures return the user to sign-in or settings with a readable message.

## Guest Users

- A visitor can use the application without registering first.
- A guest account is created lazily on the first operation that needs ownership, never on page view.
- A guest has an ordinary account and session but no email address or password.
- A guest receives a random username so the account can be identified in the interface.
- The guest can replace that username later.
- The guest's current visual theme is copied when the account is created.
- The account can issue a transfer code for use on another device.
- The transfer code is random, short enough to transcribe, and shown only when requested.
- Repeated requests return the same active code instead of silently replacing it.
- A valid code signs another device into the same account. It does not copy the account.
- The code can create multiple sessions for the same account.
- Unknown, mistyped, and revoked codes have the same failure response.
- Code redemption has its own rate limit.
- Guest creation has a separate rate limit from sign-in.
- A guest can upgrade in place by adding an email address and password.
- Upgrade keeps the same account identity and all owned application data.
- An already-used email address blocks the upgrade.
- Upgrade turns the guest into a normal account and invalidates the transfer code.
- Only empty, abandoned guests are removed by retention maintenance.
- A guest that owns data is never removed by abandoned-guest cleanup.

## Groups

- Signed-in users can view the groups available in the application.
- Each group has a name and a membership roster.
- Creating a group makes the creator its first administrator.
- A group has two roles: administrator and member.
- A group always keeps at least one administrator.
- Users join by redeeming an invite code.
- Joining is idempotent. Redeeming the same code twice does not create duplicate membership.
- Joining by code always creates an ordinary member, never an administrator.
- Administrators can rename a group and regenerate its invite code.
- Regenerating a code immediately invalidates the previous code.
- Administrators can promote, demote, and remove members.
- Members can leave voluntarily.
- Leaving, demoting, or removing the only administrator is refused.
- Members cannot perform administrator actions.
- Group names and aggregate counts can be shown more broadly than the roster.
- Only members can view the full roster.
- Only administrators can view the current invite code.
- Group membership can grant access to shared application resources without transferring ownership.
- Deleting an account removes its memberships but does not destroy a shared group solely because its creator was deleted.
- Invite-code guessing and other code-based joins are rate limited.

## Account Settings

The settings area lets a signed-in user manage their own account.

- Set or clear the optional username.
- Set or clear the optional display name.
- Use the display name, then username, then email as the account label shown in the interface.
- See whether a password exists.
- Set the first password on an externally authenticated account.
- Change an existing password by supplying the current password.
- Show a wrong current password error beside the current-password field.
- Show a weak new password error beside the new-password field.
- View linked external identities.
- View providers enabled by this deployment.
- Add an external identity through its provider flow.
- Remove an external identity unless it is the last sign-in method.
- Change the account language preference.
- Change the account visual theme.
- Show validation only after the first submit.
- Clear an individual field error when that field is corrected.

## Language Selection

- The application supports multiple languages across public pages, signed-in pages, validation, and server responses.
- The current page language is explicit in the URL.
- Changing language navigates to the equivalent page in the selected language.
- The selected language is stored on the account for transactional messages and future prefix-less visits.
- Preference order is: explicit URL, account preference, browser storage, browser language, default language.
- A URL language always overrides every other preference.
- Server errors carry stable message identifiers and a fallback message, not language-specific prose only.
- Every message identifier exists in every supported language catalog.
- Catalogs have matching placeholders and plural forms.
- Labels are translated, but stored values and protocol codes remain stable.
- Dates and times follow the current page language.
- Language names and brand names keep their own names where appropriate.

## Theme Selector

- The application supports light and dark themes.
- The selector works for signed-out visitors.
- A signed-out visitor's choice is stored in browser preferences.
- A signed-in user's choice is stored on the account and applies immediately.
- The account preference follows the user to another browser after sign-in.
- A guest starts with the theme already active in the browser.
- Theme changes update the whole interface without requiring a page reload.
- A failed preference update must not leave the control showing a state the server rejected.

## Administrator Area

Only administrators can access this area. The server checks this permission for every request.

### Account list

- List all accounts with identifier, administrator status, confirmation status, and creation time.
- Search by a case-insensitive substring.
- Sort by supported columns in ascending, descending, or default order.
- Paginate in the data store, not after loading all rows.
- Keep page, size, filters, and sorting in the URL so views can be bookmarked and revisited.
- Bound invalid page and size values instead of allowing unbounded requests.
- Re-read list data after changes so multiple tabs and devices agree.

### Account management

- Create an account with email, password, and administrator status.
- Edit an account's email and administrator status.
- Leave the password empty to keep the current password.
- Supplying a password replaces it.
- Apply profile changes and password replacement atomically.
- Resetting a password ends every session for that account.
- Delete an account only after explicit confirmation.
- Remove account-owned application data and dependent credentials on deletion.
- Preserve historical security records that describe activity involving the deleted account.
- Prevent an administrator from deleting their own account.
- Prevent an administrator from removing their own administrator status.
- Enforce all of these restrictions on the server, not only in the interface.

### Account diagnostics

The account detail page helps support an account without exposing credentials or private content.

- Show confirmation state and relevant confirmation-link status without showing the link.
- Send a fresh confirmation link.
- Confirm an address directly when support has verified ownership.
- Show successful and failed sign-in attempts, time, outcome, and origin.
- Keep sign-in attempts after the related account is deleted.
- Show current lockout state, attempt count, limit, and remaining time.
- Clear all dimensions of a lockout, including account and recent-origin keys.
- Show active session count and session start and expiry times.
- End all sessions for an account.
- Never show a session identifier because it is itself a credential.
- Show linked providers and provider-reported display metadata without showing provider secrets or permanent identifiers.
- Remove a linked provider while enforcing the last-credential rule.
- Return not-found when an account disappears between list and detail views.

### Audit trail

- Record every administrator action.
- Store time, acting administrator, target, action, detail, and request origin.
- Emit the security log and store the audit record from the same action record operation.
- Do not allow a logging or audit-storage failure to undo a completed account action.
- List audit entries newest first by default.
- Filter by action, administrator, and target.
- Paginate the results.
- Preserve entries after the actor or target account is deleted.
- Store a display snapshot of the actor when needed for historical identification.
- Never store passwords, session credentials, confirmation links, or external permanent identifiers.

### System page

The system page describes deployment health without exposing secrets.

Show safe configuration facts:

- Environment and public address.
- Whether email confirmation is required.
- Whether secure session cookies are enabled.
- Which external providers are configured.
- Whether outgoing mail is configured and which relay is used.
- Time limits, retention periods, and rate-limit policy.
- Resource limits and trusted proxy settings when relevant.

Show runtime facts:

- Application version.
- Start time and uptime.
- Memory, processor, and thread information.
- Applied database migration versions and status.
- Last run, interval, outcome, and error for each background job.

Show data-store facts:

- Counts by record type.
- Unconfirmed accounts.
- Accounts without a password.
- Active sessions.
- Expired records waiting for cleanup.
- Recent failed sign-ins.
- Current lockouts.

Rules for this page:

- Never show passwords, password hashes, session credentials, tokens, provider secrets, mail credentials, or database credentials.
- Reduce credential-bearing settings to configured/not configured.
- Remove credentials from any displayed connection address.
- Show counts instead of private user-owned records.
- Mark values that indicate operational risk.
- Cache expensive counts briefly, but refresh runtime and job state live.
- Provide a confirmed action to run scheduled cleanup immediately.
- Keep clearing active rate limits as a separate confirmed and audited action.

## Optimistic Locking

- Editable records have a revision value.
- A read captures the current revision.
- An update or delete succeeds only when its expected revision still matches.
- A successful write increments the revision.
- A zero-row write is checked again to distinguish a missing record from a concurrent change.
- A concurrent change returns a conflict that the user can understand and resolve.
- A missing record returns not-found, not a misleading conflict.
- The same rule applies to account profiles, groups, memberships, and other editable records.
- A stale browser form needs to submit the revision it originally read if the application must detect changes made after the form loaded. A server-side re-read alone does not detect that case.

## Usage Events

- Record one usage event for every request, including anonymous requests.
- Store time, method, normalized route, response status, optional account, and request origin.
- Normalize record identifiers in routes so one feature is counted as one route.
- Do not store query strings or secrets in usage events.
- Queue recording outside the request's main work.
- Use a bounded queue so memory remains limited.
- Apply backpressure when the queue is full instead of silently dropping events.
- Never make a successful user request fail because usage recording fails.
- Keep the recording worker alive after an individual storage failure.
- Remove old usage events through retention maintenance.
- Let administrators choose a time window for usage reports.
- Show most-used routes and allow the same data to be viewed least-used first.
- Flag accounts that exceed an action-count threshold or a distinct-origin threshold.
- Treat these flags as investigation signals, not accusations.

## Tracing and Logging

- Create one server trace span for each request.
- Continue an incoming distributed trace when a trusted caller provides trace context.
- Include method, normalized route, response status, and timing in trace data.
- Keep query strings and sensitive values out of span names, attributes, and events.
- Make storage operations appear under the request trace when they run during the request.
- Link asynchronous usage recording to the request that caused it, even though it finishes later.
- Make trace and log naming stable enough to aggregate by feature rather than by individual record.
- Log ordinary requests, lifecycle events, failures, and security events at appropriate levels.
- Keep security-relevant events in a separately identifiable log stream.
- Never log passwords, password hashes, session credentials, confirmation links, external permanent identifiers, or other bearer credentials.
- Treat URLs as sensitive because credentials can appear in query strings or path segments.

## Database Migration

- Store every schema change as an ordered, versioned migration.
- Apply migrations when an application instance starts, before serving requests.
- Keep migration history visible to administrators.
- Keep a migration ledger with rank, version, description, installation status, and installation time.
- Make the production and test data stores structurally equivalent.
- Keep migrations safe for both empty databases and existing installations.
- Include explicit data backfills when a new rule needs values in old rows.
- Keep timestamps and other cross-store data types consistent.
- Define ownership behavior for every account reference.
- Cascade deletion for dependent credentials and owned records when appropriate.
- Preserve records of past actions and sign-in attempts when their account is deleted.
- Use a non-destructive reference cleanup for historical records.
- Test constraint changes and deletion behavior against the real production data store.
- Test upgrades from an earlier schema version, not only fresh installation.
- Fail startup when migrations cannot be applied or when deployment configuration is unsafe.

## Testing Strategy

### Rule tests

- Test validation boundaries and normalization.
- Test authentication success and every security failure.
- Test rate limits independently for every authentication action.
- Test confirmation, password recovery, external identity linking, and last-credential protection.
- Test guest creation, transfer, code invalidation, and in-place upgrade.
- Test group roles, invite rotation, idempotent joining, and the last-administrator rule.
- Test administrator restrictions, account deletion, audit preservation, and session revocation.
- Test optimistic-lock conflicts and missing-record handling.
- Test usage-event queue behavior and worker recovery after a failed write.

### Contract tests

- Test request and response encoding.
- Test every declared success and failure status.
- Test field-level validation errors.
- Test empty responses and redirects.
- Test that the published interface description matches the actual interface.
- Test that all supported language catalogs have identical required keys and placeholders.

### Data-store integration tests

- Run service tests against a fresh migrated test store.
- Run a separate suite against the real production data-store engine.
- Verify foreign-key behavior, cascades, uniqueness, constraints, and transaction boundaries there.
- Give each integration test isolated data or an isolated schema.
- Test migration upgrades and backfills against pre-migration data.
- Use realistic data volumes for query and pagination checks.

### Interface tests

- Test page guards and signed-out versus signed-in behavior.
- Test form submission, inline errors, loading, empty, conflict, and not-found states.
- Test URL-persisted filters, sorting, pagination, language, and theme behavior.
- Assert stable message identifiers in component tests rather than fragile translated copy.

### End-to-end tests

- Run the real application through a browser.
- Cover sign-up, confirmation, sign-in, sign-out, recovery, settings, guest transfer, group membership, and administrator workflows.
- Cover session expiry and access denial.
- Cover language and theme changes across navigation.
- Cover account deletion and preserved audit history.
- Keep a small full-stack golden path for every critical user journey.

### Test quality rules

- Tests must be isolated and repeatable.
- Shared fixtures must not hide missing constraints.
- Security tests must assert that sensitive values are absent from responses, logs, traces, and diagnostics.
- Background work must be tested eventually, not assumed to finish before the request returns.
- Every new feature should add rule, contract, data-store, interface, and end-to-end coverage where applicable.

## Reusable Data Model

The following tables cover the reusable account, security, administration, usage, and group features.
All timestamps use one consistent numeric representation. Every generated identifier is stable and
opaque to the user interface unless it is intentionally part of a public URL.

### `users`

One row per real or guest account.

- `id BIGINT`: generated primary key.
- `email VARCHAR(255)`: optional for guests; unique for real accounts after normalization.
- `password_hash VARCHAR(255)`: optional for external-only accounts and guests.
- `username VARCHAR(32)`: optional, normalized, and unique.
- `display_name VARCHAR(255)`: optional name shown in the interface.
- `is_guest BOOLEAN NOT NULL DEFAULT FALSE`: distinguishes temporary accounts from normal accounts.
- `is_admin BOOLEAN NOT NULL DEFAULT FALSE`: administrator permission.
- `theme VARCHAR(20) NOT NULL DEFAULT 'light'`: account theme preference.
- `locale VARCHAR(10) NOT NULL DEFAULT 'en'`: account language preference.
- `created_at BIGINT NOT NULL`: creation time.
- `email_verified_at BIGINT`: optional confirmation time.
- `version BIGINT NOT NULL DEFAULT 0`: optimistic-lock revision, starting at zero.

Business invariants:

- Guest accounts have no email and no password.
- A guest upgrade updates this row instead of creating a second row.
- Email and username comparisons use normalized values.
- Deleting a user must not delete historical security records.

### `sessions`

One row per signed-in session.

- `id VARCHAR(64)`: opaque bearer credential and primary key. Never display it.
- `user_id BIGINT NOT NULL`: reference to `users`; delete with the account.
- `created_at BIGINT NOT NULL`: session start.
- `expires_at BIGINT NOT NULL`: session expiry.
- `revoked_at BIGINT`: optional explicit revocation time.

Add an index on `user_id` and support account-wide session revocation.

### `oauth_identities`

One row per external identity attached to an account.

- `id BIGINT`: generated primary key.
- `user_id BIGINT NOT NULL`: reference to `users`; delete with the account.
- `provider VARCHAR(32) NOT NULL`: provider name.
- `subject VARCHAR(255) NOT NULL`: provider's stable account identifier; never expose it.
- `email VARCHAR(255)`: provider-reported display metadata, not an account-matching key.
- `created_at BIGINT NOT NULL`: link time.

Require a unique constraint on `(provider, subject)` and an index on `user_id`.

### `email_verification_tokens`

One row per issued confirmation link.

- `id BIGINT`: generated primary key.
- `user_id BIGINT NOT NULL`: reference to `users`; delete with the account.
- `token VARCHAR(64) NOT NULL`: unique bearer credential; never expose outside the link flow or logs.
- `created_at BIGINT NOT NULL`: issue time.
- `expires_at BIGINT NOT NULL`: expiry time.
- `consumed_at BIGINT`: optional one-time-use marker.

Index by `user_id` and remove expired or consumed rows during maintenance.

### `password_reset_tokens`

Same lifecycle as email confirmation tokens.

- `id BIGINT`: generated primary key.
- `user_id BIGINT NOT NULL`: reference to `users`; delete with the account.
- `token VARCHAR(64) NOT NULL`: unique single-use credential.
- `created_at BIGINT NOT NULL`: issue time.
- `expires_at BIGINT NOT NULL`: expiry time.
- `consumed_at BIGINT`: optional use marker.

Index by `user_id`. Resetting a password revokes all sessions for that account.

### `guest_claim_codes`

One active transfer credential per guest account.

- `id BIGINT`: generated primary key.
- `user_id BIGINT NOT NULL`: reference to `users`; delete with the account.
- `code VARCHAR(64) NOT NULL`: unique transfer credential.
- `created_at BIGINT NOT NULL`: issue time.
- `last_used_at BIGINT`: latest redemption time.
- `revoked_at BIGINT`: optional invalidation time.

Index by `user_id`. Issuing a code is idempotent. Upgrading the guest revokes it.

### `login_attempts`

Durable sign-in history, including attempts against unknown accounts.

- `id BIGINT`: generated primary key.
- `email VARCHAR(255) NOT NULL`: normalized identifier entered by the caller.
- `user_id BIGINT`: optional matching account; set null when that account is deleted.
- `ip VARCHAR(64)`: optional request origin.
- `outcome VARCHAR(32) NOT NULL`: stable outcome code.
- `created_at BIGINT NOT NULL`: attempt time.

Add indexes on `(email, created_at)`, `user_id`, and `created_at`. Retain rows for support
diagnostics, then remove them according to policy. Do not use this table as the live lockout state.

### `audit_log`

Durable administrator action history.

- `id BIGINT`: generated primary key.
- `occurred_at BIGINT NOT NULL`: action time.
- `actor_user_id BIGINT`: optional reference; set null if the actor is deleted.
- `actor_email VARCHAR(255)`: snapshot used to identify the actor later.
- `action VARCHAR(64) NOT NULL`: stable action code.
- `target_type VARCHAR(32)`: optional target category.
- `target_id VARCHAR(64)`: optional target identifier.
- `detail VARCHAR(1000)`: safe human-readable detail.
- `ip VARCHAR(64)`: request origin.

Add indexes on time, actor, and target. Never cascade-delete audit rows.

### `usage_events`

One row per request for operational usage analysis.

- `id BIGINT`: generated primary key.
- `created_at BIGINT NOT NULL`: request time.
- `method VARCHAR(8) NOT NULL`: request method.
- `route VARCHAR(255) NOT NULL`: normalized route without query parameters.
- `status INTEGER NOT NULL`: response status.
- `user_id BIGINT`: optional account; set null if the account is deleted.
- `ip VARCHAR(64)`: optional request origin.

Add indexes on time, `(route, created_at)`, and `(user_id, created_at)`. Apply retention because
anonymous callers can grow this table without an account.

### `groups`

One row per shared group.

- `id BIGINT`: generated primary key.
- `name VARCHAR(64) NOT NULL`: display name.
- `name_norm VARCHAR(64) NOT NULL`: normalized form for sorting and searching.
- `invite_code VARCHAR(64) NOT NULL`: unique bearer credential, visible only to group administrators.
- `created_by BIGINT`: optional reference to `users`; set null if the creator is deleted.
- `created_at BIGINT NOT NULL`: creation time.
- `version BIGINT NOT NULL DEFAULT 0`: optimistic-lock revision.

Add an index on `name_norm`. A group survives deletion of its creator.

### `group_members`

One row per account in a group.

- `id BIGINT`: generated primary key.
- `group_id BIGINT NOT NULL`: reference to `groups`; delete with the group.
- `user_id BIGINT NOT NULL`: reference to `users`; delete with the account.
- `role VARCHAR(16) NOT NULL`: `admin` or `member`.
- `created_at BIGINT NOT NULL`: join time.
- `version BIGINT NOT NULL DEFAULT 0`: optimistic-lock revision.

Require uniqueness on `(group_id, user_id)` and indexes on both foreign keys. Application rules,
not only constraints, must preserve at least one administrator in every group.

### Relationship and deletion rules

- Sessions, provider identities, confirmation tokens, reset tokens, guest codes, and memberships are account-owned and cascade on account deletion.
- Group membership is removed when an account is deleted.
- The group itself survives deletion of its creator.
- Login history and audit history survive account deletion with nullable references.
- Usage events survive account deletion with a nullable account reference until retention removes them.
- Every delete path must be tested against these rules in the production data-store engine.

### Live state not stored in these tables

- Current rate-limit buckets are live state and may disappear on restart in the reference behavior.
- Background-job health is live process state.
- Pending usage events are temporary queue state.

For multiple application instances, decide explicitly whether these states move to shared storage.
Otherwise one instance may not see another instance's lockouts, job status, or pending events.

## Page and Action Inventory

The Go rebuild needs a route and template for every page and action below. Names are logical; the
actual URL scheme may differ.

### Public pages

- Landing page or public home.
- Sign-in page.
- Sign-up page.
- Transfer-code sign-in page.
- Check-inbox page.
- Email-confirmation result page.
- Password-forgotten page.
- Password-reset page.
- Access-denied page.
- Not-found page.

### Authentication actions

- Sign up.
- Sign in with email or username.
- Sign out.
- Confirm email.
- Resend confirmation.
- Request password reset.
- Redeem password reset.
- Start external sign-in.
- Handle external sign-in callback.
- List configured external providers.
- Create a guest account.
- Issue a guest transfer code.
- Redeem a guest transfer code.
- Upgrade a guest account.

### Signed-in pages and actions

- Home page.
- Account settings page.
- Update profile.
- Update password.
- Update language.
- Update theme.
- List linked external identities.
- Attach or remove an external identity.
- List groups.
- View group details.
- Create a group.
- Join a group by code.
- Leave a group.
- Rename a group.
- Regenerate an invite code.
- Promote or demote a member.
- Remove a member.

### Administrator pages and actions

- User list with search, sorting, paging, and URL state.
- User detail and diagnostics.
- Create user.
- Edit user.
- Delete user with confirmation.
- Confirm a user's email.
- Resend a user's confirmation.
- Revoke all sessions for a user.
- Remove a user's external identity.
- Clear a user's lockout.
- Login-attempt list.
- Live rate-limit list and clear action.
- Audit log with filters and paging.
- System overview.
- Run maintenance cleanup.
- Usage report by route.
- Suspicious-account usage report.

## Browser Acceptance Scenarios

These scenarios describe what a browser-level suite must prove. They are the reusable subset of the
reference application's end-to-end behavior. Domain-specific content scenarios are intentionally not
included.

### Public entry and authentication

- Open the bare site URL and redirect to the selected default language prefix.
- Sign up with a valid email and password.
- Confirm that the new session reaches the signed-in home page.
- Refresh the page and confirm that the session survives.
- Change the theme and confirm the document theme changes immediately.
- Open the account menu, sign out, and confirm the browser reaches sign-in.
- Sign in again with the same credentials.
- Visit an administrator URL as a normal user and confirm access is denied.

### Guest account lifecycle

- Use the application anonymously until an ownership-requiring action creates a guest.
- Confirm that no guest is created by page view alone.
- Confirm that the guest banner appears after the first successful write.
- Request a transfer code and verify its format and visibility.
- Open a second isolated browser context.
- Redeem the code there and confirm the same account's saved state is available.
- Upgrade the guest with a new email and password.
- Confirm the guest banner disappears.
- Sign out and sign in with the new credentials.
- Confirm the saved state still belongs to the same account.

### Administrator workflow

- Sign out from the normal account.
- Sign in with the development bootstrap administrator in non-production environments.
- Open user management and find the normal account.
- Create another account from the administrator page.
- Confirm the user list shows confirmation and lockout state.
- Open the account detail page.
- Confirm email diagnostics, sign-in security, sessions, and linked identities are visible.
- Open the system page.
- Confirm configuration, statistics, and runtime sections are visible.
- Confirm a configured password is not visible.
- Open the audit log and confirm the create action is present with the actor.
- Filter the user list by email and confirm exactly one result.
- Set one row per page and confirm page one and page two use one-based numbering.
- Move to page two, go back, and confirm the list returns to page one.
- Type a search term and confirm the URL updates without creating one history entry per keystroke.
- Delete the test account after accepting the confirmation dialog.
- Confirm the account disappears from the user list.
- Confirm the deletion remains in the audit log.

### Language behavior

- Open the site with a supported browser language and confirm the matching URL prefix and document language.
- Open the site with an unsupported browser language and confirm fallback to the default language.
- Open an explicit language URL from a browser configured for another language.
- Confirm the explicit URL wins.
- Open a deep link with a language prefix and confirm it renders the requested page rather than not-found.
- Use the language selector and confirm the current path is preserved under the new prefix.

### Translation completeness

- Walk every public page in every supported language.
- Sign in and walk every signed-in and administrator page in every supported language.
- Confirm every page mounts with a visible heading.
- Fail when a message key appears literally in page text.
- Fail when the browser reports a missing catalog key.
- Check labels, placeholders, accessible names, dialogs, and status messages, not only visible headings.

## Current Browser Coverage and Gaps

The reusable reference browser specs currently cover these areas:

- `golden-path.spec.ts`: public entry, sign-up, session refresh, theme change, sign-out, sign-in, access denial, administrator sign-in, user creation, list state, account diagnostics, system overview, audit entries, account deletion, and audit preservation.
- `locale.spec.ts`: browser-language selection, unsupported-language fallback, explicit URL precedence, deep links, document language, and language switching.
- `translation.spec.ts`: all public, signed-in, and administrator pages in both supported languages; missing visible keys; missing console catalog keys; headings and accessibility-related copy.

A complete template should add browser coverage for behavior that the current reusable suite mainly
tests below the browser level:

- Email confirmation through a test mailbox.
- Password recovery through a test mailbox.
- External-provider sign-in, linking, failure, and unlink protection.
- Profile changes, password changes, field errors, and account-preference persistence.
- Guest invalid, expired, revoked, and rate-limited transfer-code cases.
- Guest account cleanup rules.
- Every group visibility, membership, role, invite rotation, leave, and last-administrator case.
- Administrator confirmation, resend, session revocation, identity removal, lockout clearing, and self-protection rules.
- System cleanup, rate-limit clearing, usage reports, suspicious-account thresholds, and job-health warnings.
- Two-browser optimistic-lock conflicts.
- Session expiry while a page remains open.
- Full-page and HTMX-fragment versions of protected and state-changing requests.
- Secret absence from rendered pages, response bodies, logs, and traces.

This split matters. Unit and service tests prove rules quickly. Browser tests prove navigation,
cookies, redirects, history, accessibility, and real template behavior.

## Go and HTMX Rebuild Requirements

The feature rules above do not depend on the rendering approach. A server-rendered Go and HTMX
version needs these additional delivery rules to reproduce the same behavior.

### Full pages and fragments

- Every navigable page must render as a complete document for a normal browser request.
- The same page must provide a fragment response for in-page HTMX requests.
- Fragments must contain their own accessible headings, labels, error summaries, and empty states.
- Do not put security decisions only in fragment visibility. Repeat authorization on the server.
- After a mutation, return the smallest updated fragment or redirect to a canonical URL.
- Re-read authoritative state after a mutation instead of trusting a client-side toggle.

### HTMX navigation and history

- Use normal links for public, authentication, external-provider, and language navigation.
- Preserve the language prefix on every internal URL.
- Keep list filters, sorting, page size, and page number in the URL.
- Push meaningful filter and paging changes into browser history.
- Replace history while a search field is being typed, so every keystroke does not create a history entry.
- Make the browser back button restore the prior server-rendered list state.
- Return an explicit full-page redirect instruction when an HTMX request loses its session.
- Return access-denied or not-found fragments/pages consistently for both normal and HTMX requests.

### Forms and errors

- Render field errors beside the field they describe.
- Do not show validation errors before the first submit.
- Preserve submitted values after a validation failure.
- Return a conflict response for an optimistic-lock failure and show a recovery message.
- Return a not-found response when the record disappeared.
- Use one flash or alert region that can be replaced by an HTMX response.
- Keep success and error messages accessible to assistive technology.
- Add a loading state and prevent duplicate submits for slow actions.
- Confirm destructive actions in the browser and enforce confirmation on the server where needed.

### Security in forms

- Include CSRF protection in every state-changing form and HTMX request.
- Keep session cookies `HttpOnly`, `SameSite`, and secure outside development.
- Keep transfer codes, confirmation tokens, reset tokens, and invite codes out of logs and analytics.
- Use top-level browser navigation for external identity-provider flows.
- Handle provider failures by redirecting to a readable sign-in or settings state.

### Template and test hooks

- Use semantic headings, labels, links, buttons, tables, and dialogs.
- Give controls stable accessible names independent of translated copy where possible.
- Add stable test identifiers only where accessible roles are insufficient.
- Ensure each page has one visible heading after its data load completes.
- Test both full-document and fragment responses.
- Test a normal browser navigation and an HTMX navigation for every important mutation.
- Verify that a fragment cannot bypass authentication, CSRF, authorization, or validation.
