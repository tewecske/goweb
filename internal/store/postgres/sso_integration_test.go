//go:build integration

package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/tewecske/goweb/internal/service"
)

func TestSSOLoginSessionRepositoryRecordsListsAndExpires(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	ctx := context.Background()
	repository, err := NewSSOLoginSessionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := NewRetentionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	ada := insertTokenUser(t, harness.DB, "ada-sso@example.test")
	grace := insertTokenUser(t, harness.DB, "grace-sso@example.test")

	for _, session := range []service.SSOLoginSession{
		{SessionID: "sid-b", UserID: ada, CreatedAt: 100, ExpiresAt: 500},
		{SessionID: "sid-a", UserID: ada, CreatedAt: 50, ExpiresAt: 300},
		{SessionID: "sid-g", UserID: grace, CreatedAt: 100, ExpiresAt: 900},
		// A repeat keeps the later expiry and never shortens it.
		{SessionID: "sid-a", UserID: ada, CreatedAt: 200, ExpiresAt: 700},
		{SessionID: "sid-a", UserID: ada, CreatedAt: 210, ExpiresAt: 250},
		// The same sid reported for another account must not take it over.
		{SessionID: "sid-g", UserID: ada, CreatedAt: 300, ExpiresAt: 2000},
	} {
		if err := repository.RecordSSOLoginSession(ctx, session); err != nil {
			t.Fatalf("RecordSSOLoginSession(%+v) error = %v", session, err)
		}
	}
	sids, err := repository.ListSSOLoginSessions(ctx, ada)
	if err != nil || !slices.Equal(sids, []string{"sid-a", "sid-b"}) {
		t.Fatalf("ListSSOLoginSessions(ada) = %v, %v; want sid-a, sid-b", sids, err)
	}
	var expiresA, expiresG int64
	if err := harness.DB.QueryRowContext(ctx, "SELECT expires_at FROM sso_login_sessions WHERE sid = 'sid-a'").Scan(&expiresA); err != nil || expiresA != 700 {
		t.Fatalf("sid-a expiry = %d (%v), want 700", expiresA, err)
	}
	if err := harness.DB.QueryRowContext(ctx, "SELECT expires_at FROM sso_login_sessions WHERE sid = 'sid-g' AND user_id = $1", grace).Scan(&expiresG); err != nil || expiresG != 900 {
		t.Fatalf("sid-g = %d (%v), want grace's record unchanged", expiresG, err)
	}

	removed, err := retention.DeleteExpiredSSOLoginSessions(ctx, 500)
	if err != nil || removed != 1 {
		t.Fatalf("DeleteExpiredSSOLoginSessions(500) = %d, %v; want only sid-b (expires at 500) removed", removed, err)
	}
	if err := repository.DeleteSSOLoginSession(ctx, "sid-a"); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeleteSSOLoginSession(ctx, "absent"); err != nil {
		t.Fatalf("DeleteSSOLoginSession(absent) error = %v, want nil", err)
	}
	if sids, _ := repository.ListSSOLoginSessions(ctx, ada); len(sids) != 0 {
		t.Fatalf("ada sids after deletes = %v, want none", sids)
	}

	if _, err := harness.DB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", grace); err != nil {
		t.Fatal(err)
	}
	if sids, _ := repository.ListSSOLoginSessions(ctx, grace); len(sids) != 0 {
		t.Fatalf("grace sids after account deletion = %v, want cascade", sids)
	}
}

func TestSessionRepositoryBindsClientSessionsToSSOSessions(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	ctx := context.Background()
	repository, err := NewSessionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	user := insertTokenUser(t, harness.DB, "client-sso@example.test")
	bound := service.Session{ID: "bound-session", UserID: user, CreatedAt: 100, ExpiresAt: 10_000, SSOSessionID: "sid-1", SSOIDToken: "header.claims.signature"}
	sameSID := service.Session{ID: "second-device", UserID: user, CreatedAt: 100, ExpiresAt: 10_000, SSOSessionID: "sid-1", SSOIDToken: "other.id.token"}
	otherSID := service.Session{ID: "other-sid", UserID: user, CreatedAt: 100, ExpiresAt: 10_000, SSOSessionID: "sid-2", SSOIDToken: "x.y.z"}
	local := service.Session{ID: "local-session", UserID: user, CreatedAt: 100, ExpiresAt: 10_000}
	for _, session := range []service.Session{bound, sameSID, otherSID, local} {
		if err := repository.CreateSession(ctx, session); err != nil {
			t.Fatalf("CreateSession(%s) error = %v", session.ID, err)
		}
	}
	if token, err := repository.FindSSOIDToken(ctx, "bound-session"); err != nil || token != "header.claims.signature" {
		t.Fatalf("FindSSOIDToken(bound) = %q, %v", token, err)
	}
	if token, err := repository.FindSSOIDToken(ctx, "local-session"); err != nil || token != "" {
		t.Fatalf("FindSSOIDToken(local) = %q, %v; want empty for an unbound session", token, err)
	}
	var nullSID bool
	if err := harness.DB.QueryRowContext(ctx, "SELECT sso_sid IS NULL AND sso_id_token IS NULL FROM sessions WHERE id = $1", sessionDigest("local-session")).Scan(&nullSID); err != nil || !nullSID {
		t.Fatalf("local session binding stored as NULL = %t (%v)", nullSID, err)
	}

	revoked, err := repository.RevokeSSOSessions(ctx, "sid-1", 500)
	if err != nil || revoked != 2 {
		t.Fatalf("RevokeSSOSessions(sid-1) = %d, %v; want both sessions of that sid", revoked, err)
	}
	if again, _ := repository.RevokeSSOSessions(ctx, "sid-1", 600); again != 0 {
		t.Fatalf("repeat revocation = %d, want 0 (idempotent)", again)
	}
	for id, wantRevoked := range map[string]bool{"bound-session": true, "second-device": true, "other-sid": false, "local-session": false} {
		session, err := repository.FindSession(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if (session.RevokedAt != nil) != wantRevoked {
			t.Errorf("%s revoked = %t, want %t", id, session.RevokedAt != nil, wantRevoked)
		}
	}
}

func TestUpgradeGuestWithIdentityIsAllOrNothing(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	ctx := context.Background()
	users, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	insertGuest := func(code string) service.User {
		t.Helper()
		var id int64
		if err := harness.DB.QueryRowContext(ctx, "INSERT INTO users (is_guest, theme, locale, created_at) VALUES (TRUE, 'dark', 'hu', 100) RETURNING id").Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := harness.DB.ExecContext(ctx, "INSERT INTO guest_claim_codes (user_id, code, created_at) VALUES ($1, $2, 100)", id, code); err != nil {
			t.Fatal(err)
		}
		guest, err := users.FindUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return guest
	}
	upgrade := func(guest service.User, email, subject string, version int64) (service.User, error) {
		converted := guest
		converted.IsGuest = false
		converted.Email = &email
		verified := int64(200)
		converted.EmailVerifiedAt = &verified
		return users.UpgradeGuestWithIdentity(ctx, converted, version, service.OAuthIdentity{UserID: guest.ID, Provider: "sso", Subject: subject, Email: email, CreatedAt: 200}, 200)
	}
	stillGuest := func(id int64) bool {
		user, err := users.FindUserByID(ctx, id)
		return err == nil && user.IsGuest && user.Email == nil
	}
	activeCodes := func(id int64) (count int) {
		_ = harness.DB.QueryRowContext(ctx, "SELECT count(*) FROM guest_claim_codes WHERE user_id = $1 AND revoked_at IS NULL", id).Scan(&count)
		return count
	}

	guest := insertGuest("code-one")
	saved, err := upgrade(guest, "ada@example.test", "subject-ada", guest.Version)
	if err != nil {
		t.Fatalf("UpgradeGuestWithIdentity() error = %v", err)
	}
	if saved.ID != guest.ID || saved.IsGuest || saved.Email == nil || *saved.Email != "ada@example.test" || saved.Theme != "dark" || saved.Locale != "hu" || saved.Version != guest.Version+1 {
		t.Fatalf("upgraded = %+v", saved)
	}
	identityRepository, _ := NewOAuthIdentityRepository(harness.DB)
	if identity, err := identityRepository.FindOAuthIdentity(ctx, "sso", "subject-ada"); err != nil || identity.UserID != guest.ID {
		t.Fatalf("identity = %+v, %v", identity, err)
	}
	if activeCodes(guest.ID) != 0 {
		t.Fatal("the transfer code survived the upgrade")
	}

	// Each failure leaves the guest exactly as it was.
	other := insertGuest("code-two")
	if _, err := upgrade(other, "grace@example.test", "subject-ada", other.Version); !errors.Is(err, service.ErrOAuthIdentityConflict) {
		t.Fatalf("taken subject error = %v, want %v", err, service.ErrOAuthIdentityConflict)
	}
	if _, err := upgrade(other, "ada@example.test", "subject-grace", other.Version); !errors.Is(err, service.ErrDuplicateEmail) {
		t.Fatalf("taken email error = %v, want %v", err, service.ErrDuplicateEmail)
	}
	if _, err := upgrade(other, "grace@example.test", "subject-grace", other.Version+5); !errors.Is(err, service.ErrGuestUpgradeRequiresGuest) {
		t.Fatalf("stale version error = %v, want %v", err, service.ErrGuestUpgradeRequiresGuest)
	}
	if !stillGuest(other.ID) || activeCodes(other.ID) != 1 {
		t.Fatalf("after failed upgrades guest = %t, active codes = %d; want an untouched guest", stillGuest(other.ID), activeCodes(other.ID))
	}
	if _, err := identityRepository.FindOAuthIdentity(ctx, "sso", "subject-grace"); !errors.Is(err, service.ErrOAuthIdentityNotFound) {
		t.Fatalf("a failed upgrade left an identity behind: %v", err)
	}
}
