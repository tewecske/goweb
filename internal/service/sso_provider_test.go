package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

type ssoAdminStub struct {
	login       SSOLoginRequest
	consent     SSOConsentRequest
	logout      SSOLogoutRequest
	requestErr  error
	accepted    []string // subjects accepted for login
	rejected    []string // "login" or "consent"
	grant       *SSOConsentGrant
	rememberFor time.Duration
	logouts     int
	revokedSIDs []string
	failSIDs    map[string]bool
	consentSubj string
	consentErr  error
}

func (s *ssoAdminStub) LoginRequest(context.Context, string) (SSOLoginRequest, error) {
	return s.login, s.requestErr
}

func (s *ssoAdminStub) AcceptLogin(_ context.Context, _ string, subject string, rememberFor time.Duration) (string, error) {
	s.accepted = append(s.accepted, subject)
	s.rememberFor = rememberFor
	return "https://id.example.test/accepted-login", nil
}

func (s *ssoAdminStub) RejectLogin(context.Context, string) (string, error) {
	s.rejected = append(s.rejected, "login")
	return "https://id.example.test/rejected-login", nil
}

func (s *ssoAdminStub) ConsentRequest(context.Context, string) (SSOConsentRequest, error) {
	return s.consent, s.requestErr
}

func (s *ssoAdminStub) AcceptConsent(_ context.Context, _ string, grant SSOConsentGrant) (string, error) {
	s.grant = &grant
	return "https://id.example.test/accepted-consent", nil
}

func (s *ssoAdminStub) RejectConsent(context.Context, string) (string, error) {
	s.rejected = append(s.rejected, "consent")
	return "https://id.example.test/rejected-consent", nil
}

func (s *ssoAdminStub) LogoutRequest(context.Context, string) (SSOLogoutRequest, error) {
	return s.logout, s.requestErr
}

func (s *ssoAdminStub) AcceptLogout(context.Context, string) (string, error) {
	s.logouts++
	return "https://id.example.test/logged-out", nil
}

func (s *ssoAdminStub) RevokeLoginSession(_ context.Context, sid string) error {
	s.revokedSIDs = append(s.revokedSIDs, sid)
	if s.failSIDs[sid] {
		return ErrSSOUnavailable
	}
	return nil
}

func (s *ssoAdminStub) RevokeConsentSessions(_ context.Context, subject string) error {
	s.consentSubj = subject
	return s.consentErr
}

type ssoSessionStoreStub struct {
	recorded  []SSOLoginSession
	recordErr error
	sids      map[int64][]string
	deleted   []string
}

func (s *ssoSessionStoreStub) RecordSSOLoginSession(_ context.Context, session SSOLoginSession) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	s.recorded = append(s.recorded, session)
	return nil
}

func (s *ssoSessionStoreStub) ListSSOLoginSessions(_ context.Context, userID int64) ([]string, error) {
	return s.sids[userID], nil
}

func (s *ssoSessionStoreStub) DeleteSSOLoginSession(_ context.Context, sid string) error {
	s.deleted = append(s.deleted, sid)
	return nil
}

// ssoUsersStub serves a fixed set of accounts; anything else is not found.
type ssoUsersStub struct {
	userRepositoryStub
	users map[int64]User
}

func (s *ssoUsersStub) FindUserByID(_ context.Context, id int64) (User, error) {
	user, ok := s.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

func newSSOTestService(t *testing.T, admin *ssoAdminStub, store *ssoSessionStoreStub, confirmationRequired bool) *SSOProviderService {
	t.Helper()
	verified := int64(100)
	users := &ssoUsersStub{users: map[int64]User{
		42: {ID: 42, Email: strPtr("ada@example.test"), DisplayName: strPtr("Ada"), Username: strPtr("ada"), Locale: "hu", EmailVerifiedAt: &verified},
		43: {ID: 43, Email: strPtr("unverified@example.test"), Username: strPtr("grace"), Locale: "en"},
		44: {ID: 44, IsGuest: true},
	}}
	service, err := NewSSOProviderService(admin, users, store, 8*time.Hour, confirmationRequired)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Unix(1_000, 0) }
	return service
}

func TestSSOBeginLogin(t *testing.T) {
	tests := []struct {
		name         string
		login        SSOLoginRequest
		current      int64
		wantTarget   string
		wantAccepted []string
		wantRejected []string
	}{
		// Hydra's remembered subject wins over a different local session.
		{name: "skip accepts the remembered subject", login: SSOLoginRequest{Skip: true, Subject: "42"}, current: 43, wantTarget: "https://id.example.test/accepted-login", wantAccepted: []string{"42"}},
		{name: "skip for a deleted account is rejected", login: SSOLoginRequest{Skip: true, Subject: "99"}, wantTarget: "https://id.example.test/rejected-login", wantRejected: []string{"login"}},
		{name: "skip with a non-canonical subject is rejected", login: SSOLoginRequest{Skip: true, Subject: "042"}, wantTarget: "https://id.example.test/rejected-login", wantRejected: []string{"login"}},
		{name: "signed-in browser is accepted", current: 42, wantTarget: "https://id.example.test/accepted-login", wantAccepted: []string{"42"}},
		{name: "signed-in guest must sign in", current: 44},
		{name: "anonymous visitor must sign in"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admin := &ssoAdminStub{login: test.login}
			service := newSSOTestService(t, admin, &ssoSessionStoreStub{}, false)
			target, err := service.BeginLogin(context.Background(), "challenge", test.current)
			if err != nil {
				t.Fatalf("BeginLogin() error = %v", err)
			}
			if target != test.wantTarget || !slices.Equal(admin.accepted, test.wantAccepted) || !slices.Equal(admin.rejected, test.wantRejected) {
				t.Fatalf("target %q accepted %v rejected %v, want %q %v %v", target, admin.accepted, admin.rejected, test.wantTarget, test.wantAccepted, test.wantRejected)
			}
			if len(admin.accepted) > 0 && admin.rememberFor != 8*time.Hour {
				t.Fatalf("remember for %s, want the session lifetime", admin.rememberFor)
			}
		})
	}
}

func TestSSOCompleteLoginRequiresConfirmedEmailWhenConfigured(t *testing.T) {
	admin := &ssoAdminStub{}
	service := newSSOTestService(t, admin, &ssoSessionStoreStub{}, true)
	if target, _ := service.CompleteLogin(context.Background(), "challenge", 43); target != "https://id.example.test/rejected-login" {
		t.Fatalf("unverified account target = %q, want rejection", target)
	}
	if target, _ := service.CompleteLogin(context.Background(), "challenge", 42); target != "https://id.example.test/accepted-login" {
		t.Fatalf("verified account target = %q, want acceptance", target)
	}
	if !slices.Equal(admin.accepted, []string{"42"}) {
		t.Fatalf("accepted subjects = %v, want only 42", admin.accepted)
	}
}

func TestSSOChallengeValidationAndExpiry(t *testing.T) {
	admin := &ssoAdminStub{requestErr: ErrSSOChallengeExpired}
	service := newSSOTestService(t, admin, &ssoSessionStoreStub{}, false)
	for _, challenge := range []string{"", "  ", strings.Repeat("a", maxSSOChallenge+1)} {
		if _, err := service.BeginLogin(context.Background(), challenge, 0); !errors.Is(err, ErrInvalidSSOChallenge) {
			t.Fatalf("BeginLogin(len %d) error = %v, want %v", len(challenge), err, ErrInvalidSSOChallenge)
		}
	}
	if _, err := service.Consent(context.Background(), "challenge"); !errors.Is(err, ErrSSOChallengeExpired) {
		t.Fatalf("Consent() error = %v, want %v", err, ErrSSOChallengeExpired)
	}
	if _, err := service.Logout(context.Background(), "challenge"); !errors.Is(err, ErrSSOChallengeExpired) {
		t.Fatalf("Logout() error = %v, want %v", err, ErrSSOChallengeExpired)
	}
	if len(admin.accepted)+len(admin.rejected)+admin.logouts != 0 {
		t.Fatal("an invalid or expired challenge was answered")
	}
}

func TestSSOConsentReleasesClaimsByScopeAndRecordsSession(t *testing.T) {
	tests := []struct {
		name   string
		user   string
		scopes []string
		want   map[string]any
	}{
		{name: "openid only", user: "42", scopes: []string{"openid"}, want: map[string]any{}},
		{name: "email and profile", user: "42", scopes: []string{"openid", "email", "profile"}, want: map[string]any{"email": "ada@example.test", "email_verified": true, "name": "Ada", "locale": "hu"}},
		{name: "unverified falls back to username", user: "43", scopes: []string{"openid", "email", "profile"}, want: map[string]any{"email": "unverified@example.test", "email_verified": false, "name": "grace", "locale": "en"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admin := &ssoAdminStub{consent: SSOConsentRequest{Subject: test.user, LoginSessionID: "sid-1", RequestedScope: test.scopes, RequestedAudience: []string{"api"}}}
			store := &ssoSessionStoreStub{}
			service := newSSOTestService(t, admin, store, false)
			target, err := service.Consent(context.Background(), "challenge")
			if err != nil || target != "https://id.example.test/accepted-consent" {
				t.Fatalf("Consent() = %q, %v", target, err)
			}
			if len(admin.grant.IDTokenClaims) != len(test.want) {
				t.Fatalf("claims = %v, want %v", admin.grant.IDTokenClaims, test.want)
			}
			for key, value := range test.want {
				if admin.grant.IDTokenClaims[key] != value {
					t.Fatalf("claim %s = %v, want %v (all: %v)", key, admin.grant.IDTokenClaims[key], value, admin.grant.IDTokenClaims)
				}
			}
			if !slices.Equal(admin.grant.Scope, test.scopes) || !slices.Equal(admin.grant.Audience, []string{"api"}) || admin.grant.RememberFor != 8*time.Hour {
				t.Fatalf("grant = %+v, want requested scopes and audience remembered for the session lifetime", admin.grant)
			}
			wantSession := SSOLoginSession{SessionID: "sid-1", UserID: mustParse(test.user), CreatedAt: 1_000, ExpiresAt: 1_000 + 8*3600}
			if len(store.recorded) != 1 || store.recorded[0] != wantSession {
				t.Fatalf("recorded = %+v, want %+v", store.recorded, wantSession)
			}
		})
	}
}

func mustParse(subject string) int64 {
	id, _ := parseSSOSubject(subject)
	return id
}

func TestSSOConsentRefusesIneligibleAccountsAndUnrecordedSessions(t *testing.T) {
	for _, subject := range []string{"44", "99", "not-a-number"} {
		admin := &ssoAdminStub{consent: SSOConsentRequest{Subject: subject, LoginSessionID: "sid-1"}}
		store := &ssoSessionStoreStub{}
		service := newSSOTestService(t, admin, store, false)
		if target, _ := service.Consent(context.Background(), "challenge"); target != "https://id.example.test/rejected-consent" {
			t.Fatalf("Consent(subject %q) target = %q, want rejection", subject, target)
		}
		if len(store.recorded) != 0 || admin.grant != nil {
			t.Fatalf("Consent(subject %q) recorded or granted for an ineligible account", subject)
		}
	}

	// A session that cannot be recorded could never be revoked later.
	admin := &ssoAdminStub{consent: SSOConsentRequest{Subject: "42", LoginSessionID: "sid-1"}}
	service := newSSOTestService(t, admin, &ssoSessionStoreStub{recordErr: errors.New("database down")}, false)
	if _, err := service.Consent(context.Background(), "challenge"); err == nil || admin.grant != nil {
		t.Fatalf("Consent() error = %v granted = %t, want failure without a grant", err, admin.grant != nil)
	}
}

func TestSSOLogoutForgetsTheSession(t *testing.T) {
	admin := &ssoAdminStub{logout: SSOLogoutRequest{Subject: "42", SessionID: "sid-1"}}
	store := &ssoSessionStoreStub{}
	service := newSSOTestService(t, admin, store, false)
	target, err := service.Logout(context.Background(), "challenge")
	if err != nil || target != "https://id.example.test/logged-out" || admin.logouts != 1 {
		t.Fatalf("Logout() = %q, %v (accepted %d)", target, err, admin.logouts)
	}
	if !slices.Equal(store.deleted, []string{"sid-1"}) {
		t.Fatalf("deleted = %v, want sid-1", store.deleted)
	}
}

func TestSSORevokeUserRevokesEverySessionAndConsent(t *testing.T) {
	admin := &ssoAdminStub{failSIDs: map[string]bool{"sid-b": true}}
	store := &ssoSessionStoreStub{sids: map[int64][]string{42: {"sid-a", "sid-b", "sid-c"}, 43: {"other"}}}
	service := newSSOTestService(t, admin, store, false)

	err := service.RevokeUser(context.Background(), 42)
	if !errors.Is(err, ErrSSOUnavailable) {
		t.Fatalf("RevokeUser() error = %v, want the failed revocation reported", err)
	}
	if !slices.Equal(admin.revokedSIDs, []string{"sid-a", "sid-b", "sid-c"}) {
		t.Fatalf("revoked sids = %v, want every sid of account 42 despite a failure", admin.revokedSIDs)
	}
	// The failed sid stays recorded so a retry can revoke it.
	if !slices.Equal(store.deleted, []string{"sid-a", "sid-c"}) {
		t.Fatalf("deleted records = %v, want only revoked sids", store.deleted)
	}
	if admin.consentSubj != "42" {
		t.Fatalf("consent revoked for %q, want subject 42", admin.consentSubj)
	}
}
