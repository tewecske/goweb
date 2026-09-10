package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthSignInCallbackCreatesAccountForNewProviderIdentity(t *testing.T) {
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	provider := &oauthProviderStub{name: "google", authorizationURL: "https://accounts.example.test/authorize", profile: OAuthProfile{Subject: "subject-1", Email: "New@Example.COM", EmailVerified: true, DisplayName: "New User"}}
	states := &oauthStateRepositoryStub{consumed: OAuthState{State: state, Provider: "google", Action: oauthActionSignIn, ExpiresAt: 200}}
	identities := &oauthIdentityRepositoryStub{findErr: ErrOAuthIdentityNotFound}
	users := &oauthUserRepositoryStub{}
	service := newOAuthServiceForTest(t, provider, states, identities, users)

	result, err := service.Callback(context.Background(), "google", "authorization-code", state)
	if err != nil {
		t.Fatalf("Callback() error = %v, want nil", err)
	}
	if result.User.ID != users.created.ID || result.Session.UserID != users.created.ID {
		t.Fatalf("created user/session = %d/%d, want user %d", result.User.ID, result.Session.UserID, users.created.ID)
	}
	if users.created.Email == nil || *users.created.Email != "new@example.com" || users.created.EmailVerifiedAt == nil {
		t.Fatalf("created user email/verified = %v/%v, want normalized and verified", users.created.Email, users.created.EmailVerifiedAt)
	}
	if identities.created.Provider != "google" || identities.created.Subject != "subject-1" {
		t.Fatalf("created identity = %#v, want google/subject-1", identities.created)
	}
	if provider.receivedCode != "authorization-code" || states.consumedState != state {
		t.Errorf("callback inputs code/state = %q/%q", provider.receivedCode, states.consumedState)
	}
}

func TestOAuthSignInCallbackUsesStableIdentitySubject(t *testing.T) {
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	provider := &oauthProviderStub{name: "google", profile: OAuthProfile{Subject: "stable-subject", Email: "different@example.com"}}
	states := &oauthStateRepositoryStub{consumed: OAuthState{State: state, Provider: "google", Action: oauthActionSignIn, ExpiresAt: 200}}
	identities := &oauthIdentityRepositoryStub{found: OAuthIdentity{UserID: 42, Provider: "google", Subject: "stable-subject"}}
	users := &oauthUserRepositoryStub{byID: User{ID: 42, Email: stringPointer("original@example.com")}}
	service := newOAuthServiceForTest(t, provider, states, identities, users)

	result, err := service.Callback(context.Background(), "google", "code", state)
	if err != nil {
		t.Fatalf("Callback() error = %v, want nil", err)
	}
	if result.User.ID != 42 || users.createCalls != 0 || identities.createCalls != 0 {
		t.Fatalf("existing identity callback = user %d, create calls %d/%d", result.User.ID, users.createCalls, identities.createCalls)
	}
}

func TestOAuthSignInCallbackRefusesEmailMerge(t *testing.T) {
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	provider := &oauthProviderStub{name: "google", profile: OAuthProfile{Subject: "new-subject", Email: "existing@example.com"}}
	states := &oauthStateRepositoryStub{consumed: OAuthState{State: state, Provider: "google", Action: oauthActionSignIn, ExpiresAt: 200}}
	identities := &oauthIdentityRepositoryStub{findErr: ErrOAuthIdentityNotFound}
	users := &oauthUserRepositoryStub{byEmail: User{ID: 42, Email: stringPointer("existing@example.com")}}
	service := newOAuthServiceForTest(t, provider, states, identities, users)

	if _, err := service.Callback(context.Background(), "google", "code", state); !errors.Is(err, ErrOAuthEmailConflict) {
		t.Fatalf("Callback() error = %v, want ErrOAuthEmailConflict", err)
	}
	if users.createCalls != 0 || identities.createCalls != 0 {
		t.Error("email conflict created account or identity")
	}
}

func TestOAuthSignInStartAndCallbackRejectUnsafeStateOrProviders(t *testing.T) {
	provider := &oauthProviderStub{name: "google", authorizationURL: "https://accounts.example.test/authorize"}
	states := &oauthStateRepositoryStub{}
	service := newOAuthServiceForTest(t, provider, states, &oauthIdentityRepositoryStub{}, &oauthUserRepositoryStub{})

	authorizationURL, err := service.Start(context.Background(), "google")
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil || parsed.Query().Get("state") == "" {
		t.Fatalf("authorization URL = %q, want state query", authorizationURL)
	}
	if strings.Contains(authorizationURL, "authorization-code") {
		t.Error("authorization URL contains callback code")
	}
	if _, err := service.Start(context.Background(), "github"); !errors.Is(err, ErrOAuthProviderUnavailable) {
		t.Fatalf("Start(unconfigured) error = %v, want ErrOAuthProviderUnavailable", err)
	}
	if _, err := service.Callback(context.Background(), "google", "code", "bad-state"); !errors.Is(err, ErrOAuthStateInvalid) {
		t.Fatalf("Callback(bad state) error = %v, want ErrOAuthStateInvalid", err)
	}
}

func TestOAuthSignInCallbackRejectsProviderMismatchAndFailures(t *testing.T) {
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		provider   *oauthProviderStub
		stored     OAuthState
		consumeErr error
		expected   error
	}{
		{name: "provider mismatch", provider: &oauthProviderStub{name: "google"}, stored: OAuthState{State: state, Provider: "github", Action: oauthActionSignIn, ExpiresAt: 200}, expected: ErrOAuthStateInvalid},
		{name: "state store", provider: &oauthProviderStub{name: "google"}, consumeErr: errors.New("state store unavailable"), expected: ErrOAuthStateInvalid},
		{name: "provider exchange", provider: &oauthProviderStub{name: "google", exchangeErr: errors.New("provider unavailable")}, stored: OAuthState{State: state, Provider: "google", Action: oauthActionSignIn, ExpiresAt: 200}, expected: ErrOAuthAuthenticationFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newOAuthServiceForTest(t, test.provider, &oauthStateRepositoryStub{consumed: test.stored, consumeErr: test.consumeErr}, &oauthIdentityRepositoryStub{}, &oauthUserRepositoryStub{})
			if _, err := service.Callback(context.Background(), "google", "code", state); !errors.Is(err, test.expected) {
				t.Fatalf("Callback() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

func TestOAuthSignInLinkBindsStateAndConfirmsMatchingEmail(t *testing.T) {
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	provider := &oauthProviderStub{name: "google", authorizationURL: "https://accounts.example.test/authorize", profile: OAuthProfile{Subject: "linked-subject", Email: "user@example.com", EmailVerified: true}}
	states := &oauthStateRepositoryStub{consumed: OAuthState{State: state, Provider: "google", Action: oauthActionLink, UserID: 42, ExpiresAt: 200}}
	identities := &oauthIdentityRepositoryStub{findErr: ErrOAuthIdentityNotFound}
	users := &oauthUserRepositoryStub{byID: User{ID: 42, Email: stringPointer("user@example.com"), Version: 2}}
	service := newOAuthServiceForTest(t, provider, states, identities, users)

	authorizationURL, err := service.StartLink(context.Background(), 42, "google")
	if err != nil {
		t.Fatalf("StartLink() error = %v, want nil", err)
	}
	if states.created.Action != oauthActionLink || states.created.UserID != 42 || !strings.Contains(authorizationURL, "state=") {
		t.Fatalf("link state/URL = %#v/%q, want link action user 42", states.created, authorizationURL)
	}
	if err := service.CallbackLink(context.Background(), 42, "google", "code", state); err != nil {
		t.Fatalf("CallbackLink() error = %v, want nil", err)
	}
	if identities.created.Subject != "linked-subject" || users.updated.EmailVerifiedAt == nil {
		t.Fatalf("linked identity/verified user = %#v/%v, want identity and verified email", identities.created, users.updated.EmailVerifiedAt)
	}
}

func TestOAuthSignInLinkRejectsDuplicateAndWrongActor(t *testing.T) {
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	provider := &oauthProviderStub{name: "google", profile: OAuthProfile{Subject: "linked-subject", Email: "user@example.com"}}
	tests := []struct {
		name     string
		actorID  int64
		stored   OAuthState
		identity *oauthIdentityRepositoryStub
		expected error
	}{
		{name: "wrong actor", actorID: 99, stored: OAuthState{State: state, Provider: "google", Action: oauthActionLink, UserID: 42, ExpiresAt: 200}, identity: &oauthIdentityRepositoryStub{findErr: ErrOAuthIdentityNotFound}, expected: ErrOAuthStateInvalid},
		{name: "duplicate identity", actorID: 42, stored: OAuthState{State: state, Provider: "google", Action: oauthActionLink, UserID: 42, ExpiresAt: 200}, identity: &oauthIdentityRepositoryStub{found: OAuthIdentity{ID: 7, UserID: 42, Provider: "google", Subject: "linked-subject"}}, expected: ErrOAuthIdentityConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newOAuthServiceForTest(t, provider, &oauthStateRepositoryStub{consumed: test.stored}, test.identity, &oauthUserRepositoryStub{byID: User{ID: 42, Email: stringPointer("user@example.com")}})
			if err := service.CallbackLink(context.Background(), test.actorID, "google", "code", state); !errors.Is(err, test.expected) {
				t.Fatalf("CallbackLink() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

func TestOAuthSignInUnlinkEnforcesLastCredential(t *testing.T) {
	tests := []struct {
		name          string
		password      *string
		identities    []OAuthIdentity
		identityID    int64
		expected      error
		wantDeletedID int64
	}{
		{name: "password account", password: stringPointer("hash"), identities: []OAuthIdentity{{ID: 7, UserID: 42}, {ID: 8, UserID: 42}}, identityID: 7, wantDeletedID: 7},
		{name: "last external method", identities: []OAuthIdentity{{ID: 7, UserID: 42}}, identityID: 7, expected: ErrOAuthLastSignInMethod},
		{name: "not attached", password: stringPointer("hash"), identities: []OAuthIdentity{{ID: 7, UserID: 42}}, identityID: 9, expected: ErrOAuthIdentityNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identities := &oauthIdentityRepositoryStub{listed: test.identities}
			users := &oauthUserRepositoryStub{byID: User{ID: 42, PasswordHash: test.password}}
			service := newOAuthServiceForTest(t, &oauthProviderStub{name: "google"}, &oauthStateRepositoryStub{}, identities, users)
			err := service.Unlink(context.Background(), 42, test.identityID)
			if !errors.Is(err, test.expected) {
				if test.expected == nil {
					t.Fatalf("Unlink() error = %v, want nil", err)
				}
				t.Fatalf("Unlink() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
			if identities.deletedID != test.wantDeletedID {
				t.Errorf("deleted identity ID = %d, want %d", identities.deletedID, test.wantDeletedID)
			}
		})
	}
}

func newOAuthServiceForTest(t *testing.T, provider *oauthProviderStub, states *oauthStateRepositoryStub, identities *oauthIdentityRepositoryStub, users *oauthUserRepositoryStub) *OAuthSignInService {
	t.Helper()
	registry, err := NewProviderRegistry(provider)
	if err != nil {
		t.Fatalf("NewProviderRegistry() error = %v, want nil", err)
	}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	service, err := NewOAuthSignInService(registry, states, identities, users, sessions, time.Hour)
	if err != nil {
		t.Fatalf("NewOAuthSignInService() error = %v, want nil", err)
	}
	service.now = func() time.Time { return time.Unix(100, 0) }
	return service
}

type oauthProviderStub struct {
	name             string
	authorizationURL string
	profile          OAuthProfile
	exchangeErr      error
	receivedCode     string
}

func (p *oauthProviderStub) Name() string {
	return p.name
}

func (p *oauthProviderStub) AuthorizationURL(_ context.Context, state string) (string, error) {
	parsed, err := url.Parse(p.authorizationURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("state", state)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (p *oauthProviderStub) Exchange(_ context.Context, code string) (OAuthProfile, error) {
	p.receivedCode = code
	if p.exchangeErr != nil {
		return OAuthProfile{}, p.exchangeErr
	}
	return p.profile, nil
}

type oauthStateRepositoryStub struct {
	created       OAuthState
	consumed      OAuthState
	consumedState string
	consumedAt    int64
	consumeErr    error
}

func (r *oauthStateRepositoryStub) CreateOAuthState(_ context.Context, state OAuthState) error {
	r.created = state
	return nil
}

func (r *oauthStateRepositoryStub) ConsumeOAuthState(_ context.Context, state string, now int64) (OAuthState, error) {
	r.consumedState = state
	r.consumedAt = now
	if r.consumeErr != nil {
		return OAuthState{}, r.consumeErr
	}
	return r.consumed, nil
}

type oauthIdentityRepositoryStub struct {
	found       OAuthIdentity
	findErr     error
	created     OAuthIdentity
	createErr   error
	createCalls int
	listed      []OAuthIdentity
	listErr     error
	deletedUser int64
	deletedID   int64
	deleteErr   error
}

func (r *oauthIdentityRepositoryStub) FindOAuthIdentity(context.Context, string, string) (OAuthIdentity, error) {
	if r.findErr != nil {
		return OAuthIdentity{}, r.findErr
	}
	return r.found, nil
}

func (r *oauthIdentityRepositoryStub) CreateOAuthIdentity(_ context.Context, identity OAuthIdentity) error {
	r.createCalls++
	if r.createErr != nil {
		return r.createErr
	}
	r.created = identity
	return nil
}

func (r *oauthIdentityRepositoryStub) ListOAuthIdentities(context.Context, int64) ([]OAuthIdentity, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	return append([]OAuthIdentity(nil), r.listed...), nil
}

func (r *oauthIdentityRepositoryStub) DeleteOAuthIdentity(_ context.Context, userID, identityID int64) error {
	r.deletedUser = userID
	r.deletedID = identityID
	return r.deleteErr
}

type oauthUserRepositoryStub struct {
	byID         User
	byEmail      User
	created      User
	updated      User
	createErr    error
	findIDErr    error
	findEmailErr error
	updateErr    error
	createCalls  int
	updateCalls  int
}

func (r *oauthUserRepositoryStub) CreateUser(_ context.Context, user User) (User, error) {
	r.createCalls++
	if r.createErr != nil {
		return User{}, r.createErr
	}
	r.created = user
	r.created.ID = 99
	return r.created, nil
}

func (r *oauthUserRepositoryStub) FindUserByID(context.Context, int64) (User, error) {
	if r.findIDErr != nil {
		return User{}, r.findIDErr
	}
	if r.byID.ID == 0 {
		return User{}, ErrUserNotFound
	}
	return r.byID, nil
}

func (r *oauthUserRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	if r.findEmailErr != nil {
		return User{}, r.findEmailErr
	}
	if r.byEmail.ID == 0 {
		return User{}, ErrUserNotFound
	}
	return r.byEmail, nil
}

func (r *oauthUserRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *oauthUserRepositoryStub) UpdateUser(_ context.Context, user User, _ int64) (User, error) {
	r.updateCalls++
	if r.updateErr != nil {
		return User{}, r.updateErr
	}
	r.updated = user
	r.updated.Version++
	return r.updated, nil
}

func (r *oauthUserRepositoryStub) DeleteUser(context.Context, int64, int64) error {
	return ErrUserNotFound
}
