package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultOAuthStateLifetime is used by application wiring when no
	// deployment-specific state lifetime is configured.
	DefaultOAuthStateLifetime = 10 * time.Minute
	oauthStateBytes           = 32
	maxOAuthStateLength       = oauthStateBytes * 2
	maxOAuthCodeLength        = 2048
	maxOAuthSubjectLength     = 255
)

var (
	// ErrOAuthProviderUnavailable identifies an absent or unusable provider.
	ErrOAuthProviderUnavailable = errors.New("service: oauth provider unavailable")
	// ErrOAuthStateInvalid identifies missing, expired, or mismatched callback state.
	ErrOAuthStateInvalid = errors.New("service: invalid oauth state")
	// ErrOAuthAuthenticationFailed is the safe failure for provider callbacks.
	ErrOAuthAuthenticationFailed = errors.New("service: oauth authentication failed")
	// ErrOAuthEmailConflict refuses account merging by reported email.
	ErrOAuthEmailConflict = errors.New("service: oauth email conflict")
	// ErrOAuthIdentityNotFound identifies an unlinked provider subject.
	ErrOAuthIdentityNotFound = errors.New("service: oauth identity not found")
	// ErrOAuthIdentityConflict identifies a concurrent identity attachment.
	ErrOAuthIdentityConflict = errors.New("service: oauth identity conflict")
)

// OAuthProviderClient is the provider-specific transport port consumed by the
// OAuth sign-in service. Registry membership controls whether it is reachable.
type OAuthProviderClient interface {
	OAuthProvider
	AuthorizationURL(context.Context, string) (string, error)
	Exchange(context.Context, string) (OAuthProfile, error)
}

// OAuthProfile contains provider-asserted identity metadata. Subject is the
// stable provider identifier used for account matching.
type OAuthProfile struct {
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

// OAuthState is one short-lived, one-time callback state record.
type OAuthState struct {
	State     string
	Provider  string
	CreatedAt int64
	ExpiresAt int64
}

// OAuthStateRepository persists and atomically consumes callback state.
type OAuthStateRepository interface {
	CreateOAuthState(context.Context, OAuthState) error
	ConsumeOAuthState(context.Context, string, int64) (OAuthState, error)
}

// OAuthIdentity is a stable external identity attached to an account.
type OAuthIdentity struct {
	ID        int64
	UserID    int64
	Provider  string
	Subject   string
	Email     string
	CreatedAt int64
}

// OAuthIdentityRepository resolves and creates external identities.
type OAuthIdentityRepository interface {
	FindOAuthIdentity(context.Context, string, string) (OAuthIdentity, error)
	CreateOAuthIdentity(context.Context, OAuthIdentity) error
}

// OAuthSignInResult contains the account and session created by OAuth sign-in.
type OAuthSignInResult struct {
	User    User
	Session Session
}

// OAuthSignInService handles provider redirects and callback account mapping.
type OAuthSignInService struct {
	providers  *ProviderRegistry
	states     OAuthStateRepository
	identities OAuthIdentityRepository
	users      UserRepository
	sessions   *SessionService
	stateLife  time.Duration
	now        func() time.Time
}

// NewOAuthSignInService constructs OAuth flows with explicit registry, state,
// identity, account, and session dependencies.
func NewOAuthSignInService(
	providers *ProviderRegistry,
	states OAuthStateRepository,
	identities OAuthIdentityRepository,
	users UserRepository,
	sessions *SessionService,
	stateLifetime time.Duration,
) (*OAuthSignInService, error) {
	if providers == nil || states == nil || identities == nil || users == nil || sessions == nil || stateLifetime < time.Second {
		return nil, ErrOAuthProviderUnavailable
	}
	return &OAuthSignInService{
		providers:  providers,
		states:     states,
		identities: identities,
		users:      users,
		sessions:   sessions,
		stateLife:  stateLifetime,
		now:        time.Now,
	}, nil
}

// Start creates one callback state and returns a provider authorization URL.
// Unconfigured providers cannot be reached through this method.
func (s *OAuthSignInService) Start(ctx context.Context, providerName string) (string, error) {
	if err := s.validate(ctx); err != nil {
		return "", err
	}
	provider, ok := s.providerClient(providerName)
	if !ok {
		return "", ErrOAuthProviderUnavailable
	}
	state, err := newOAuthState()
	if err != nil {
		return "", err
	}
	createdAt := s.now().Unix()
	expiresAt := createdAt + int64(s.stateLife/time.Second)
	if expiresAt <= createdAt {
		return "", ErrOAuthStateInvalid
	}
	authorizationURL, err := provider.AuthorizationURL(ctx, state)
	if err != nil {
		return "", oauthFailure(err)
	}
	if !safeOAuthURL(authorizationURL) {
		return "", ErrOAuthAuthenticationFailed
	}
	if err := s.states.CreateOAuthState(ctx, OAuthState{State: state, Provider: canonicalProviderName(provider.Name()), CreatedAt: createdAt, ExpiresAt: expiresAt}); err != nil {
		return "", oauthFailure(err)
	}
	return authorizationURL, nil
}

// Callback consumes state and authenticates the provider profile. Provider
// subject, never reported email, selects an existing account.
func (s *OAuthSignInService) Callback(ctx context.Context, providerName, code, rawState string) (OAuthSignInResult, error) {
	if err := s.validate(ctx); err != nil {
		return OAuthSignInResult{}, err
	}
	if strings.TrimSpace(code) == "" || len(code) > maxOAuthCodeLength {
		return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
	}
	state, err := normalizeOAuthState(rawState)
	if err != nil {
		return OAuthSignInResult{}, err
	}
	provider, ok := s.providerClient(providerName)
	if !ok {
		return OAuthSignInResult{}, ErrOAuthProviderUnavailable
	}
	now := s.now().Unix()
	storedState, err := s.states.ConsumeOAuthState(ctx, state, now)
	if err != nil {
		return OAuthSignInResult{}, ErrOAuthStateInvalid
	}
	canonicalName := canonicalProviderName(provider.Name())
	if storedState.Provider != canonicalName || storedState.ExpiresAt <= now ||
		storedState.State == "" || subtle.ConstantTimeCompare([]byte(storedState.State), []byte(state)) != 1 {
		return OAuthSignInResult{}, ErrOAuthStateInvalid
	}
	profile, err := provider.Exchange(ctx, code)
	if err != nil {
		return OAuthSignInResult{}, oauthFailure(err)
	}
	if err := validateOAuthProfile(profile); err != nil {
		return OAuthSignInResult{}, err
	}

	identity, err := s.identities.FindOAuthIdentity(ctx, canonicalName, profile.Subject)
	if err == nil {
		return s.signInExistingIdentity(ctx, identity)
	}
	if !errors.Is(err, ErrOAuthIdentityNotFound) {
		return OAuthSignInResult{}, oauthFailure(err)
	}
	return s.createOAuthAccount(ctx, canonicalName, profile, now)
}

func (s *OAuthSignInService) signInExistingIdentity(ctx context.Context, identity OAuthIdentity) (OAuthSignInResult, error) {
	if identity.UserID <= 0 {
		return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
	}
	user, err := s.users.FindUserByID(ctx, identity.UserID)
	if err != nil || user.ID != identity.UserID {
		return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
	}
	session, err := s.sessions.Create(ctx, user.ID)
	if err != nil {
		return OAuthSignInResult{}, oauthFailure(err)
	}
	user.PasswordHash = nil
	return OAuthSignInResult{User: user, Session: session}, nil
}

func (s *OAuthSignInService) createOAuthAccount(ctx context.Context, providerName string, profile OAuthProfile, now int64) (OAuthSignInResult, error) {
	email := ""
	if profile.Email != "" {
		normalized, err := NormalizeEmail(profile.Email)
		if err != nil || normalized == "" {
			return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
		}
		email = normalized
		existing, err := s.users.FindUserByEmail(ctx, email)
		if err == nil && existing.ID > 0 {
			return OAuthSignInResult{}, ErrOAuthEmailConflict
		}
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			return OAuthSignInResult{}, oauthFailure(err)
		}
	} else {
		return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
	}

	displayName, err := normalizeDisplayName(profile.DisplayName)
	if err != nil {
		return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
	}
	user := User{
		Email:       &email,
		DisplayName: optionalString(displayName),
		IsGuest:     false,
		IsAdmin:     false,
		Theme:       defaultUserTheme,
		Locale:      defaultUserLocale,
		CreatedAt:   now,
		Version:     0,
	}
	if profile.EmailVerified {
		verifiedAt := now
		user.EmailVerifiedAt = &verifiedAt
	}
	created, err := s.users.CreateUser(ctx, user)
	if err != nil {
		return OAuthSignInResult{}, oauthFailure(err)
	}
	if created.ID <= 0 {
		return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
	}
	identity := OAuthIdentity{UserID: created.ID, Provider: providerName, Subject: profile.Subject, Email: email, CreatedAt: now}
	if err := s.identities.CreateOAuthIdentity(ctx, identity); err != nil {
		if errors.Is(err, ErrOAuthIdentityConflict) {
			return OAuthSignInResult{}, ErrOAuthAuthenticationFailed
		}
		return OAuthSignInResult{}, oauthFailure(err)
	}
	session, err := s.sessions.Create(ctx, created.ID)
	if err != nil {
		return OAuthSignInResult{}, oauthFailure(err)
	}
	created.PasswordHash = nil
	return OAuthSignInResult{User: created, Session: session}, nil
}

func (s *OAuthSignInService) validate(ctx context.Context) error {
	if s == nil || s.providers == nil || s.states == nil || s.identities == nil || s.users == nil || s.sessions == nil || s.now == nil {
		return ErrOAuthProviderUnavailable
	}
	if ctx == nil {
		return errors.New("service: nil oauth context")
	}
	return nil
}

func (s *OAuthSignInService) providerClient(name string) (OAuthProviderClient, bool) {
	provider, ok := s.providers.Get(name)
	if !ok {
		return nil, false
	}
	client, ok := provider.(OAuthProviderClient)
	return client, ok
}

func validateOAuthProfile(profile OAuthProfile) error {
	if profile.Subject == "" || len(profile.Subject) > maxOAuthSubjectLength || strings.ContainsAny(profile.Subject, "\x00\r\n") {
		return ErrOAuthAuthenticationFailed
	}
	return nil
}

func normalizeOAuthState(raw string) (string, error) {
	if len(raw) != maxOAuthStateLength {
		return "", ErrOAuthStateInvalid
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return "", ErrOAuthStateInvalid
	}
	return raw, nil
}

func newOAuthState() (string, error) {
	value := make([]byte, oauthStateBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate oauth state: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func safeOAuthURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != "" && parsed.User == nil
}

func oauthFailure(_ error) error {
	return ErrOAuthAuthenticationFailed
}

func canonicalProviderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
