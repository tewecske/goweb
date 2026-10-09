package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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
	oauthActionSignIn         = "sign-in"
	oauthActionLink           = "link"
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
	// ErrOAuthLastSignInMethod prevents removing an account's final credential.
	ErrOAuthLastSignInMethod = errors.New("service: last oauth sign-in method")
)

// OAuthProviderClient is the provider-specific transport port consumed by the
// OAuth sign-in service. Registry membership controls whether it is reachable.
type OAuthProviderClient interface {
	OAuthProvider
	// AuthorizationURL receives the callback state and the PKCE S256 code
	// challenge; Exchange receives the matching code verifier.
	AuthorizationURL(ctx context.Context, state, codeChallenge string) (string, error)
	Exchange(ctx context.Context, code, codeVerifier string) (OAuthProfile, error)
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
// CodeVerifier is the PKCE secret that redeems this flow's authorization code.
type OAuthState struct {
	State        string
	Provider     string
	Action       string
	UserID       int64
	CodeVerifier string
	CreatedAt    int64
	ExpiresAt    int64
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
	ListOAuthIdentities(context.Context, int64) ([]OAuthIdentity, error)
	DeleteOAuthIdentity(context.Context, int64, int64) error
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

// Start creates one callback state and returns a provider authorization URL
// and the state, which the caller binds to the initiating browser.
// Unconfigured providers cannot be reached through this method.
func (s *OAuthSignInService) Start(ctx context.Context, providerName string) (string, string, error) {
	if err := s.validate(ctx); err != nil {
		return "", "", err
	}
	provider, ok := s.providerClient(providerName)
	if !ok {
		return "", "", ErrOAuthProviderUnavailable
	}
	state, err := newOAuthState()
	if err != nil {
		return "", "", err
	}
	verifier, challenge, err := newPKCEVerifier()
	if err != nil {
		return "", "", err
	}
	createdAt := s.now().Unix()
	expiresAt := createdAt + int64(s.stateLife/time.Second)
	if expiresAt <= createdAt {
		return "", "", ErrOAuthStateInvalid
	}
	authorizationURL, err := provider.AuthorizationURL(ctx, state, challenge)
	if err != nil {
		return "", "", oauthFailure(err)
	}
	if !safeOAuthURL(authorizationURL) {
		return "", "", ErrOAuthAuthenticationFailed
	}
	if err := s.states.CreateOAuthState(ctx, OAuthState{State: state, Provider: canonicalProviderName(provider.Name()), Action: oauthActionSignIn, CodeVerifier: verifier, CreatedAt: createdAt, ExpiresAt: expiresAt}); err != nil {
		return "", "", oauthFailure(err)
	}
	return authorizationURL, state, nil
}

// OAuthCallbackResult is the outcome of one provider callback. Linked selects
// whether the callback attached an identity to an account or signed one in.
type OAuthCallbackResult struct {
	Linked bool
	UserID int64
	SignIn OAuthSignInResult
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
	stored, canonicalName, provider, now, err := s.consumeCallbackState(ctx, providerName, rawState)
	if err != nil {
		return OAuthSignInResult{}, err
	}
	if stored.Action != oauthActionSignIn || stored.UserID != 0 {
		return OAuthSignInResult{}, ErrOAuthStateInvalid
	}
	profile, err := exchangeOAuthProfile(ctx, provider, code, stored.CodeVerifier)
	if err != nil {
		return OAuthSignInResult{}, err
	}
	return s.signInWithProfile(ctx, canonicalName, profile, now)
}

// CompleteCallback consumes one callback state and completes whichever flow it
// represents: an anonymous sign-in or an authenticated identity link. The HTTP
// layer uses it because both flows share the registered redirect URI.
// actorUserID is the account signed in to the browser presenting the callback,
// or zero; a link completes only for the account that started it.
func (s *OAuthSignInService) CompleteCallback(ctx context.Context, actorUserID int64, providerName, code, rawState string) (OAuthCallbackResult, error) {
	if err := s.validate(ctx); err != nil {
		return OAuthCallbackResult{}, err
	}
	if strings.TrimSpace(code) == "" || len(code) > maxOAuthCodeLength {
		return OAuthCallbackResult{}, ErrOAuthAuthenticationFailed
	}
	stored, canonicalName, provider, now, err := s.consumeCallbackState(ctx, providerName, rawState)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	switch stored.Action {
	case oauthActionSignIn:
		if stored.UserID != 0 {
			return OAuthCallbackResult{}, ErrOAuthStateInvalid
		}
	case oauthActionLink:
		if stored.UserID <= 0 || stored.UserID != actorUserID {
			return OAuthCallbackResult{}, ErrOAuthStateInvalid
		}
	default:
		return OAuthCallbackResult{}, ErrOAuthStateInvalid
	}
	profile, err := exchangeOAuthProfile(ctx, provider, code, stored.CodeVerifier)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	if stored.Action == oauthActionLink {
		if err := s.linkProfile(ctx, stored.UserID, canonicalName, profile, now); err != nil {
			return OAuthCallbackResult{}, err
		}
		return OAuthCallbackResult{Linked: true, UserID: stored.UserID}, nil
	}
	result, err := s.signInWithProfile(ctx, canonicalName, profile, now)
	if err != nil {
		return OAuthCallbackResult{}, err
	}
	return OAuthCallbackResult{SignIn: result}, nil
}

// consumeCallbackState normalizes and atomically consumes one callback state,
// validating provider identity, expiry, and the constant-time state match.
func (s *OAuthSignInService) consumeCallbackState(ctx context.Context, providerName, rawState string) (OAuthState, string, OAuthProviderClient, int64, error) {
	state, err := normalizeOAuthState(rawState)
	if err != nil {
		return OAuthState{}, "", nil, 0, err
	}
	provider, ok := s.providerClient(providerName)
	if !ok {
		return OAuthState{}, "", nil, 0, ErrOAuthProviderUnavailable
	}
	now := s.now().Unix()
	stored, err := s.states.ConsumeOAuthState(ctx, state, now)
	if err != nil {
		return OAuthState{}, "", nil, 0, ErrOAuthStateInvalid
	}
	canonicalName := canonicalProviderName(provider.Name())
	if stored.Provider != canonicalName || stored.ExpiresAt <= now ||
		stored.State == "" || subtle.ConstantTimeCompare([]byte(stored.State), []byte(state)) != 1 {
		return OAuthState{}, "", nil, 0, ErrOAuthStateInvalid
	}
	return stored, canonicalName, provider, now, nil
}

func exchangeOAuthProfile(ctx context.Context, provider OAuthProviderClient, code, codeVerifier string) (OAuthProfile, error) {
	if codeVerifier == "" {
		return OAuthProfile{}, ErrOAuthStateInvalid
	}
	profile, err := provider.Exchange(ctx, code, codeVerifier)
	if err != nil {
		return OAuthProfile{}, oauthFailure(err)
	}
	if err := validateOAuthProfile(profile); err != nil {
		return OAuthProfile{}, err
	}
	return profile, nil
}

// signInWithProfile resolves an existing identity or creates an account. It
// never merges accounts by reported email.
func (s *OAuthSignInService) signInWithProfile(ctx context.Context, canonicalName string, profile OAuthProfile, now int64) (OAuthSignInResult, error) {
	identity, err := s.identities.FindOAuthIdentity(ctx, canonicalName, profile.Subject)
	if err == nil {
		return s.signInExistingIdentity(ctx, identity)
	}
	if !errors.Is(err, ErrOAuthIdentityNotFound) {
		return OAuthSignInResult{}, oauthFailure(err)
	}
	return s.createOAuthAccount(ctx, canonicalName, profile, now)
}

// StartLink creates a provider callback state bound to an authenticated user
// and returns the authorization URL and the state for browser binding.
func (s *OAuthSignInService) StartLink(ctx context.Context, userID int64, providerName string) (string, string, error) {
	if err := s.validate(ctx); err != nil {
		return "", "", err
	}
	if userID <= 0 {
		return "", "", ErrOAuthAuthenticationFailed
	}
	if _, err := s.users.FindUserByID(ctx, userID); err != nil {
		return "", "", ErrOAuthAuthenticationFailed
	}
	provider, ok := s.providerClient(providerName)
	if !ok {
		return "", "", ErrOAuthProviderUnavailable
	}
	state, err := newOAuthState()
	if err != nil {
		return "", "", err
	}
	verifier, challenge, err := newPKCEVerifier()
	if err != nil {
		return "", "", err
	}
	createdAt := s.now().Unix()
	expiresAt := createdAt + int64(s.stateLife/time.Second)
	if expiresAt <= createdAt {
		return "", "", ErrOAuthStateInvalid
	}
	authorizationURL, err := provider.AuthorizationURL(ctx, state, challenge)
	if err != nil || !safeOAuthURL(authorizationURL) {
		return "", "", ErrOAuthAuthenticationFailed
	}
	if err := s.states.CreateOAuthState(ctx, OAuthState{State: state, Provider: canonicalProviderName(provider.Name()), Action: oauthActionLink, UserID: userID, CodeVerifier: verifier, CreatedAt: createdAt, ExpiresAt: expiresAt}); err != nil {
		return "", "", oauthFailure(err)
	}
	return authorizationURL, state, nil
}

// CallbackLink consumes a link state and attaches the returned provider
// identity to actorUserID. It never merges accounts by reported email.
func (s *OAuthSignInService) CallbackLink(ctx context.Context, actorUserID int64, providerName, code, rawState string) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if actorUserID <= 0 || strings.TrimSpace(code) == "" || len(code) > maxOAuthCodeLength {
		return ErrOAuthAuthenticationFailed
	}
	stored, canonicalName, provider, now, err := s.consumeCallbackState(ctx, providerName, rawState)
	if err != nil {
		return err
	}
	if stored.Action != oauthActionLink || stored.UserID != actorUserID {
		return ErrOAuthStateInvalid
	}
	profile, err := exchangeOAuthProfile(ctx, provider, code, stored.CodeVerifier)
	if err != nil {
		return err
	}
	return s.linkProfile(ctx, actorUserID, canonicalName, profile, now)
}

// linkProfile attaches one provider identity to an account, refusing a subject
// already linked elsewhere, and confirms the account email when the provider
// asserts a verified match.
func (s *OAuthSignInService) linkProfile(ctx context.Context, actorUserID int64, canonicalName string, profile OAuthProfile, now int64) error {
	if _, err := s.identities.FindOAuthIdentity(ctx, canonicalName, profile.Subject); err == nil {
		return ErrOAuthIdentityConflict
	} else if !errors.Is(err, ErrOAuthIdentityNotFound) {
		return oauthFailure(err)
	}
	user, err := s.users.FindUserByID(ctx, actorUserID)
	if err != nil || user.ID != actorUserID {
		return ErrOAuthAuthenticationFailed
	}
	email := ""
	if profile.Email != "" {
		email, err = NormalizeEmail(profile.Email)
		if err != nil || email == "" {
			return ErrOAuthAuthenticationFailed
		}
	}
	identity := OAuthIdentity{UserID: actorUserID, Provider: canonicalName, Subject: profile.Subject, Email: email, CreatedAt: now}
	if err := s.identities.CreateOAuthIdentity(ctx, identity); err != nil {
		if errors.Is(err, ErrOAuthIdentityConflict) {
			return ErrOAuthIdentityConflict
		}
		return oauthFailure(err)
	}
	if profile.EmailVerified && email != "" && user.Email != nil {
		accountEmail, normalizeErr := NormalizeEmail(*user.Email)
		if normalizeErr == nil && accountEmail == email && user.EmailVerifiedAt == nil {
			verifiedAt := now
			user.EmailVerifiedAt = &verifiedAt
			updated, updateErr := s.users.UpdateUser(ctx, user, user.Version)
			if updateErr != nil || updated.ID != actorUserID {
				return oauthFailure(updateErr)
			}
		}
	}
	return nil
}

// Unlink removes one external identity unless it would leave the account with
// no password and no other linked identity.
func (s *OAuthSignInService) Unlink(ctx context.Context, userID, identityID int64) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if userID <= 0 || identityID <= 0 {
		return ErrOAuthIdentityNotFound
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return ErrOAuthIdentityNotFound
	}
	identities, err := s.identities.ListOAuthIdentities(ctx, userID)
	if err != nil {
		return oauthFailure(err)
	}
	var target OAuthIdentity
	found := false
	for _, identity := range identities {
		if identity.ID == identityID && identity.UserID == userID {
			target = identity
			found = true
			break
		}
	}
	if !found {
		return ErrOAuthIdentityNotFound
	}
	if user.PasswordHash == nil && len(identities) <= 1 {
		return ErrOAuthLastSignInMethod
	}
	if err := s.identities.DeleteOAuthIdentity(ctx, userID, target.ID); err != nil {
		return oauthFailure(err)
	}
	return nil
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

// newPKCEVerifier returns an RFC 7636 code verifier and its S256 challenge.
func newPKCEVerifier() (string, string, error) {
	value := make([]byte, oauthStateBytes)
	if _, err := rand.Read(value); err != nil {
		return "", "", fmt.Errorf("generate oauth code verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(value)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
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
