package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// maxSSOChallenge bounds login, consent, and logout challenges. Hydra's
// challenges carry an encrypted flow and are about 1.5 KB.
const maxSSOChallenge = 4096

var (
	// ErrNilSSOAdmin identifies missing Hydra admin API access.
	ErrNilSSOAdmin = errors.New("service: nil single sign-on admin")
	// ErrNilSSOLoginSessionRepository identifies missing sid persistence.
	ErrNilSSOLoginSessionRepository = errors.New("service: nil single sign-on session repository")
	// ErrInvalidSSOChallenge identifies an empty or oversized challenge.
	ErrInvalidSSOChallenge = errors.New("service: invalid single sign-on challenge")
	// ErrSSOChallengeExpired identifies a challenge Hydra no longer knows or
	// has already handled.
	ErrSSOChallengeExpired = errors.New("service: single sign-on challenge expired")
	// ErrSSOUnavailable identifies a failed call to the Hydra admin API.
	ErrSSOUnavailable = errors.New("service: single sign-on unavailable")
)

// SSOLoginRequest is the part of a Hydra login request the provider uses.
// Skip means Hydra already holds an authenticated session for Subject.
type SSOLoginRequest struct {
	Skip      bool
	Subject   string
	SessionID string
	// ClientName is the registered name of the app asking for the sign-in.
	ClientName string
}

// SSOConsentRequest is the part of a Hydra consent request the provider uses.
type SSOConsentRequest struct {
	Subject           string
	LoginSessionID    string
	RequestedScope    []string
	RequestedAudience []string
}

// SSOLogoutRequest is the part of a Hydra logout request the provider uses.
type SSOLogoutRequest struct {
	Subject   string
	SessionID string
}

// SSOConsentGrant is what the provider grants a client: scopes, audiences,
// and the ID token claims rebuilt from the account on every sign-in.
type SSOConsentGrant struct {
	Scope         []string
	Audience      []string
	IDTokenClaims map[string]any
	RememberFor   time.Duration
}

// SSOAdmin is the Hydra admin API port. Accept and reject calls return the URL
// the browser must be redirected to next.
type SSOAdmin interface {
	LoginRequest(ctx context.Context, challenge string) (SSOLoginRequest, error)
	AcceptLogin(ctx context.Context, challenge, subject string, rememberFor time.Duration) (string, error)
	RejectLogin(ctx context.Context, challenge string) (string, error)
	ConsentRequest(ctx context.Context, challenge string) (SSOConsentRequest, error)
	AcceptConsent(ctx context.Context, challenge string, grant SSOConsentGrant) (string, error)
	RejectConsent(ctx context.Context, challenge string) (string, error)
	LogoutRequest(ctx context.Context, challenge string) (SSOLogoutRequest, error)
	AcceptLogout(ctx context.Context, challenge string) (string, error)
	RevokeLoginSession(ctx context.Context, sid string) error
	RevokeConsentSessions(ctx context.Context, subject string) error
}

// SSOLoginSession records one Hydra login session ID for an account.
type SSOLoginSession struct {
	SessionID string
	UserID    int64
	CreatedAt int64
	ExpiresAt int64
}

// SSOLoginSessionRepository persists the Hydra session IDs seen per account.
type SSOLoginSessionRepository interface {
	RecordSSOLoginSession(context.Context, SSOLoginSession) error
	ListSSOLoginSessions(context.Context, int64) ([]string, error)
	DeleteSSOLoginSession(context.Context, string) error
}

// SSOProviderService answers Hydra's login, consent, and logout challenges for
// the identity deployment and revokes an account's single sign-on sessions.
type SSOProviderService struct {
	admin                     SSOAdmin
	users                     UserRepository
	sessions                  SSOLoginSessionRepository
	rememberFor               time.Duration
	emailConfirmationRequired bool
	now                       func() time.Time
}

// NewSSOProviderService constructs the provider use cases. rememberFor is how
// long Hydra keeps the single sign-on session; it matches the session lifetime.
func NewSSOProviderService(admin SSOAdmin, users UserRepository, sessions SSOLoginSessionRepository, rememberFor time.Duration, emailConfirmationRequired bool) (*SSOProviderService, error) {
	if admin == nil {
		return nil, ErrNilSSOAdmin
	}
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if sessions == nil {
		return nil, ErrNilSSOLoginSessionRepository
	}
	if rememberFor < time.Second {
		return nil, ErrInvalidSessionLifetime
	}
	return &SSOProviderService{
		admin:                     admin,
		users:                     users,
		sessions:                  sessions,
		rememberFor:               rememberFor,
		emailConfirmationRequired: emailConfirmationRequired,
		now:                       time.Now,
	}, nil
}

// BeginLogin answers a login challenge without showing a form when possible:
// when Hydra already has a session (skip) or the browser is signed in here.
// An empty redirect means the visitor must sign in first.
func (s *SSOProviderService) BeginLogin(ctx context.Context, challenge string, currentUserID int64) (string, error) {
	if err := validateSSOChallenge(challenge); err != nil {
		return "", err
	}
	request, err := s.admin.LoginRequest(ctx, challenge)
	if err != nil {
		return "", err
	}
	if request.Skip {
		// Hydra requires accepting the remembered subject; refuse it when the
		// account was deleted or may no longer sign in.
		userID, err := parseSSOSubject(request.Subject)
		if err == nil && s.eligible(ctx, userID) {
			return s.admin.AcceptLogin(ctx, challenge, request.Subject, s.rememberFor)
		}
		return s.admin.RejectLogin(ctx, challenge)
	}
	if currentUserID > 0 && s.eligible(ctx, currentUserID) {
		return s.admin.AcceptLogin(ctx, challenge, ssoSubject(currentUserID), s.rememberFor)
	}
	return "", nil
}

// maxSSOClientNameRunes bounds the app name shown on the sign-in page.
const maxSSOClientNameRunes = 64

// LoginClientName returns the registered name of the app a pending login
// challenge belongs to, so the sign-in page can say where the visitor is going.
// It returns "" when the challenge is unusable or the app has no usable name:
// the name is cosmetic and must never block signing in.
func (s *SSOProviderService) LoginClientName(ctx context.Context, challenge string) string {
	if s == nil || s.admin == nil || validateSSOChallenge(challenge) != nil {
		return ""
	}
	request, err := s.admin.LoginRequest(ctx, challenge)
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(request.ClientName)
	if name == "" || utf8.RuneCountInString(name) > maxSSOClientNameRunes {
		return ""
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ""
		}
	}
	return name
}

// CompleteLogin accepts a login challenge for an account that just signed in.
func (s *SSOProviderService) CompleteLogin(ctx context.Context, challenge string, userID int64) (string, error) {
	if err := validateSSOChallenge(challenge); err != nil {
		return "", err
	}
	if !s.eligible(ctx, userID) {
		return s.admin.RejectLogin(ctx, challenge)
	}
	return s.admin.AcceptLogin(ctx, challenge, ssoSubject(userID), s.rememberFor)
}

// Consent grants the requested scopes to a trusted client and supplies ID
// token claims. Hydra asks on every sign-in, so claims always reflect the
// current account.
func (s *SSOProviderService) Consent(ctx context.Context, challenge string) (string, error) {
	if err := validateSSOChallenge(challenge); err != nil {
		return "", err
	}
	request, err := s.admin.ConsentRequest(ctx, challenge)
	if err != nil {
		return "", err
	}
	userID, err := parseSSOSubject(request.Subject)
	if err != nil {
		return s.admin.RejectConsent(ctx, challenge)
	}
	user, ok := s.eligibleUser(ctx, userID)
	if !ok {
		return s.admin.RejectConsent(ctx, challenge)
	}
	if request.LoginSessionID != "" {
		now := s.now().Unix()
		if err := s.sessions.RecordSSOLoginSession(ctx, SSOLoginSession{
			SessionID: request.LoginSessionID,
			UserID:    userID,
			CreatedAt: now,
			ExpiresAt: now + int64(s.rememberFor/time.Second),
		}); err != nil {
			// Without the record a later revocation could miss this session,
			// so the sign-in does not proceed.
			return "", fmt.Errorf("record single sign-on session: %w", err)
		}
	}
	return s.admin.AcceptConsent(ctx, challenge, SSOConsentGrant{
		Scope:         request.RequestedScope,
		Audience:      request.RequestedAudience,
		IDTokenClaims: ssoIDTokenClaims(user, request.RequestedScope),
		RememberFor:   s.rememberFor,
	})
}

// Logout accepts a logout challenge and forgets its session ID. The caller
// ends the provider's own browser session.
func (s *SSOProviderService) Logout(ctx context.Context, challenge string) (string, error) {
	if err := validateSSOChallenge(challenge); err != nil {
		return "", err
	}
	request, err := s.admin.LogoutRequest(ctx, challenge)
	if err != nil {
		return "", err
	}
	if request.SessionID != "" {
		_ = s.sessions.DeleteSSOLoginSession(ctx, request.SessionID)
	}
	return s.admin.AcceptLogout(ctx, challenge)
}

// RevokeUser ends every single sign-on session for an account. Revoking each
// recorded session ID triggers back-channel logout in client apps; revoking
// consent invalidates issued tokens. Records are kept when their revocation
// fails so a retry can finish the job.
func (s *SSOProviderService) RevokeUser(ctx context.Context, userID int64) error {
	if s == nil || s.admin == nil || s.sessions == nil {
		return ErrNilSSOAdmin
	}
	if userID <= 0 {
		return ErrInvalidSessionUserID
	}
	sids, err := s.sessions.ListSSOLoginSessions(ctx, userID)
	if err != nil {
		return fmt.Errorf("list single sign-on sessions: %w", err)
	}
	var failures []error
	for _, sid := range sids {
		if err := s.admin.RevokeLoginSession(ctx, sid); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := s.sessions.DeleteSSOLoginSession(ctx, sid); err != nil {
			failures = append(failures, err)
		}
	}
	if err := s.admin.RevokeConsentSessions(ctx, ssoSubject(userID)); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (s *SSOProviderService) eligible(ctx context.Context, userID int64) bool {
	_, ok := s.eligibleUser(ctx, userID)
	return ok
}

// eligibleUser returns the account when it may sign in to client apps: it
// exists, is not a guest, and has a confirmed email when confirmation is
// required.
func (s *SSOProviderService) eligibleUser(ctx context.Context, userID int64) (User, bool) {
	if userID <= 0 {
		return User{}, false
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil || user.ID != userID || user.IsGuest {
		return User{}, false
	}
	if s.emailConfirmationRequired && user.EmailVerifiedAt == nil {
		return User{}, false
	}
	return user, true
}

// ssoIDTokenClaims follows the standard scope-to-claim mapping: "email"
// releases email and email_verified, "profile" releases name and locale.
func ssoIDTokenClaims(user User, scopes []string) map[string]any {
	claims := map[string]any{}
	if slices.Contains(scopes, "email") && user.Email != nil {
		claims["email"] = *user.Email
		claims["email_verified"] = user.EmailVerifiedAt != nil
	}
	if slices.Contains(scopes, "profile") {
		if name := ssoDisplayName(user); name != "" {
			claims["name"] = name
		}
		if user.Locale != "" {
			claims["locale"] = user.Locale
		}
	}
	return claims
}

func ssoDisplayName(user User) string {
	if user.DisplayName != nil && strings.TrimSpace(*user.DisplayName) != "" {
		return strings.TrimSpace(*user.DisplayName)
	}
	if user.Username != nil {
		return strings.TrimSpace(*user.Username)
	}
	return ""
}

// ssoSubject is the stable OpenID Connect subject: the account ID in decimal.
func ssoSubject(userID int64) string {
	return strconv.FormatInt(userID, 10)
}

func parseSSOSubject(subject string) (int64, error) {
	userID, err := strconv.ParseInt(subject, 10, 64)
	if err != nil || userID <= 0 || ssoSubject(userID) != subject {
		return 0, ErrInvalidSessionUserID
	}
	return userID, nil
}

func validateSSOChallenge(challenge string) error {
	if strings.TrimSpace(challenge) == "" || len(challenge) > maxSSOChallenge {
		return ErrInvalidSSOChallenge
	}
	return nil
}
