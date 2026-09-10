package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidCredentials is the uniform normal failure for sign-in.
	ErrInvalidCredentials = errors.New("service: invalid credentials")
	// ErrEmailUnconfirmed identifies a correct password blocked by confirmation policy.
	ErrEmailUnconfirmed = errors.New("service: email unconfirmed")
)

// SignInInput contains the identifier and password submitted by a user.
type SignInInput struct {
	Identifier string
	Password   string
}

// SignInResult contains the authenticated account and newly created session.
type SignInResult struct {
	User    User
	Session Session
}

// PasswordVerifier is the small password-checking port consumed by sign-in.
type PasswordVerifier interface {
	Verify(string, string) (bool, error)
}

// FailedAttemptState clears failed-attempt state after successful sign-in.
type FailedAttemptState interface {
	Clear(context.Context, string) error
}

// SignInService authenticates password-backed accounts.
type SignInService struct {
	users                UserRepository
	verifier             PasswordVerifier
	sessions             *SessionService
	attempts             FailedAttemptState
	confirmationRequired bool
}

// NewSignInService constructs sign-in with explicit account, password, session,
// and failed-attempt dependencies.
func NewSignInService(
	users UserRepository,
	verifier PasswordVerifier,
	sessions *SessionService,
	attempts FailedAttemptState,
	confirmationRequired bool,
) (*SignInService, error) {
	if users == nil {
		return nil, errors.New("service: nil user repository")
	}
	if verifier == nil {
		return nil, errors.New("service: nil password verifier")
	}
	if sessions == nil {
		return nil, ErrNilSessionRepository
	}
	if attempts == nil {
		return nil, errors.New("service: nil failed attempt state")
	}
	return &SignInService{
		users:                users,
		verifier:             verifier,
		sessions:             sessions,
		attempts:             attempts,
		confirmationRequired: confirmationRequired,
	}, nil
}

// SignIn authenticates by normalized email or username and creates a session
// for successful credentials.
func (s *SignInService) SignIn(ctx context.Context, input SignInInput) (SignInResult, error) {
	if s == nil || s.users == nil || s.verifier == nil || s.sessions == nil || s.attempts == nil {
		return SignInResult{}, ErrInvalidCredentials
	}
	if ctx == nil {
		return SignInResult{}, errors.New("service: nil signin context")
	}
	identifier, isEmail, err := normalizeSignInIdentifier(input.Identifier)
	if err != nil {
		return SignInResult{}, ErrInvalidCredentials
	}

	user, err := s.findUser(ctx, identifier, isEmail)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return SignInResult{}, ErrInvalidCredentials
		}
		return SignInResult{}, fmt.Errorf("find signin user: %w", err)
	}
	if user.ID <= 0 || user.IsGuest || user.PasswordHash == nil {
		return SignInResult{}, ErrInvalidCredentials
	}
	valid, err := s.verifier.Verify(input.Password, *user.PasswordHash)
	if err != nil || !valid {
		return SignInResult{}, ErrInvalidCredentials
	}
	if s.confirmationRequired && user.EmailVerifiedAt == nil {
		return SignInResult{}, ErrEmailUnconfirmed
	}
	if err := s.attempts.Clear(ctx, identifier); err != nil {
		return SignInResult{}, fmt.Errorf("clear signin attempts: %w", err)
	}
	session, err := s.sessions.Create(ctx, user.ID)
	if err != nil {
		return SignInResult{}, fmt.Errorf("create signin session: %w", err)
	}
	user.PasswordHash = nil
	return SignInResult{User: user, Session: session}, nil
}

func (s *SignInService) findUser(ctx context.Context, identifier string, isEmail bool) (User, error) {
	if isEmail {
		return s.users.FindUserByEmail(ctx, identifier)
	}
	return s.users.FindUserByUsername(ctx, identifier)
}

func normalizeSignInIdentifier(raw string) (string, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.Contains(trimmed, "@") {
		identifier, err := NormalizeEmail(trimmed)
		if err != nil || identifier == "" {
			return "", true, ErrInvalidCredentials
		}
		return identifier, true, nil
	}
	identifier, err := NormalizeUsername(trimmed)
	if err != nil || identifier == "" {
		return "", false, ErrInvalidCredentials
	}
	return identifier, false, nil
}
