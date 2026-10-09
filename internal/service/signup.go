package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tewecske/goweb/internal/locale"
)

const (
	defaultUserTheme     = "light"
	defaultUserLocale    = string(locale.Default)
	maxDisplayNameLength = 255
)

var (
	// ErrUserNotFound identifies an identity lookup without a matching account.
	ErrUserNotFound = errors.New("service: user not found")
	// ErrDuplicateEmail identifies an email already attached to an account.
	ErrDuplicateEmail = errors.New("service: duplicate email")
	// ErrDuplicateUsername identifies a username already attached to an account.
	ErrDuplicateUsername = errors.New("service: duplicate username")
	// ErrInvalidSignupInput identifies missing or malformed account input.
	ErrInvalidSignupInput = errors.New("service: invalid signup input")
	// ErrInvalidDisplayName identifies a display name outside storage limits.
	ErrInvalidDisplayName = errors.New("service: invalid display name")
	// ErrInvalidCreatedUser identifies persistence that did not return its new account.
	ErrInvalidCreatedUser = errors.New("service: invalid created user")
)

// SignUpInput contains account values submitted by a new user. Password is
// never retained after the sign-up operation returns. Origin is the client
// address used for the sign-up rate limit.
type SignUpInput struct {
	Email       string
	Password    string
	Username    string
	DisplayName string
	Origin      string
}

// SignUpResult contains the created account and its new session. When email
// confirmation is required no session is created: the account cannot sign in
// until it confirms its email, so sign-up must not grant access either.
type SignUpResult struct {
	User                 User
	Session              Session
	ConfirmationRequired bool
}

// PasswordHashProvider is the small hashing port consumed by sign-up.
type PasswordHashProvider interface {
	Hash(string) (string, error)
}

// SignUpService creates password-backed accounts and their initial sessions.
type SignUpService struct {
	users                UserRepository
	hasher               PasswordHashProvider
	sessions             *SessionService
	confirmationRequired bool
}

// NewSignUpService constructs sign-up with explicit account, hashing, and
// session dependencies.
func NewSignUpService(
	users UserRepository,
	hasher PasswordHashProvider,
	sessions *SessionService,
	confirmationRequired bool,
) (*SignUpService, error) {
	if users == nil {
		return nil, errors.New("service: nil user repository")
	}
	if hasher == nil {
		return nil, errors.New("service: nil password hash provider")
	}
	if sessions == nil {
		return nil, ErrNilSessionRepository
	}
	return &SignUpService{
		users:                users,
		hasher:               hasher,
		sessions:             sessions,
		confirmationRequired: confirmationRequired,
	}, nil
}

// SignUp validates input, rejects normalized identity duplicates, persists the
// account, and creates its first session.
func (s *SignUpService) SignUp(ctx context.Context, input SignUpInput) (SignUpResult, error) {
	if s == nil || s.users == nil || s.hasher == nil || s.sessions == nil {
		return SignUpResult{}, ErrInvalidSignupInput
	}
	if ctx == nil {
		return SignUpResult{}, errors.New("service: nil signup context")
	}
	if err := ValidatePassword(input.Password); err != nil {
		return SignUpResult{}, fmt.Errorf("validate signup password: %w", err)
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil {
		return SignUpResult{}, errors.Join(ErrInvalidSignupInput, err)
	}
	if email == "" {
		return SignUpResult{}, errors.Join(ErrInvalidSignupInput, ErrInvalidEmail)
	}
	username, err := NormalizeUsername(input.Username)
	if err != nil {
		return SignUpResult{}, errors.Join(ErrInvalidSignupInput, err)
	}
	displayName, err := normalizeDisplayName(input.DisplayName)
	if err != nil {
		return SignUpResult{}, err
	}

	if err := s.rejectDuplicateEmail(ctx, email); err != nil {
		return SignUpResult{}, err
	}
	if username != "" {
		if err := s.rejectDuplicateUsername(ctx, username); err != nil {
			return SignUpResult{}, err
		}
	}

	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return SignUpResult{}, fmt.Errorf("hash signup password: %w", err)
	}
	createdAt := time.Now().Unix()
	user := User{
		Email:        &email,
		PasswordHash: &passwordHash,
		IsGuest:      false,
		IsAdmin:      false,
		Theme:        defaultUserTheme,
		Locale:       defaultUserLocale,
		CreatedAt:    createdAt,
		Version:      0,
	}
	if username != "" {
		user.Username = &username
	}
	if displayName != "" {
		user.DisplayName = &displayName
	}
	created, err := s.users.CreateUser(ctx, user)
	if err != nil {
		return SignUpResult{}, fmt.Errorf("create signup user: %w", err)
	}
	if created.ID <= 0 {
		return SignUpResult{}, ErrInvalidCreatedUser
	}
	created.PasswordHash = nil
	if s.confirmationRequired {
		return SignUpResult{User: created, ConfirmationRequired: true}, nil
	}
	session, err := s.sessions.Create(ctx, created.ID)
	if err != nil {
		return SignUpResult{}, fmt.Errorf("create signup session: %w", err)
	}
	return SignUpResult{User: created, Session: session}, nil
}

const signUpOriginAction = "signup.origin"

// RateLimitedSignUpService applies a per-origin budget before sign-up, which
// bounds password hashing work and probing for registered emails.
type RateLimitedSignUpService struct {
	signUp  *SignUpService
	limiter *RateLimiter
}

// NewRateLimitedSignUpService decorates sign-up with an origin budget.
func NewRateLimitedSignUpService(signUp *SignUpService, limiter *RateLimiter) (*RateLimitedSignUpService, error) {
	if signUp == nil {
		return nil, errors.New("service: nil signup service")
	}
	if limiter == nil {
		return nil, ErrInvalidRateLimitConfig
	}
	return &RateLimitedSignUpService{signUp: signUp, limiter: limiter}, nil
}

// SignUp consumes one attempt from input.Origin's budget before signing up.
func (s *RateLimitedSignUpService) SignUp(ctx context.Context, input SignUpInput) (SignUpResult, error) {
	if s == nil || s.signUp == nil || s.limiter == nil {
		return SignUpResult{}, ErrInvalidRateLimitConfig
	}
	decision, err := s.limiter.Allow(signUpOriginAction, originRateLimitKey(input.Origin))
	if err != nil {
		return SignUpResult{}, err
	}
	if !decision.Allowed {
		return SignUpResult{}, RateLimitError{RetryAfter: decision.RetryAfter}
	}
	return s.signUp.SignUp(ctx, input)
}

func (s *SignUpService) rejectDuplicateEmail(ctx context.Context, email string) error {
	user, err := s.users.FindUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("check signup email: %w", err)
	}
	if err == nil && user.ID > 0 {
		return ErrDuplicateEmail
	}
	return nil
}

func (s *SignUpService) rejectDuplicateUsername(ctx context.Context, username string) error {
	user, err := s.users.FindUserByUsername(ctx, username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("check signup username: %w", err)
	}
	if err == nil && user.ID > 0 {
		return ErrDuplicateUsername
	}
	return nil
}

func normalizeDisplayName(raw string) (string, error) {
	displayName := strings.TrimSpace(raw)
	if utf8.RuneCountInString(displayName) > maxDisplayNameLength {
		return "", ErrInvalidDisplayName
	}
	return displayName, nil
}
