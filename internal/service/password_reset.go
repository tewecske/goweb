package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultPasswordResetLifetime is used by application wiring when no
	// deployment-specific lifetime is configured.
	DefaultPasswordResetLifetime = time.Hour
	passwordResetTokenBytes      = 32
	maxPasswordResetTokenLength  = passwordResetTokenBytes * 2
	passwordResetPath            = "/reset-password"
	passwordResetRequestAction   = "password-reset.request"
)

var (
	// ErrInvalidPasswordResetConfig identifies unusable reset settings.
	ErrInvalidPasswordResetConfig = errors.New("service: invalid password reset config")
	// ErrInvalidPasswordResetToken is the uniform failure for unusable links.
	ErrInvalidPasswordResetToken = errors.New("service: invalid password reset token")
	// ErrPasswordResetTokenNotFound identifies a token that is not active.
	ErrPasswordResetTokenNotFound = errors.New("service: password reset token not found")
	// ErrPasswordResetTokenGeneration identifies unavailable secure randomness.
	ErrPasswordResetTokenGeneration = errors.New("service: password reset token generation failed")
)

// PasswordResetToken is the persistence model for one reset link. Token is a
// bearer credential and must never appear in logs or diagnostics.
type PasswordResetToken struct {
	UserID     int64
	Token      string
	CreatedAt  int64
	ExpiresAt  int64
	ConsumedAt *int64
}

// PasswordResetTokenRepository stores and atomically consumes reset tokens.
// Consume must return only an active, unexpired token.
type PasswordResetTokenRepository interface {
	CreatePasswordResetToken(context.Context, PasswordResetToken) error
	ConsumePasswordResetToken(context.Context, string, int64) (PasswordResetToken, error)
}

// PasswordResetService handles public password-reset requests without account
// enumeration.
type PasswordResetService struct {
	users     UserRepository
	tokens    PasswordResetTokenRepository
	mailer    MailSender
	limiter   *RateLimiter
	publicURL url.URL
	lifetime  time.Duration
	now       func() time.Time
}

// NewPasswordResetService constructs password-reset issuance with explicit
// account, token, delivery, rate-limit, URL, and lifetime dependencies.
func NewPasswordResetService(
	users UserRepository,
	tokens PasswordResetTokenRepository,
	mailer MailSender,
	limiter *RateLimiter,
	publicURL url.URL,
	lifetime time.Duration,
) (*PasswordResetService, error) {
	if users == nil || tokens == nil || mailer == nil || limiter == nil {
		return nil, ErrInvalidPasswordResetConfig
	}
	if publicURL.Scheme != "http" && publicURL.Scheme != "https" {
		return nil, ErrInvalidPasswordResetConfig
	}
	if publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return nil, ErrInvalidPasswordResetConfig
	}
	if lifetime < time.Second {
		return nil, ErrInvalidPasswordResetConfig
	}
	return &PasswordResetService{
		users:     users,
		tokens:    tokens,
		mailer:    mailer,
		limiter:   limiter,
		publicURL: publicURL,
		lifetime:  lifetime,
		now:       time.Now,
	}, nil
}

// Request accepts a reset request without revealing account existence. It
// sends only for an existing password-backed non-guest account.
func (s *PasswordResetService) Request(ctx context.Context, rawEmail string) error {
	if s == nil || s.users == nil || s.tokens == nil || s.mailer == nil || s.limiter == nil || s.now == nil {
		return ErrInvalidPasswordResetConfig
	}
	if ctx == nil {
		return errors.New("service: nil password reset context")
	}
	email, err := NormalizeEmail(rawEmail)
	if err != nil || email == "" {
		return nil
	}
	decision, err := s.limiter.Allow(passwordResetRequestAction, email)
	if err != nil {
		return fmt.Errorf("allow password reset: %w", err)
	}
	if !decision.Allowed {
		return RateLimitError{RetryAfter: decision.RetryAfter}
	}

	user, err := s.users.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("find password reset user: %w", err)
	}
	if user.ID <= 0 || user.IsGuest || user.Email == nil || user.PasswordHash == nil {
		return nil
	}
	accountEmail, err := NormalizeEmail(*user.Email)
	if err != nil || accountEmail == "" {
		return nil
	}

	createdAt := s.now().Unix()
	expiresAt := createdAt + int64(s.lifetime/time.Second)
	if expiresAt <= createdAt {
		return ErrInvalidPasswordResetConfig
	}
	token, err := newPasswordResetToken()
	if err != nil {
		return err
	}
	reset := PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	if err := s.tokens.CreatePasswordResetToken(ctx, reset); err != nil {
		return fmt.Errorf("create password reset token: %w", err)
	}

	message := Mail{
		To:       accountEmail,
		Subject:  "Reset your password",
		TextBody: "Open this link to reset your password:\n\n" + s.resetLink(token) + "\n\nThis link can be used once.",
	}
	if err := s.mailer.Send(ctx, message); err != nil {
		return fmt.Errorf("send password reset mail: %w", err)
	}
	return nil
}

func (s *PasswordResetService) resetLink(token string) string {
	resetURL := s.publicURL
	resetURL.Path = strings.TrimRight(resetURL.Path, "/") + passwordResetPath
	query := resetURL.Query()
	query.Set("token", token)
	resetURL.RawQuery = query.Encode()
	return resetURL.String()
}

func newPasswordResetToken() (string, error) {
	value := make([]byte, passwordResetTokenBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("%w: random source unavailable", ErrPasswordResetTokenGeneration)
	}
	token := hex.EncodeToString(value)
	if len(token) != maxPasswordResetTokenLength {
		return "", ErrPasswordResetTokenGeneration
	}
	return token, nil
}
