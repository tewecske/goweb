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
	// DefaultEmailConfirmationLifetime is used by application wiring when no
	// deployment-specific lifetime is configured.
	DefaultEmailConfirmationLifetime = 24 * time.Hour
	confirmationTokenBytes           = 32
	maxConfirmationTokenLength       = confirmationTokenBytes * 2
	confirmationPath                 = "/confirm-email"
)

var (
	// ErrInvalidConfirmationConfig identifies unusable confirmation settings.
	ErrInvalidConfirmationConfig = errors.New("service: invalid confirmation config")
	// ErrInvalidConfirmationUser identifies an account that cannot be confirmed.
	ErrInvalidConfirmationUser = errors.New("service: invalid confirmation user")
	// ErrConfirmationTokenGeneration identifies unavailable secure randomness.
	ErrConfirmationTokenGeneration = errors.New("service: confirmation token generation failed")
)

// EmailConfirmationToken is the persistence model for one confirmation link.
// Token is a bearer credential and must never appear in logs or diagnostics.
type EmailConfirmationToken struct {
	UserID    int64
	Token     string
	CreatedAt int64
	ExpiresAt int64
}

// EmailConfirmationTokenRepository stores newly issued confirmation tokens.
type EmailConfirmationTokenRepository interface {
	CreateEmailConfirmationToken(context.Context, EmailConfirmationToken) error
}

// EmailConfirmationService issues confirmation links for password accounts.
type EmailConfirmationService struct {
	users     UserRepository
	tokens    EmailConfirmationTokenRepository
	mailer    MailSender
	publicURL url.URL
	lifetime  time.Duration
	now       func() time.Time
}

// NewEmailConfirmationService constructs confirmation issuance with explicit
// account, token, delivery, URL, and lifetime dependencies.
func NewEmailConfirmationService(
	users UserRepository,
	tokens EmailConfirmationTokenRepository,
	mailer MailSender,
	publicURL url.URL,
	lifetime time.Duration,
) (*EmailConfirmationService, error) {
	if users == nil || tokens == nil || mailer == nil {
		return nil, ErrInvalidConfirmationConfig
	}
	if publicURL.Scheme != "http" && publicURL.Scheme != "https" {
		return nil, ErrInvalidConfirmationConfig
	}
	if publicURL.Host == "" || publicURL.User != nil || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return nil, ErrInvalidConfirmationConfig
	}
	if lifetime < time.Second {
		return nil, ErrInvalidConfirmationConfig
	}
	return &EmailConfirmationService{
		users:     users,
		tokens:    tokens,
		mailer:    mailer,
		publicURL: publicURL,
		lifetime:  lifetime,
		now:       time.Now,
	}, nil
}

// Issue creates and delivers one expiring confirmation link for userID.
// The token is returned only through the delivered message, never as a
// service result or part of an error.
func (s *EmailConfirmationService) Issue(ctx context.Context, userID int64) error {
	if s == nil || s.users == nil || s.tokens == nil || s.mailer == nil || s.now == nil {
		return ErrInvalidConfirmationConfig
	}
	if ctx == nil {
		return errors.New("service: nil confirmation context")
	}
	if userID <= 0 {
		return ErrInvalidConfirmationUser
	}

	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("find confirmation user: %w", err)
	}
	if user.ID != userID || user.IsGuest || user.Email == nil {
		return ErrInvalidConfirmationUser
	}
	email, err := NormalizeEmail(*user.Email)
	if err != nil || email == "" {
		return ErrInvalidConfirmationUser
	}

	createdAt := s.now().Unix()
	expiresAt := createdAt + int64(s.lifetime/time.Second)
	if expiresAt <= createdAt {
		return ErrInvalidConfirmationConfig
	}
	token, err := newConfirmationToken()
	if err != nil {
		return err
	}
	confirmation := EmailConfirmationToken{
		UserID:    userID,
		Token:     token,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
	if err := s.tokens.CreateEmailConfirmationToken(ctx, confirmation); err != nil {
		return fmt.Errorf("create confirmation token: %w", err)
	}

	message := Mail{
		To:       email,
		Subject:  "Confirm your email address",
		TextBody: "Open this link to confirm your email address:\n\n" + s.confirmationLink(token) + "\n\nThis link can be used once.",
	}
	if err := s.mailer.Send(ctx, message); err != nil {
		return fmt.Errorf("send confirmation mail: %w", err)
	}
	return nil
}

func (s *EmailConfirmationService) confirmationLink(token string) string {
	confirmationURL := s.publicURL
	confirmationURL.Path = strings.TrimRight(confirmationURL.Path, "/") + confirmationPath
	query := confirmationURL.Query()
	query.Set("token", token)
	confirmationURL.RawQuery = query.Encode()
	return confirmationURL.String()
}

func newConfirmationToken() (string, error) {
	value := make([]byte, confirmationTokenBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("%w: random source unavailable", ErrConfirmationTokenGeneration)
	}
	token := hex.EncodeToString(value)
	if len(token) != maxConfirmationTokenLength {
		return "", ErrConfirmationTokenGeneration
	}
	return token, nil
}
