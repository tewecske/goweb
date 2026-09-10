package service

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// PasswordResetConsumer replaces passwords and revokes existing sessions.
type PasswordResetConsumer struct {
	users    UserRepository
	tokens   PasswordResetTokenRepository
	hasher   PasswordHashProvider
	sessions *SessionService
	now      func() time.Time
}

// NewPasswordResetConsumer constructs reset redemption with explicit account,
// token, hashing, and session dependencies.
func NewPasswordResetConsumer(
	users UserRepository,
	tokens PasswordResetTokenRepository,
	hasher PasswordHashProvider,
	sessions *SessionService,
) (*PasswordResetConsumer, error) {
	if users == nil || tokens == nil || hasher == nil || sessions == nil {
		return nil, ErrInvalidPasswordResetConfig
	}
	return &PasswordResetConsumer{
		users:    users,
		tokens:   tokens,
		hasher:   hasher,
		sessions: sessions,
		now:      time.Now,
	}, nil
}

// Redeem consumes one reset link, replaces the password, and ends every
// existing session for its account.
func (s *PasswordResetConsumer) Redeem(ctx context.Context, rawToken, newPassword string) error {
	if s == nil || s.users == nil || s.tokens == nil || s.hasher == nil || s.sessions == nil || s.now == nil {
		return ErrInvalidPasswordResetConfig
	}
	if ctx == nil {
		return errors.New("service: nil password reset context")
	}
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	passwordHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash password reset: %w", err)
	}
	token, err := normalizePasswordResetToken(rawToken)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	reset, err := s.tokens.ConsumePasswordResetToken(ctx, token, now)
	if err != nil {
		if errors.Is(err, ErrPasswordResetTokenNotFound) {
			return ErrInvalidPasswordResetToken
		}
		return fmt.Errorf("consume password reset token: %w", err)
	}
	if reset.UserID <= 0 || reset.ExpiresAt <= now || reset.ConsumedAt != nil ||
		len(reset.Token) != maxPasswordResetTokenLength ||
		subtle.ConstantTimeCompare([]byte(reset.Token), []byte(token)) != 1 {
		return ErrInvalidPasswordResetToken
	}

	user, err := s.users.FindUserByID(ctx, reset.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrInvalidPasswordResetToken
		}
		return fmt.Errorf("find password reset user: %w", err)
	}
	if user.ID != reset.UserID || user.IsGuest || user.Email == nil {
		return ErrInvalidPasswordResetToken
	}
	user.PasswordHash = &passwordHash
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrInvalidPasswordResetToken
		}
		return fmt.Errorf("replace password: %w", err)
	}
	if updated.ID != reset.UserID {
		return ErrInvalidPasswordResetToken
	}
	if err := s.sessions.RevokeUser(ctx, reset.UserID); err != nil {
		return fmt.Errorf("revoke password reset sessions: %w", err)
	}
	return nil
}

func normalizePasswordResetToken(raw string) (string, error) {
	if len(raw) != maxPasswordResetTokenLength {
		return "", ErrInvalidPasswordResetToken
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return "", ErrInvalidPasswordResetToken
	}
	return raw, nil
}
