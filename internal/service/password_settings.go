package service

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrCurrentPasswordRequired identifies a password change without the current password.
	ErrCurrentPasswordRequired = errors.New("service: current password required")
	// ErrCurrentPasswordMismatch identifies an incorrect current password.
	ErrCurrentPasswordMismatch = errors.New("service: current password mismatch")
)

// PasswordSettingsInput contains a password change request from the owner.
// CurrentPassword is required only when the account already has a password.
type PasswordSettingsInput struct {
	CurrentPassword string
	NewPassword     string
}

// PasswordSettingsService manages an account's own password. It supports the
// first password for externally authenticated accounts and current-password
// protected changes for existing passwords.
type PasswordSettingsService struct {
	users    UserRepository
	hasher   PasswordHashProvider
	verifier PasswordVerifier
}

// NewPasswordSettingsService constructs password settings with explicit account,
// hashing, and verification dependencies.
func NewPasswordSettingsService(users UserRepository, hasher PasswordHashProvider, verifier PasswordVerifier) (*PasswordSettingsService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if hasher == nil || verifier == nil {
		return nil, ErrInvalidSettings
	}
	return &PasswordSettingsService{users: users, hasher: hasher, verifier: verifier}, nil
}

// Update validates the request, verifies the current password when one exists,
// and persists the new password using the account's optimistic-lock revision.
func (s *PasswordSettingsService) Update(ctx context.Context, userID int64, input PasswordSettingsInput) (User, error) {
	if s == nil || s.users == nil || s.hasher == nil || s.verifier == nil {
		return User{}, ErrInvalidSettings
	}
	if ctx == nil {
		return User{}, errors.New("service: nil password settings context")
	}
	if userID <= 0 {
		return User{}, ErrInvalidUserID
	}
	if err := ValidatePassword(input.NewPassword); err != nil {
		return User{}, fmt.Errorf("validate settings password: %w", err)
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("find password settings user: %w", err)
	}
	if user.ID != userID {
		return User{}, ErrUserNotFound
	}
	if err := s.verifyCurrent(ctx, user, input.CurrentPassword); err != nil {
		return User{}, err
	}
	unchanged, err := s.matchesCurrent(user, input.NewPassword)
	if err != nil {
		return User{}, err
	}
	if unchanged {
		return publicUser(user), nil
	}
	passwordHash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return User{}, fmt.Errorf("hash settings password: %w", err)
	}
	user.PasswordHash = &passwordHash
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		return User{}, fmt.Errorf("update settings password: %w", err)
	}
	return publicUser(updated), nil
}

func (s *PasswordSettingsService) verifyCurrent(ctx context.Context, user User, currentPassword string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if user.PasswordHash == nil {
		return nil
	}
	if currentPassword == "" {
		return ErrCurrentPasswordRequired
	}
	valid, err := s.verifier.Verify(currentPassword, *user.PasswordHash)
	if err != nil || !valid {
		return ErrCurrentPasswordMismatch
	}
	return nil
}

func (s *PasswordSettingsService) matchesCurrent(user User, newPassword string) (bool, error) {
	if user.PasswordHash == nil {
		return false, nil
	}
	valid, err := s.verifier.Verify(newPassword, *user.PasswordHash)
	if err != nil {
		return false, nil
	}
	return valid, nil
}
