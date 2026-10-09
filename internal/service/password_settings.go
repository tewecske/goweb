package service

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrCurrentPasswordRequired identifies a password change without the current password.
	ErrCurrentPasswordRequired = errors.New("service: current password required")
	// ErrCurrentPasswordMismatch identifies an incorrect current password.
	ErrCurrentPasswordMismatch = errors.New("service: current password mismatch")
	// ErrRecentSignInRequired identifies a first password set from a session
	// that was not signed in recently.
	ErrRecentSignInRequired = errors.New("service: recent sign-in required")
)

// RecentSignInWindow is how recently an account without a password must have
// signed in before it may set its first password. Such accounts have no
// current password to confirm, so a fresh sign-in stands in for it and a
// stolen older session cannot add a permanent credential.
const RecentSignInWindow = 10 * time.Minute

// PasswordSettingsInput contains a password change request from the owner.
// CurrentPassword is required only when the account already has a password;
// otherwise SessionID must identify a session signed in within
// RecentSignInWindow.
type PasswordSettingsInput struct {
	CurrentPassword string
	NewPassword     string
	SessionID       string
}

// PasswordSettingsResult is the account after a password change and, when the
// password changed, the replacement session for the requesting browser.
type PasswordSettingsResult struct {
	User    User
	Session Session
}

// PasswordSettingsService manages an account's own password. It supports the
// first password for externally authenticated accounts and current-password
// protected changes for existing passwords.
type PasswordSettingsService struct {
	users    UserRepository
	hasher   PasswordHashProvider
	verifier PasswordVerifier
	sessions *SessionService
}

// NewPasswordSettingsService constructs password settings with explicit account,
// hashing, verification, and session dependencies.
func NewPasswordSettingsService(users UserRepository, hasher PasswordHashProvider, verifier PasswordVerifier, sessions *SessionService) (*PasswordSettingsService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if hasher == nil || verifier == nil || sessions == nil {
		return nil, ErrInvalidSettings
	}
	return &PasswordSettingsService{users: users, hasher: hasher, verifier: verifier, sessions: sessions}, nil
}

// Update validates the request, verifies the current password when one exists,
// and persists the new password using the account's optimistic-lock revision.
// A changed password ends every existing session for the account, including
// any held by someone who stole one, and returns a new session for the caller.
func (s *PasswordSettingsService) Update(ctx context.Context, userID int64, input PasswordSettingsInput) (PasswordSettingsResult, error) {
	if s == nil || s.users == nil || s.hasher == nil || s.verifier == nil || s.sessions == nil {
		return PasswordSettingsResult{}, ErrInvalidSettings
	}
	if ctx == nil {
		return PasswordSettingsResult{}, errors.New("service: nil password settings context")
	}
	if userID <= 0 {
		return PasswordSettingsResult{}, ErrInvalidUserID
	}
	if err := ValidatePassword(input.NewPassword); err != nil {
		return PasswordSettingsResult{}, fmt.Errorf("validate settings password: %w", err)
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return PasswordSettingsResult{}, fmt.Errorf("find password settings user: %w", err)
	}
	if user.ID != userID {
		return PasswordSettingsResult{}, ErrUserNotFound
	}
	if err := s.verifyCurrent(ctx, user, input); err != nil {
		return PasswordSettingsResult{}, err
	}
	unchanged, err := s.matchesCurrent(user, input.NewPassword)
	if err != nil {
		return PasswordSettingsResult{}, err
	}
	if unchanged {
		return PasswordSettingsResult{User: publicUser(user)}, nil
	}
	passwordHash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return PasswordSettingsResult{}, fmt.Errorf("hash settings password: %w", err)
	}
	user.PasswordHash = &passwordHash
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return PasswordSettingsResult{}, ErrRecordNotFound
		}
		if errors.Is(err, ErrOptimisticLockConflict) {
			return PasswordSettingsResult{}, ErrOptimisticLockConflict
		}
		return PasswordSettingsResult{}, fmt.Errorf("update settings password: %w", err)
	}
	if err := s.sessions.RevokeUser(ctx, userID); err != nil {
		return PasswordSettingsResult{}, fmt.Errorf("revoke sessions after password change: %w", err)
	}
	session, err := s.sessions.Create(ctx, userID)
	if err != nil {
		return PasswordSettingsResult{}, fmt.Errorf("create session after password change: %w", err)
	}
	return PasswordSettingsResult{User: publicUser(updated), Session: session}, nil
}

func (s *PasswordSettingsService) verifyCurrent(ctx context.Context, user User, input PasswordSettingsInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if user.PasswordHash == nil {
		session, err := s.sessions.Lookup(ctx, input.SessionID)
		if err != nil || session.UserID != user.ID || time.Since(time.Unix(session.CreatedAt, 0)) > RecentSignInWindow {
			return ErrRecentSignInRequired
		}
		return nil
	}
	if input.CurrentPassword == "" {
		return ErrCurrentPasswordRequired
	}
	valid, err := s.verifier.Verify(input.CurrentPassword, *user.PasswordHash)
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
