package service

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidGuestUpgrade identifies missing or malformed upgrade input.
	ErrInvalidGuestUpgrade = errors.New("service: invalid guest upgrade")
	// ErrGuestUpgradeRequiresGuest identifies an account that cannot be upgraded.
	ErrGuestUpgradeRequiresGuest = errors.New("service: account is not guest")
	// ErrNilGuestUpgradeDependency identifies missing upgrade wiring.
	ErrNilGuestUpgradeDependency = errors.New("service: nil guest upgrade dependency")
	// ErrInvalidUpgradedUser identifies persistence that did not return the
	// converted account.
	ErrInvalidUpgradedUser = errors.New("service: invalid upgraded user")
)

// GuestUpgradeInput contains the credentials added to a guest account.
type GuestUpgradeInput struct {
	Email    string
	Password string
}

// GuestUpgradeResult is the converted account and the new session that
// replaces every guest session.
type GuestUpgradeResult struct {
	User    User
	Session Session
}

// GuestUpgradeService converts a guest in place without changing its ID.
type GuestUpgradeService struct {
	users    UserRepository
	hasher   PasswordHashProvider
	codes    GuestClaimCodeRevoker
	sessions *SessionService
}

// NewGuestUpgradeService constructs guest upgrade with explicit dependencies.
func NewGuestUpgradeService(
	users UserRepository,
	hasher PasswordHashProvider,
	codes GuestClaimCodeRevoker,
	sessions *SessionService,
) (*GuestUpgradeService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if hasher == nil {
		return nil, errors.New("service: nil password hash provider")
	}
	if codes == nil || sessions == nil {
		return nil, ErrNilGuestUpgradeDependency
	}
	return &GuestUpgradeService{users: users, hasher: hasher, codes: codes, sessions: sessions}, nil
}

// Upgrade validates and atomically applies the guest's first credentials from
// the use-case perspective. Code revocation happens first so a failed account
// update cannot leave a converted account transferable by its old code.
// Every guest session, including any opened on another device with a
// transfer code, ends when the account gains credentials; the caller gets a
// fresh session.
func (s *GuestUpgradeService) Upgrade(ctx context.Context, userID int64, input GuestUpgradeInput) (GuestUpgradeResult, error) {
	if s == nil || s.users == nil || s.hasher == nil || s.codes == nil || s.sessions == nil {
		return GuestUpgradeResult{}, ErrNilGuestUpgradeDependency
	}
	if ctx == nil {
		return GuestUpgradeResult{}, errors.New("service: nil guest upgrade context")
	}
	if userID <= 0 {
		return GuestUpgradeResult{}, ErrInvalidUserID
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil || email == "" {
		return GuestUpgradeResult{}, errors.Join(ErrInvalidGuestUpgrade, ErrInvalidEmail)
	}
	if err := ValidatePassword(input.Password); err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("validate guest upgrade password: %w", err)
	}

	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("find guest for upgrade: %w", err)
	}
	if user.ID != userID || !user.IsGuest {
		return GuestUpgradeResult{}, ErrGuestUpgradeRequiresGuest
	}
	if err := s.rejectDuplicateEmail(ctx, email); err != nil {
		return GuestUpgradeResult{}, err
	}
	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("hash guest upgrade password: %w", err)
	}
	if err := s.codes.RevokeGuestClaimCode(ctx, userID, time.Now().Unix()); err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("revoke guest claim code: %w", err)
	}

	user.Email = &email
	user.PasswordHash = &passwordHash
	user.IsGuest = false
	user.EmailVerifiedAt = nil
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("update upgraded user: %w", err)
	}
	if updated.ID != userID || updated.IsGuest || updated.Email == nil || updated.PasswordHash == nil {
		return GuestUpgradeResult{}, ErrInvalidUpgradedUser
	}
	updated.PasswordHash = nil
	if err := s.sessions.RevokeUser(ctx, userID); err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("revoke guest sessions after upgrade: %w", err)
	}
	session, err := s.sessions.Create(ctx, userID)
	if err != nil {
		return GuestUpgradeResult{}, fmt.Errorf("create session after guest upgrade: %w", err)
	}
	return GuestUpgradeResult{User: updated, Session: session}, nil
}

func (s *GuestUpgradeService) rejectDuplicateEmail(ctx context.Context, email string) error {
	existing, err := s.users.FindUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return fmt.Errorf("check guest upgrade email: %w", err)
	}
	if err == nil && existing.ID > 0 {
		return ErrDuplicateEmail
	}
	return nil
}
