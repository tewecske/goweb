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

// GuestUpgradeService converts a guest in place without changing its ID.
type GuestUpgradeService struct {
	users  UserRepository
	hasher PasswordHashProvider
	codes  GuestClaimCodeRevoker
}

// NewGuestUpgradeService constructs guest upgrade with explicit dependencies.
func NewGuestUpgradeService(
	users UserRepository,
	hasher PasswordHashProvider,
	codes GuestClaimCodeRevoker,
) (*GuestUpgradeService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	if hasher == nil {
		return nil, errors.New("service: nil password hash provider")
	}
	if codes == nil {
		return nil, ErrNilGuestUpgradeDependency
	}
	return &GuestUpgradeService{users: users, hasher: hasher, codes: codes}, nil
}

// Upgrade validates and atomically applies the guest's first credentials from
// the use-case perspective. Code revocation happens first so a failed account
// update cannot leave a converted account transferable by its old code.
func (s *GuestUpgradeService) Upgrade(ctx context.Context, userID int64, input GuestUpgradeInput) (User, error) {
	if s == nil || s.users == nil || s.hasher == nil || s.codes == nil {
		return User{}, ErrNilGuestUpgradeDependency
	}
	if ctx == nil {
		return User{}, errors.New("service: nil guest upgrade context")
	}
	if userID <= 0 {
		return User{}, ErrInvalidUserID
	}
	email, err := NormalizeEmail(input.Email)
	if err != nil || email == "" {
		return User{}, errors.Join(ErrInvalidGuestUpgrade, ErrInvalidEmail)
	}
	if err := ValidatePassword(input.Password); err != nil {
		return User{}, fmt.Errorf("validate guest upgrade password: %w", err)
	}

	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("find guest for upgrade: %w", err)
	}
	if user.ID != userID || !user.IsGuest {
		return User{}, ErrGuestUpgradeRequiresGuest
	}
	if err := s.rejectDuplicateEmail(ctx, email); err != nil {
		return User{}, err
	}
	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("hash guest upgrade password: %w", err)
	}
	if err := s.codes.RevokeGuestClaimCode(ctx, userID, time.Now().Unix()); err != nil {
		return User{}, fmt.Errorf("revoke guest claim code: %w", err)
	}

	user.Email = &email
	user.PasswordHash = &passwordHash
	user.IsGuest = false
	user.EmailVerifiedAt = nil
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		return User{}, fmt.Errorf("update upgraded user: %w", err)
	}
	if updated.ID != userID || updated.IsGuest || updated.Email == nil || updated.PasswordHash == nil {
		return User{}, ErrInvalidUpgradedUser
	}
	updated.PasswordHash = nil
	return updated, nil
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
