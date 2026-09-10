package service

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidGuestCreation identifies an unusable guest creation request.
	ErrInvalidGuestCreation = errors.New("service: invalid guest creation")
	// ErrInvalidCreatedGuest identifies persistence that did not return a guest.
	ErrInvalidCreatedGuest = errors.New("service: invalid created guest")
)

// GuestService creates an anonymous account for an ownership-requiring write.
// Callers must invoke Create only after deciding that the operation needs an
// owner; page rendering must not call this use case.
type GuestService struct {
	users UserRepository
}

// NewGuestService constructs guest-account creation with explicit persistence.
func NewGuestService(users UserRepository) (*GuestService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	return &GuestService{users: users}, nil
}

// Create creates a credential-free guest account with safe default
// preferences. Session and username assignment belong to the guest session
// flow so account creation remains usable by ownership write services.
func (s *GuestService) Create(ctx context.Context) (User, error) {
	if s == nil || s.users == nil {
		return User{}, ErrInvalidGuestCreation
	}
	if ctx == nil {
		return User{}, errors.New("service: nil guest context")
	}

	guest := User{
		IsGuest:   true,
		Theme:     defaultUserTheme,
		Locale:    defaultUserLocale,
		CreatedAt: time.Now().Unix(),
	}
	created, err := s.users.CreateUser(ctx, guest)
	if err != nil {
		return User{}, fmt.Errorf("create guest user: %w", err)
	}
	if created.ID <= 0 || !created.IsGuest || created.Email != nil || created.PasswordHash != nil || created.EmailVerifiedAt != nil {
		return User{}, ErrInvalidCreatedGuest
	}
	created.PasswordHash = nil
	return created, nil
}
