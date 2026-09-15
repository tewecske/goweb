package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/tewecske/goweb/internal/locale"
)

var (
	// ErrInvalidSettings identifies missing settings wiring.
	ErrInvalidSettings = errors.New("service: invalid settings")
	// ErrUsernameUnavailable identifies a username already attached to another account.
	ErrUsernameUnavailable = errors.New("service: username unavailable")
	// ErrInvalidLocale identifies a language code outside the supported catalog.
	ErrInvalidLocale = errors.New("service: invalid locale")
)

// ProfileSettingsInput contains account profile values submitted by the owner.
// Empty values clear the optional field.
type ProfileSettingsInput struct {
	Username    string
	DisplayName string
}

// ProfileSettingsService updates an account's optional profile fields.
type ProfileSettingsService struct {
	users UserRepository
}

// NewProfileSettingsService constructs profile settings with its account port.
func NewProfileSettingsService(users UserRepository) (*ProfileSettingsService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	return &ProfileSettingsService{users: users}, nil
}

// Update validates and persists normalized username and display name using the
// caller-provided optimistic-lock revision. Supplying an unchanged value does
// not write a new revision.
func (s *ProfileSettingsService) Update(ctx context.Context, userID int64, input ProfileSettingsInput) (User, error) {
	if s == nil || s.users == nil {
		return User{}, ErrInvalidSettings
	}
	if ctx == nil {
		return User{}, errors.New("service: nil profile settings context")
	}
	if userID <= 0 {
		return User{}, ErrInvalidUserID
	}
	username, err := NormalizeUsername(input.Username)
	if err != nil {
		return User{}, fmt.Errorf("validate profile username: %w", err)
	}
	displayName, err := normalizeDisplayName(input.DisplayName)
	if err != nil {
		return User{}, err
	}

	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("find profile settings user: %w", err)
	}
	if user.ID != userID {
		return User{}, ErrUserNotFound
	}

	if username != "" && !sameOptionalString(user.Username, username) {
		if err := s.rejectDuplicateUsername(ctx, userID, username); err != nil {
			return User{}, err
		}
	}
	if err := applyProfileFields(&user, username, displayName); err != nil {
		return User{}, err
	}
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return User{}, ErrRecordNotFound
		}
		if errors.Is(err, ErrOptimisticLockConflict) {
			return User{}, ErrOptimisticLockConflict
		}
		return User{}, fmt.Errorf("update profile settings: %w", err)
	}
	return publicUser(updated), nil
}

func (s *ProfileSettingsService) rejectDuplicateUsername(ctx context.Context, userID int64, username string) error {
	existing, err := s.users.FindUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("check profile username: %w", err)
	}
	if existing.ID > 0 && existing.ID != userID {
		return ErrUsernameUnavailable
	}
	return nil
}

func applyProfileFields(user *User, username, displayName string) error {
	if user == nil {
		return ErrInvalidSettings
	}
	user.Username = optionalNormalized(username)
	user.DisplayName = optionalNormalized(displayName)
	return nil
}

func optionalNormalized(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func sameOptionalString(current *string, value string) bool {
	if current == nil {
		return value == ""
	}
	return *current == value
}

func publicUser(user User) User {
	user.PasswordHash = nil
	return user
}

// LocaleSettingsService persists an account language preference. It returns the
// canonical route so callers can navigate to the equivalent localized page.
type LocaleSettingsService struct {
	users UserRepository
}

// NewLocaleSettingsService constructs locale settings with its account port.
func NewLocaleSettingsService(users UserRepository) (*LocaleSettingsService, error) {
	if users == nil {
		return nil, ErrNilUserRepository
	}
	return &LocaleSettingsService{users: users}, nil
}

// Update validates and persists the account language preference. Unsupported
// languages are rejected before any write.
func (s *LocaleSettingsService) Update(ctx context.Context, userID int64, rawLocale string) (User, error) {
	if s == nil || s.users == nil {
		return User{}, ErrInvalidSettings
	}
	if ctx == nil {
		return User{}, errors.New("service: nil locale settings context")
	}
	if userID <= 0 {
		return User{}, ErrInvalidUserID
	}
	code := strings.ToLower(strings.TrimSpace(rawLocale))
	if !validLocale(code) {
		return User{}, ErrInvalidLocale
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		return User{}, fmt.Errorf("find locale settings user: %w", err)
	}
	if user.ID != userID {
		return User{}, ErrUserNotFound
	}
	if user.Locale == code {
		return publicUser(user), nil
	}
	user.Locale = code
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return User{}, ErrRecordNotFound
		}
		if errors.Is(err, ErrOptimisticLockConflict) {
			return User{}, ErrOptimisticLockConflict
		}
		return User{}, fmt.Errorf("update locale settings: %w", err)
	}
	return publicUser(updated), nil
}

func validLocale(code string) bool {
	return locale.Supported(locale.Code(code))
}
