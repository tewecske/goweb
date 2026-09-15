package service

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestProfileSettingsServiceUpdate(t *testing.T) {
	tests := []struct {
		name        string
		input       ProfileSettingsInput
		existing    User
		lookupUser  User
		wantErr     error
		wantUser    *string
		wantDisplay *string
		wantWrites  int
	}{
		{
			name:        "sets normalized username and display name",
			input:       ProfileSettingsInput{Username: "  Alice_42 ", DisplayName: "  Alice  "},
			existing:    User{ID: 7, Username: nil, DisplayName: nil, Version: 3},
			wantUser:    strPtr("alice_42"),
			wantDisplay: strPtr("Alice"),
			wantWrites:  1,
		},
		{
			name:        "clears optional fields with empty values",
			input:       ProfileSettingsInput{},
			existing:    User{ID: 7, Username: strPtr("alice"), DisplayName: strPtr("Alice"), Version: 4},
			wantUser:    nil,
			wantDisplay: nil,
			wantWrites:  1,
		},
		{
			name:       "skips duplicate username check for unchanged value",
			input:      ProfileSettingsInput{Username: "alice"},
			existing:   User{ID: 7, Username: strPtr("alice"), DisplayName: strPtr("Alice"), Version: 4},
			wantUser:   strPtr("alice"),
			wantWrites: 1,
		},
		{
			name:     "rejects malformed username",
			input:    ProfileSettingsInput{Username: "bad user"},
			existing: User{ID: 7, Version: 1},
			wantErr:  ErrInvalidUsername,
		},
		{
			name:     "rejects oversized display name",
			input:    ProfileSettingsInput{DisplayName: strings.Repeat("a", maxDisplayNameLength+1)},
			existing: User{ID: 7, Version: 1},
			wantErr:  ErrInvalidDisplayName,
		},
		{
			name:       "rejects username held by another account",
			input:      ProfileSettingsInput{Username: "taken"},
			existing:   User{ID: 7, Version: 1},
			lookupUser: User{ID: 8, Username: strPtr("taken")},
			wantErr:    ErrUsernameUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &settingsUserRepositoryStub{user: test.existing, lookupUser: test.lookupUser}
			service, err := NewProfileSettingsService(users)
			if err != nil {
				t.Fatalf("NewProfileSettingsService() error = %v, want nil", err)
			}
			updated, err := service.Update(context.Background(), test.existing.ID, test.input)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, test.wantErr)
			}
			if test.wantErr != nil {
				return
			}
			if users.updateCalls != test.wantWrites {
				t.Fatalf("UpdateUser() calls = %d, want %d", users.updateCalls, test.wantWrites)
			}
			if !sameOptionalString(updated.Username, optionalValue(test.wantUser)) {
				t.Errorf("updated username = %v, want %v", updated.Username, test.wantUser)
			}
			if !sameOptionalString(updated.DisplayName, optionalValue(test.wantDisplay)) {
				t.Errorf("updated display name = %v, want %v", updated.DisplayName, test.wantDisplay)
			}
			if updated.PasswordHash != nil {
				t.Errorf("updated user exposes password hash")
			}
		})
	}
}

func TestProfileSettingsServiceRejectsInvalidInput(t *testing.T) {
	users := &settingsUserRepositoryStub{user: User{ID: 7, Version: 1}}
	service, err := NewProfileSettingsService(users)
	if err != nil {
		t.Fatalf("NewProfileSettingsService() error = %v", err)
	}
	if _, err := service.Update(context.Background(), 0, ProfileSettingsInput{}); !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("Update() error = %v, want ErrInvalidUserID", err)
	}
	if _, err := NewProfileSettingsService(nil); !errors.Is(err, ErrNilUserRepository) {
		t.Fatalf("NewProfileSettingsService(nil) error = %v, want ErrNilUserRepository", err)
	}
}

func TestProfileSettingsServicePropagatesWriteFailure(t *testing.T) {
	writeErr := errors.New("write failed")
	users := &settingsUserRepositoryStub{user: User{ID: 7, Username: strPtr("old"), Version: 2}, updateErr: writeErr}
	service, err := NewProfileSettingsService(users)
	if err != nil {
		t.Fatalf("NewProfileSettingsService() error = %v", err)
	}
	if _, err := service.Update(context.Background(), 7, ProfileSettingsInput{Username: "new"}); !errors.Is(err, writeErr) {
		t.Fatalf("Update() error = %v, want errors.Is(_, %v)", err, writeErr)
	}
}

func TestLocaleSettingsServiceUpdate(t *testing.T) {
	users := &settingsUserRepositoryStub{user: User{ID: 7, Locale: "en", Version: 1}}
	service, err := NewLocaleSettingsService(users)
	if err != nil {
		t.Fatalf("NewLocaleSettingsService() error = %v", err)
	}
	updated, err := service.Update(context.Background(), 7, "  HU ")
	if err != nil {
		t.Fatalf("Update() error = %v, want nil", err)
	}
	if updated.Locale != "hu" {
		t.Fatalf("updated locale = %q, want %q", updated.Locale, "hu")
	}
	if users.updateCalls != 1 {
		t.Fatalf("UpdateUser() calls = %d, want 1", users.updateCalls)
	}
}

func TestLocaleSettingsServiceRejectsUnsupportedLanguage(t *testing.T) {
	users := &settingsUserRepositoryStub{user: User{ID: 7, Locale: "en", Version: 1}}
	service, err := NewLocaleSettingsService(users)
	if err != nil {
		t.Fatalf("NewLocaleSettingsService() error = %v", err)
	}
	for _, code := range []string{"", "de", "fr", "../en", "en-US"} {
		if _, err := service.Update(context.Background(), 7, code); !errors.Is(err, ErrInvalidLocale) {
			t.Fatalf("Update(%q) error = %v, want ErrInvalidLocale", code, err)
		}
	}
	if users.updateCalls != 0 {
		t.Fatalf("UpdateUser() calls = %d, want 0", users.updateCalls)
	}
}

func TestLocaleSettingsServiceUnchangedSkipsWrite(t *testing.T) {
	users := &settingsUserRepositoryStub{user: User{ID: 7, Locale: "hu", Version: 1}}
	service, err := NewLocaleSettingsService(users)
	if err != nil {
		t.Fatalf("NewLocaleSettingsService() error = %v", err)
	}
	if _, err := service.Update(context.Background(), 7, "hu"); err != nil {
		t.Fatalf("Update() error = %v, want nil", err)
	}
	if users.updateCalls != 0 {
		t.Fatalf("UpdateUser() calls = %d, want 0 for unchanged locale", users.updateCalls)
	}
}

type settingsUserRepositoryStub struct {
	user        User
	lookupUser  User
	findErr     error
	updateErr   error
	updateCalls int
}

func (r *settingsUserRepositoryStub) CreateUser(context.Context, User) (User, error) {
	return User{}, nil
}

func (r *settingsUserRepositoryStub) FindUserByID(context.Context, int64) (User, error) {
	if r.findErr != nil {
		return User{}, r.findErr
	}
	return r.user, nil
}

func (r *settingsUserRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *settingsUserRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	if r.lookupUser.ID <= 0 {
		return User{}, ErrUserNotFound
	}
	return r.lookupUser, nil
}

func (r *settingsUserRepositoryStub) UpdateUser(_ context.Context, user User, _ int64) (User, error) {
	r.updateCalls++
	if r.updateErr != nil {
		return User{}, r.updateErr
	}
	return user, nil
}

func (r *settingsUserRepositoryStub) DeleteUser(context.Context, int64, int64) error {
	return ErrUserNotFound
}

func strPtr(value string) *string { return &value }

func optionalValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
