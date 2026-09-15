package service

import (
	"context"
	"errors"
	"testing"
)

func TestPasswordSettingsServiceUpdate(t *testing.T) {
	tests := []struct {
		name       string
		existing   User
		input      PasswordSettingsInput
		verify     func(string, string) (bool, error)
		wantErr    error
		wantWrites int
	}{
		{
			name:       "sets first password for external-only account",
			existing:   User{ID: 7, PasswordHash: nil, Version: 1},
			input:      PasswordSettingsInput{NewPassword: "correct horse battery"},
			wantWrites: 1,
		},
		{
			name:       "changes password with valid current password",
			existing:   User{ID: 7, PasswordHash: strPtr("stored-hash"), Version: 2},
			input:      PasswordSettingsInput{CurrentPassword: "old-password", NewPassword: "correct horse battery"},
			verify:     verifyCurrentOnly,
			wantWrites: 1,
		},
		{
			name:     "requires current password when one exists",
			existing: User{ID: 7, PasswordHash: strPtr("stored-hash"), Version: 2},
			input:    PasswordSettingsInput{NewPassword: "correct horse battery"},
			wantErr:  ErrCurrentPasswordRequired,
		},
		{
			name:     "rejects wrong current password",
			existing: User{ID: 7, PasswordHash: strPtr("stored-hash"), Version: 2},
			input:    PasswordSettingsInput{CurrentPassword: "wrong", NewPassword: "correct horse battery"},
			verify:   neverVerify,
			wantErr:  ErrCurrentPasswordMismatch,
		},
		{
			name:     "rejects weak new password",
			existing: User{ID: 7, PasswordHash: nil, Version: 1},
			input:    PasswordSettingsInput{NewPassword: "short"},
			wantErr:  ErrPasswordTooShort,
		},
		{
			name:       "skips write when new password matches current",
			existing:   User{ID: 7, PasswordHash: strPtr("stored-hash"), Version: 2},
			input:      PasswordSettingsInput{CurrentPassword: "current", NewPassword: "current-password-value"},
			verify:     alwaysVerify,
			wantWrites: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := test.verify
			if verifier == nil {
				verifier = neverVerify
			}
			users := &settingsUserRepositoryStub{user: test.existing}
			service, err := NewPasswordSettingsService(users, &settingsHasherStub{}, passwordVerifierStub{verify: verifier})
			if err != nil {
				t.Fatalf("NewPasswordSettingsService() error = %v, want nil", err)
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
			if updated.PasswordHash != nil {
				t.Errorf("returned user exposes password hash")
			}
		})
	}
}

func TestPasswordSettingsServiceRejectsInvalidInput(t *testing.T) {
	users := &settingsUserRepositoryStub{user: User{ID: 7, Version: 1}}
	service, err := NewPasswordSettingsService(users, &settingsHasherStub{}, passwordVerifierStub{verify: alwaysVerify})
	if err != nil {
		t.Fatalf("NewPasswordSettingsService() error = %v", err)
	}
	weak := PasswordSettingsInput{NewPassword: "short"}
	if _, err := service.Update(context.Background(), 0, PasswordSettingsInput{NewPassword: "correct horse battery"}); !errors.Is(err, ErrInvalidUserID) {
		t.Fatalf("Update() error = %v, want ErrInvalidUserID", err)
	}
	if _, err := NewPasswordSettingsService(nil, &settingsHasherStub{}, passwordVerifierStub{verify: alwaysVerify}); !errors.Is(err, ErrNilUserRepository) {
		t.Fatalf("NewPasswordSettingsService(nil) error = %v, want ErrNilUserRepository", err)
	}
	if _, err := NewPasswordSettingsService(users, nil, passwordVerifierStub{verify: alwaysVerify}); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("NewPasswordSettingsService(nil hasher) error = %v, want ErrInvalidSettings", err)
	}
	if _, err := service.Update(context.Background(), 7, weak); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Update(weak) error = %v, want ErrPasswordTooShort", err)
	}
}

type settingsHasherStub struct{}

func (settingsHasherStub) Hash(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	return "hash:" + password, nil
}

func alwaysVerify(string, string) (bool, error) { return true, nil }
func neverVerify(string, string) (bool, error)  { return false, nil }

func verifyCurrentOnly(password, _ string) (bool, error) {
	return password == "old-password", nil
}

type passwordVerifierStub struct {
	verify func(string, string) (bool, error)
}

func (v passwordVerifierStub) Verify(password, hash string) (bool, error) {
	return v.verify(password, hash)
}
