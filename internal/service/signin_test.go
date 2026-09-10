package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignInAuthenticatesEmailAndClearsFailures(t *testing.T) {
	verifiedAt := int64(100)
	users := &signinUserRepositoryStub{user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}}
	attempts := &failedAttemptStateStub{}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	service, err := NewSignInService(users, signinVerifierStub{valid: true}, sessions, attempts, true)
	if err != nil {
		t.Fatalf("NewSignInService() error = %v, want nil", err)
	}

	result, err := service.SignIn(context.Background(), SignInInput{Identifier: " USER@Example.COM ", Password: "hunter42"})
	if err != nil {
		t.Fatalf("SignIn() error = %v, want nil", err)
	}
	if result.User.ID != 42 || result.Session.UserID != 42 {
		t.Fatalf("SignIn() user/session IDs = %d/%d, want 42/42", result.User.ID, result.Session.UserID)
	}
	if attempts.cleared != "user@example.com" {
		t.Errorf("cleared identifier = %q, want normalized email", attempts.cleared)
	}
}

func TestSignInAcceptsUsername(t *testing.T) {
	verifiedAt := int64(100)
	users := &signinUserRepositoryStub{user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}}
	attempts := &failedAttemptStateStub{}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	service, err := NewSignInService(users, signinVerifierStub{valid: true}, sessions, attempts, false)
	if err != nil {
		t.Fatalf("NewSignInService() error = %v, want nil", err)
	}

	if _, err := service.SignIn(context.Background(), SignInInput{Identifier: " Alice ", Password: "hunter42"}); err != nil {
		t.Fatalf("SignIn() error = %v, want nil", err)
	}
	if attempts.cleared != "alice" {
		t.Errorf("cleared identifier = %q, want normalized username", attempts.cleared)
	}
}

func TestSignInUsesUniformNormalFailures(t *testing.T) {
	verifiedAt := int64(100)
	tests := []struct {
		name     string
		user     User
		findErr  error
		valid    bool
		input    SignInInput
		expected error
	}{
		{name: "unknown email", findErr: ErrUserNotFound, input: SignInInput{Identifier: "unknown@example.com", Password: "hunter42"}, expected: ErrInvalidCredentials},
		{name: "wrong password", user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}, input: SignInInput{Identifier: "user@example.com", Password: "hunter42"}, expected: ErrInvalidCredentials},
		{name: "malformed identifier", input: SignInInput{Identifier: "not an email address", Password: "hunter42"}, expected: ErrInvalidCredentials},
		{name: "guest account", user: User{ID: 42, IsGuest: true, PasswordHash: stringPointer("stored-hash")}, input: SignInInput{Identifier: "alice", Password: "hunter42"}, expected: ErrInvalidCredentials},
		{name: "unconfirmed after correct password", user: User{ID: 42, PasswordHash: stringPointer("stored-hash")}, valid: true, input: SignInInput{Identifier: "user@example.com", Password: "hunter42"}, expected: ErrEmailUnconfirmed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &signinUserRepositoryStub{user: test.user, findErr: test.findErr}
			attempts := &failedAttemptStateStub{}
			sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
			if err != nil {
				t.Fatalf("NewSessionService() error = %v, want nil", err)
			}
			service, err := NewSignInService(users, signinVerifierStub{valid: test.valid}, sessions, attempts, true)
			if err != nil {
				t.Fatalf("NewSignInService() error = %v, want nil", err)
			}
			_, err = service.SignIn(context.Background(), test.input)
			if !errors.Is(err, test.expected) {
				t.Fatalf("SignIn() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
			if attempts.cleared != "" {
				t.Errorf("failed SignIn() cleared identifier %q", attempts.cleared)
			}
			if strings.Contains(err.Error(), test.input.Password) {
				t.Error("SignIn() error exposes password")
			}
		})
	}
}

func TestSignInPropagatesOperationalFailures(t *testing.T) {
	verifiedAt := int64(100)
	clearErr := errors.New("clear failed")
	users := &signinUserRepositoryStub{user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}}
	attempts := &failedAttemptStateStub{err: clearErr}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	service, err := NewSignInService(users, signinVerifierStub{valid: true}, sessions, attempts, false)
	if err != nil {
		t.Fatalf("NewSignInService() error = %v, want nil", err)
	}
	if _, err := service.SignIn(context.Background(), SignInInput{Identifier: "user@example.com", Password: "hunter42"}); !errors.Is(err, clearErr) {
		t.Fatalf("SignIn() error = %v, want errors.Is(_, %v)", err, clearErr)
	}
}

type signinVerifierStub struct {
	valid bool
}

func (v signinVerifierStub) Verify(string, string) (bool, error) {
	return v.valid, nil
}

type failedAttemptStateStub struct {
	cleared string
	err     error
}

func (s *failedAttemptStateStub) Clear(_ context.Context, identifier string) error {
	if s.err != nil {
		return s.err
	}
	s.cleared = identifier
	return nil
}

type signinUserRepositoryStub struct {
	user    User
	findErr error
}

func (r *signinUserRepositoryStub) CreateUser(context.Context, User) (User, error) {
	return User{}, errors.New("not implemented")
}

func (r *signinUserRepositoryStub) FindUserByID(context.Context, int64) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *signinUserRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	if r.findErr != nil {
		return User{}, r.findErr
	}
	return r.user, nil
}

func (r *signinUserRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	if r.findErr != nil {
		return User{}, r.findErr
	}
	return r.user, nil
}

func (r *signinUserRepositoryStub) UpdateUser(context.Context, User, int64) (User, error) {
	return User{}, errors.New("not implemented")
}

func (r *signinUserRepositoryStub) DeleteUser(context.Context, int64, int64) error {
	return errors.New("not implemented")
}

func stringPointer(value string) *string {
	return &value
}
