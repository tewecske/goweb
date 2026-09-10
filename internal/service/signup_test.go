package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignUpCreatesUserAndSession(t *testing.T) {
	users := &signupUserRepositoryStub{}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	service, err := NewSignUpService(users, signupHasherStub{}, sessions, true)
	if err != nil {
		t.Fatalf("NewSignUpService() error = %v, want nil", err)
	}

	result, err := service.SignUp(context.Background(), SignUpInput{
		Email:       " User@Example.COM ",
		Password:    "correct horse battery staple",
		Username:    " Alice ",
		DisplayName: " Alice Example ",
	})
	if err != nil {
		t.Fatalf("SignUp() error = %v, want nil", err)
	}
	if result.User.ID != users.created.ID || result.Session.UserID != result.User.ID {
		t.Fatalf("created user/session IDs = %d/%d, want persisted user ID %d", result.User.ID, result.Session.UserID, users.created.ID)
	}
	if result.User.Email == nil || *result.User.Email != "user@example.com" {
		t.Errorf("created email = %v, want normalized email", result.User.Email)
	}
	if result.User.Username == nil || *result.User.Username != "alice" {
		t.Errorf("created username = %v, want normalized username", result.User.Username)
	}
	if result.User.DisplayName == nil || *result.User.DisplayName != "Alice Example" {
		t.Errorf("created display name = %v, want trimmed display name", result.User.DisplayName)
	}
	if result.User.PasswordHash == nil || *result.User.PasswordHash != "hashed-password" {
		t.Error("created password hash missing or unexpected")
	}
	if !result.ConfirmationRequired {
		t.Error("ConfirmationRequired = false, want true")
	}
}

func TestSignUpRejectsNormalizedDuplicates(t *testing.T) {
	tests := []struct {
		name             string
		existing         User
		existingEmail    bool
		existingUsername bool
		input            SignUpInput
		expected         error
	}{
		{
			name:          "email",
			existing:      User{ID: 7},
			existingEmail: true,
			input:         SignUpInput{Email: " USER@example.com ", Password: "hunter42"},
			expected:      ErrDuplicateEmail,
		},
		{
			name:             "username",
			existing:         User{ID: 8},
			existingUsername: true,
			input:            SignUpInput{Email: "new@example.com", Password: "hunter42", Username: " ALICE "},
			expected:         ErrDuplicateUsername,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &signupUserRepositoryStub{
				existing:         test.existing,
				existingEmail:    test.existingEmail,
				existingUsername: test.existingUsername,
			}
			sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
			if err != nil {
				t.Fatalf("NewSessionService() error = %v, want nil", err)
			}
			service, err := NewSignUpService(users, signupHasherStub{}, sessions, false)
			if err != nil {
				t.Fatalf("NewSignUpService() error = %v, want nil", err)
			}
			_, err = service.SignUp(context.Background(), test.input)
			if !errors.Is(err, test.expected) {
				t.Fatalf("SignUp() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
			if users.createCalls != 0 {
				t.Error("SignUp() created user after duplicate")
			}
		})
	}
}

func TestSignUpRejectsInvalidInputAndFailures(t *testing.T) {
	passwordError := errors.New("hash failed")
	createError := errors.New("create failed")
	tests := []struct {
		name      string
		input     SignUpInput
		users     *signupUserRepositoryStub
		hasher    signupHasherStub
		expected  error
		wantCalls int
	}{
		{name: "invalid email", input: SignUpInput{Email: "not-email", Password: "hunter42"}, users: &signupUserRepositoryStub{}, hasher: signupHasherStub{}, expected: ErrInvalidSignupInput},
		{name: "invalid username", input: SignUpInput{Email: "user@example.com", Password: "hunter42", Username: "user@name"}, users: &signupUserRepositoryStub{}, hasher: signupHasherStub{}, expected: ErrInvalidSignupInput},
		{name: "short password", input: SignUpInput{Email: "user@example.com", Password: "abcdefg"}, users: &signupUserRepositoryStub{}, hasher: signupHasherStub{}, expected: ErrPasswordTooShort},
		{name: "hash failure", input: SignUpInput{Email: "user@example.com", Password: "hunter42"}, users: &signupUserRepositoryStub{}, hasher: signupHasherStub{err: passwordError}, expected: passwordError},
		{name: "create failure", input: SignUpInput{Email: "user@example.com", Password: "hunter42"}, users: &signupUserRepositoryStub{createErr: createError}, hasher: signupHasherStub{}, expected: createError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
			if err != nil {
				t.Fatalf("NewSessionService() error = %v, want nil", err)
			}
			service, err := NewSignUpService(test.users, test.hasher, sessions, false)
			if err != nil {
				t.Fatalf("NewSignUpService() error = %v, want nil", err)
			}
			_, err = service.SignUp(context.Background(), test.input)
			if !errors.Is(err, test.expected) {
				t.Fatalf("SignUp() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
			if strings.Contains(err.Error(), test.input.Password) {
				t.Error("SignUp() error exposes password")
			}
		})
	}
}

type signupHasherStub struct {
	err error
}

func (h signupHasherStub) Hash(string) (string, error) {
	if h.err != nil {
		return "", h.err
	}
	return "hashed-password", nil
}

type signupUserRepositoryStub struct {
	existing         User
	existingEmail    bool
	existingUsername bool
	created          User
	createErr        error
	createCalls      int
}

func (r *signupUserRepositoryStub) CreateUser(_ context.Context, user User) (User, error) {
	r.createCalls++
	if r.createErr != nil {
		return User{}, r.createErr
	}
	r.created = user
	r.created.ID = 99
	return r.created, nil
}

func (r *signupUserRepositoryStub) FindUserByID(context.Context, int64) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *signupUserRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	if r.existingEmail {
		return r.existing, nil
	}
	return User{}, ErrUserNotFound
}

func (r *signupUserRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	if r.existingUsername {
		return r.existing, nil
	}
	return User{}, ErrUserNotFound
}

func (r *signupUserRepositoryStub) UpdateUser(context.Context, User, int64) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *signupUserRepositoryStub) DeleteUser(context.Context, int64, int64) error {
	return ErrUserNotFound
}
