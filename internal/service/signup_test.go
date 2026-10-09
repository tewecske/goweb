package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSignUpCreatesUserAndSession(t *testing.T) {
	for _, confirmationRequired := range []bool{false, true} {
		t.Run(fmt.Sprintf("confirmation required %t", confirmationRequired), func(t *testing.T) {
			testSignUpCreatesUser(t, confirmationRequired)
		})
	}
}

func testSignUpCreatesUser(t *testing.T, confirmationRequired bool) {
	users := &signupUserRepositoryStub{}
	sessionStore := &sessionRepositoryStub{}
	sessions, err := NewSessionService(sessionStore, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	service, err := NewSignUpService(users, signupHasherStub{}, sessions, confirmationRequired)
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
	if result.User.ID != users.created.ID {
		t.Fatalf("created user ID = %d, want persisted user ID %d", result.User.ID, users.created.ID)
	}
	// An account that must confirm its email cannot sign in yet, so sign-up
	// must not hand it a session either.
	if confirmationRequired != (result.Session.ID == "" && sessionStore.created.ID == "") {
		t.Fatalf("session = %+v (stored %q) with confirmation required %t", result.Session, sessionStore.created.ID, confirmationRequired)
	}
	if !confirmationRequired && result.Session.UserID != result.User.ID {
		t.Fatalf("session user = %d, want %d", result.Session.UserID, result.User.ID)
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
	if result.User.PasswordHash != nil {
		t.Error("signup result exposes password hash")
	}
	if users.created.PasswordHash == nil || *users.created.PasswordHash != "hashed-password" {
		t.Error("stored password hash missing or unexpected")
	}
	if result.ConfirmationRequired != confirmationRequired {
		t.Errorf("ConfirmationRequired = %t, want %t", result.ConfirmationRequired, confirmationRequired)
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

func TestRateLimitedSignUpServiceLimitsEachOrigin(t *testing.T) {
	users := &signupUserRepositoryStub{}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base, err := NewSignUpService(users, signupHasherStub{}, sessions, false)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewRateLimitedSignUpService(base, limiter)
	if err != nil {
		t.Fatal(err)
	}
	signUp := func(email, origin string) error {
		_, err := service.SignUp(context.Background(), SignUpInput{Email: email, Password: "correct horse battery staple", Origin: origin})
		return err
	}
	if err := signUp("first@example.com", "2001:db8::1"); err != nil {
		t.Fatalf("first sign-up error = %v", err)
	}
	if err := signUp("second@example.com", "2001:db8::2"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second sign-up from the same /64 error = %v, want ErrRateLimited", err)
	}
	if err := signUp("third@example.com", "198.51.100.7"); err != nil {
		t.Fatalf("sign-up from another origin error = %v", err)
	}
	if users.createCalls != 2 {
		t.Fatalf("accounts created = %d, want 2 (the limited attempt must not create one)", users.createCalls)
	}
}
