package service

import (
	"context"
	"errors"
	"testing"
)

func TestGuestUpgradeServiceUpgradePreservesIdentity(t *testing.T) {
	users := &guestUpgradeUserRepositoryStub{user: User{
		ID:      42,
		IsGuest: true,
		Theme:   "dark",
		Locale:  "hu",
		Version: 3,
	}}
	codes := &guestUpgradeCodeRevokerStub{}
	service, err := NewGuestUpgradeService(users, guestUpgradeHasherStub{}, codes)
	if err != nil {
		t.Fatalf("NewGuestUpgradeService() error = %v, want nil", err)
	}

	updated, err := service.Upgrade(context.Background(), 42, GuestUpgradeInput{
		Email:    " User@Example.COM ",
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("Upgrade() error = %v, want nil", err)
	}
	if updated.ID != 42 || updated.IsGuest || updated.Email == nil || *updated.Email != "user@example.com" {
		t.Fatalf("updated user = %+v, want converted ID 42", updated)
	}
	if updated.PasswordHash != nil {
		t.Fatal("Upgrade() returned password hash")
	}
	if users.updated.ID != 42 || users.updated.Theme != "dark" || users.updated.Locale != "hu" || users.updated.Version != 3 {
		t.Fatalf("persisted user = %+v, want preserved identity/preferences", users.updated)
	}
	if users.updated.PasswordHash == nil || *users.updated.PasswordHash != "hashed-password" {
		t.Fatal("persisted upgraded password hash missing")
	}
	if codes.revokeCalls != 1 || codes.userID != 42 || codes.revokedAt <= 0 {
		t.Fatalf("code revocation = %d/%d/%d, want one for user 42", codes.revokeCalls, codes.userID, codes.revokedAt)
	}
}

func TestGuestUpgradeServiceRejectsInvalidChanges(t *testing.T) {
	duplicate := errors.New("duplicate lookup failed")
	tests := []struct {
		name         string
		user         User
		input        GuestUpgradeInput
		emailUser    User
		findEmailErr error
		wantErr      error
	}{
		{name: "normal account", user: User{ID: 42}, input: GuestUpgradeInput{Email: "user@example.com", Password: "hunter42"}, wantErr: ErrGuestUpgradeRequiresGuest},
		{name: "invalid email", user: User{ID: 42, IsGuest: true}, input: GuestUpgradeInput{Email: "not-email", Password: "hunter42"}, wantErr: ErrInvalidGuestUpgrade},
		{name: "weak password", user: User{ID: 42, IsGuest: true}, input: GuestUpgradeInput{Email: "user@example.com", Password: "short"}, wantErr: ErrPasswordTooShort},
		{name: "duplicate email", user: User{ID: 42, IsGuest: true}, emailUser: User{ID: 7}, input: GuestUpgradeInput{Email: "user@example.com", Password: "hunter42"}, wantErr: ErrDuplicateEmail},
		{name: "email lookup failure", user: User{ID: 42, IsGuest: true}, findEmailErr: duplicate, input: GuestUpgradeInput{Email: "user@example.com", Password: "hunter42"}, wantErr: duplicate},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &guestUpgradeUserRepositoryStub{user: test.user, emailUser: test.emailUser, findEmailErr: test.findEmailErr}
			codes := &guestUpgradeCodeRevokerStub{}
			service, err := NewGuestUpgradeService(users, guestUpgradeHasherStub{}, codes)
			if err != nil {
				t.Fatalf("NewGuestUpgradeService() error = %v, want nil", err)
			}
			_, err = service.Upgrade(context.Background(), 42, test.input)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Upgrade() error = %v, want errors.Is(_, %v)", err, test.wantErr)
			}
			if users.updateCalls != 0 || codes.revokeCalls != 0 {
				t.Fatalf("mutation calls = %d/%d, want 0/0", users.updateCalls, codes.revokeCalls)
			}
		})
	}
}

func TestGuestUpgradeServicePropagatesFailures(t *testing.T) {
	backendErr := errors.New("backend failed")
	users := &guestUpgradeUserRepositoryStub{user: User{ID: 42, IsGuest: true}, updateErr: backendErr}
	codes := &guestUpgradeCodeRevokerStub{}
	service, err := NewGuestUpgradeService(users, guestUpgradeHasherStub{}, codes)
	if err != nil {
		t.Fatalf("NewGuestUpgradeService() error = %v, want nil", err)
	}
	_, err = service.Upgrade(context.Background(), 42, GuestUpgradeInput{Email: "user@example.com", Password: "hunter42"})
	if !errors.Is(err, backendErr) {
		t.Fatalf("Upgrade() update error = %v, want errors.Is(_, %v)", err, backendErr)
	}

	revokeErr := errors.New("revoke failed")
	codes = &guestUpgradeCodeRevokerStub{err: revokeErr}
	service, err = NewGuestUpgradeService(&guestUpgradeUserRepositoryStub{user: User{ID: 42, IsGuest: true}}, guestUpgradeHasherStub{}, codes)
	if err != nil {
		t.Fatalf("NewGuestUpgradeService() second error = %v, want nil", err)
	}
	_, err = service.Upgrade(context.Background(), 42, GuestUpgradeInput{Email: "user@example.com", Password: "hunter42"})
	if !errors.Is(err, revokeErr) {
		t.Fatalf("Upgrade() revoke error = %v, want errors.Is(_, %v)", err, revokeErr)
	}

	hashErr := errors.New("hash failed")
	users = &guestUpgradeUserRepositoryStub{user: User{ID: 42, IsGuest: true}}
	service, err = NewGuestUpgradeService(users, guestUpgradeHasherStub{err: hashErr}, &guestUpgradeCodeRevokerStub{})
	if err != nil {
		t.Fatalf("NewGuestUpgradeService() third error = %v, want nil", err)
	}
	_, err = service.Upgrade(context.Background(), 42, GuestUpgradeInput{Email: "user@example.com", Password: "hunter42"})
	if !errors.Is(err, hashErr) {
		t.Fatalf("Upgrade() hash error = %v, want errors.Is(_, %v)", err, hashErr)
	}
}

type guestUpgradeHasherStub struct {
	err error
}

func (h guestUpgradeHasherStub) Hash(string) (string, error) {
	if h.err != nil {
		return "", h.err
	}
	return "hashed-password", nil
}

type guestUpgradeUserRepositoryStub struct {
	user         User
	emailUser    User
	findEmailErr error
	updated      User
	updateErr    error
	updateCalls  int
}

func (r *guestUpgradeUserRepositoryStub) CreateUser(context.Context, User) (User, error) {
	return User{}, nil
}

func (r *guestUpgradeUserRepositoryStub) FindUserByID(context.Context, int64) (User, error) {
	if r.user.ID == 0 {
		return User{}, ErrUserNotFound
	}
	return r.user, nil
}

func (r *guestUpgradeUserRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	if r.findEmailErr != nil {
		return User{}, r.findEmailErr
	}
	if r.emailUser.ID == 0 {
		return User{}, ErrUserNotFound
	}
	return r.emailUser, nil
}

func (r *guestUpgradeUserRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *guestUpgradeUserRepositoryStub) UpdateUser(_ context.Context, user User, _ int64) (User, error) {
	r.updateCalls++
	if r.updateErr != nil {
		return User{}, r.updateErr
	}
	r.updated = user
	return user, nil
}

func (r *guestUpgradeUserRepositoryStub) DeleteUser(context.Context, int64, int64) error {
	return ErrUserNotFound
}

type guestUpgradeCodeRevokerStub struct {
	err         error
	revokeCalls int
	userID      int64
	revokedAt   int64
}

func (r *guestUpgradeCodeRevokerStub) RevokeGuestClaimCode(_ context.Context, userID, revokedAt int64) error {
	r.revokeCalls++
	r.userID = userID
	r.revokedAt = revokedAt
	return r.err
}
