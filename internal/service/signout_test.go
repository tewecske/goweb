package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionServiceSignOutIsIdempotent(t *testing.T) {
	repository := &signOutRepositoryStub{}
	service, err := NewSessionService(repository, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}

	for _, sessionID := range []string{"", "session-id"} {
		if err := service.SignOut(context.Background(), sessionID); err != nil {
			t.Fatalf("SignOut(%q) error = %v, want nil", sessionID, err)
		}
	}
	if repository.revokedID != "session-id" || repository.revokeCalls != 1 {
		t.Fatalf("revoke calls/id = %d/%q, want 1/session-id", repository.revokeCalls, repository.revokedID)
	}

	repository.revokeErr = ErrSessionNotFound
	if err := service.SignOut(context.Background(), "session-id"); err != nil {
		t.Fatalf("SignOut(already absent) error = %v, want nil", err)
	}
	if err := service.SignOut(context.Background(), " "); err != nil {
		t.Fatalf("SignOut(blank) error = %v, want nil", err)
	}
}

func TestSessionServiceSignOutPropagatesOperationalErrors(t *testing.T) {
	operationalErr := errors.New("revoke failed")
	repository := &signOutRepositoryStub{revokeErr: operationalErr}
	service, err := NewSessionService(repository, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	if err := service.SignOut(context.Background(), "session-id"); !errors.Is(err, operationalErr) {
		t.Fatalf("SignOut() error = %v, want errors.Is(_, %v)", err, operationalErr)
	}
}

func TestSessionServiceSignOutRejectsNilContext(t *testing.T) {
	service, err := NewSessionService(&signOutRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	if err := service.SignOut(nil, ""); err == nil {
		t.Fatal("SignOut(nil context) error = nil, want error")
	}
}

type signOutRepositoryStub struct {
	revokedID   string
	revokeErr   error
	revokeCalls int
}

func (r *signOutRepositoryStub) CreateSession(context.Context, Session) error {
	return nil
}

func (r *signOutRepositoryStub) FindSession(context.Context, string) (Session, error) {
	return Session{}, ErrSessionNotFound
}

func (r *signOutRepositoryStub) RevokeSession(_ context.Context, id string, _ int64) error {
	r.revokeCalls++
	r.revokedID = id
	return r.revokeErr
}

func (r *signOutRepositoryStub) RevokeUserSessions(context.Context, int64) error {
	return nil
}
