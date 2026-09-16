package service

import (
	"context"
	"errors"
	"testing"
)

func TestAdminIdentityServiceRemoveIdentityRecordsAudit(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9, Email: strPtr("identity@example.test")}}
	unlinker := &identityRemoverStub{}
	auditor := &auditRecorderStub{}
	service, err := NewAdminIdentityService(users, unlinker, auditor)
	if err != nil {
		t.Fatalf("NewAdminIdentityService() error = %v", err)
	}
	if err := service.RemoveIdentity(context.Background(), AdminActionContext{ActorID: 1}, 9, 4); err != nil {
		t.Fatalf("RemoveIdentity() error = %v", err)
	}
	if unlinker.userID != 9 || unlinker.identityID != 4 {
		t.Fatalf("unlink = user %d identity %d, want 9/4", unlinker.userID, unlinker.identityID)
	}
	if len(auditor.records) != 1 || auditor.records[0].Action != AuditActionIdentityRemoved {
		t.Fatalf("audit records = %+v, want one identity-removed record", auditor.records)
	}
}

func TestAdminIdentityServicePropagatesLastCredentialRule(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9}}
	service, err := NewAdminIdentityService(users, &identityRemoverStub{err: ErrOAuthLastSignInMethod}, nil)
	if err != nil {
		t.Fatalf("NewAdminIdentityService() error = %v", err)
	}
	if err := service.RemoveIdentity(context.Background(), AdminActionContext{ActorID: 1}, 9, 4); !errors.Is(err, ErrOAuthLastSignInMethod) {
		t.Fatalf("RemoveIdentity() error = %v, want %v", err, ErrOAuthLastSignInMethod)
	}
}

func TestAdminIdentityServiceMapsMissingAccount(t *testing.T) {
	users := &userRepositoryStub{findErr: ErrUserNotFound}
	service, err := NewAdminIdentityService(users, &identityRemoverStub{}, nil)
	if err != nil {
		t.Fatalf("NewAdminIdentityService() error = %v", err)
	}
	if err := service.RemoveIdentity(context.Background(), AdminActionContext{ActorID: 1}, 9, 4); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("RemoveIdentity() error = %v, want %v", err, ErrRecordNotFound)
	}
}

func TestNewAdminIdentityServiceRejectsMissingPorts(t *testing.T) {
	if _, err := NewAdminIdentityService(nil, &identityRemoverStub{}, nil); !errors.Is(err, ErrNilIdentityManager) {
		t.Fatalf("error = %v, want %v", err, ErrNilIdentityManager)
	}
	if _, err := NewAdminIdentityService(&userRepositoryStub{}, nil, nil); !errors.Is(err, ErrNilIdentityManager) {
		t.Fatalf("error = %v, want %v", err, ErrNilIdentityManager)
	}
}

type identityRemoverStub struct {
	userID     int64
	identityID int64
	err        error
}

func (s *identityRemoverStub) Unlink(_ context.Context, userID, identityID int64) error {
	s.userID = userID
	s.identityID = identityID
	return s.err
}
