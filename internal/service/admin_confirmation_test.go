package service

import (
	"context"
	"errors"
	"testing"
)

func TestAdminConfirmationServiceConfirmEmail(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9, Email: strPtr("confirm@example.test")}}
	auditor := &auditRecorderStub{}
	service, err := NewAdminConfirmationService(users, &confirmationIssuerStub{}, auditor)
	if err != nil {
		t.Fatalf("NewAdminConfirmationService() error = %v", err)
	}
	if err := service.ConfirmEmail(context.Background(), AdminActionContext{ActorID: 1}, 9); err != nil {
		t.Fatalf("ConfirmEmail() error = %v", err)
	}
	if users.lastUpdated.EmailVerifiedAt == nil {
		t.Fatal("confirmed email has no verification time")
	}
	if len(auditor.records) != 1 || auditor.records[0].Action != AuditActionEmailConfirmed {
		t.Fatalf("audit records = %+v, want one email-confirmed record", auditor.records)
	}
}

func TestAdminConfirmationServiceConfirmEmailIdempotent(t *testing.T) {
	verified := int64(50)
	users := &userRepositoryStub{created: User{ID: 9, Email: strPtr("already@example.test"), EmailVerifiedAt: &verified}}
	service, err := NewAdminConfirmationService(users, &confirmationIssuerStub{}, &auditRecorderStub{})
	if err != nil {
		t.Fatalf("NewAdminConfirmationService() error = %v", err)
	}
	if err := service.ConfirmEmail(context.Background(), AdminActionContext{ActorID: 1}, 9); err != nil {
		t.Fatalf("ConfirmEmail() error = %v", err)
	}
	if users.lastUpdated.ID != 0 {
		t.Fatal("already confirmed account was written again")
	}
}

func TestAdminConfirmationServiceRejectsGuests(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9, IsGuest: true}}
	service, err := NewAdminConfirmationService(users, &confirmationIssuerStub{}, nil)
	if err != nil {
		t.Fatalf("NewAdminConfirmationService() error = %v", err)
	}
	if err := service.ConfirmEmail(context.Background(), AdminActionContext{ActorID: 1}, 9); !errors.Is(err, ErrInvalidConfirmationAccount) {
		t.Fatalf("ConfirmEmail(guest) error = %v, want %v", err, ErrInvalidConfirmationAccount)
	}
}

func TestAdminConfirmationServiceSendConfirmation(t *testing.T) {
	users := &userRepositoryStub{created: User{ID: 9, Email: strPtr("send@example.test")}}
	issuer := &confirmationIssuerStub{}
	auditor := &auditRecorderStub{}
	service, err := NewAdminConfirmationService(users, issuer, auditor)
	if err != nil {
		t.Fatalf("NewAdminConfirmationService() error = %v", err)
	}
	if err := service.SendConfirmation(context.Background(), AdminActionContext{ActorID: 1}, 9); err != nil {
		t.Fatalf("SendConfirmation() error = %v", err)
	}
	if len(issuer.issued) != 1 || issuer.issued[0] != 9 {
		t.Fatalf("issued = %+v, want user 9", issuer.issued)
	}
	if len(auditor.records) != 1 || auditor.records[0].Action != AuditActionConfirmationSent {
		t.Fatalf("audit records = %+v, want one confirmation-sent record", auditor.records)
	}
}

func TestAdminConfirmationServiceMapsMissingAccount(t *testing.T) {
	users := &userRepositoryStub{findErr: ErrUserNotFound}
	service, err := NewAdminConfirmationService(users, &confirmationIssuerStub{}, nil)
	if err != nil {
		t.Fatalf("NewAdminConfirmationService() error = %v", err)
	}
	if err := service.SendConfirmation(context.Background(), AdminActionContext{ActorID: 1}, 9); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("SendConfirmation() error = %v, want %v", err, ErrRecordNotFound)
	}
}

func TestNewAdminConfirmationServiceRejectsMissingPorts(t *testing.T) {
	if _, err := NewAdminConfirmationService(nil, &confirmationIssuerStub{}, nil); !errors.Is(err, ErrNilConfirmationManager) {
		t.Fatalf("error = %v, want %v", err, ErrNilConfirmationManager)
	}
	if _, err := NewAdminConfirmationService(&userRepositoryStub{}, nil, nil); !errors.Is(err, ErrNilConfirmationManager) {
		t.Fatalf("error = %v, want %v", err, ErrNilConfirmationManager)
	}
}

type confirmationIssuerStub struct {
	issued []int64
	err    error
}

func (s *confirmationIssuerStub) Issue(_ context.Context, userID int64) error {
	s.issued = append(s.issued, userID)
	return s.err
}
