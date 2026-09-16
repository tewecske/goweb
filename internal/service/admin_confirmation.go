package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var (
	// ErrInvalidConfirmationAccount identifies an account that cannot be confirmed.
	ErrInvalidConfirmationAccount = errors.New("service: invalid confirmation account")
	// ErrNilConfirmationManager identifies missing administrator confirmation wiring.
	ErrNilConfirmationManager = errors.New("service: nil admin confirmation service")
)

// ConfirmationIssuer sends one confirmation link for an account.
type ConfirmationIssuer interface {
	Issue(context.Context, int64) error
}

// AdminConfirmationService owns administrator confirmation diagnostics actions:
// direct confirmation and sending a fresh link. It never returns link tokens.
type AdminConfirmationService struct {
	users        UserRepository
	confirmation ConfirmationIssuer
	auditor      AuditRecorder
}

// NewAdminConfirmationService constructs administrator confirmation actions
// with explicit account, delivery, and audit dependencies.
func NewAdminConfirmationService(users UserRepository, confirmation ConfirmationIssuer, auditor AuditRecorder) (*AdminConfirmationService, error) {
	if users == nil || confirmation == nil {
		return nil, ErrNilConfirmationManager
	}
	return &AdminConfirmationService{users: users, confirmation: confirmation, auditor: auditor}, nil
}

// ConfirmEmail marks an account's address verified after support verification.
// An already confirmed address is an idempotent success.
func (s *AdminConfirmationService) ConfirmEmail(ctx context.Context, actor AdminActionContext, targetID int64) error {
	if s == nil || s.users == nil || s.confirmation == nil {
		return ErrNilConfirmationManager
	}
	if ctx == nil {
		return errors.New("service: nil admin confirmation context")
	}
	if actor.ActorID <= 0 || targetID <= 0 {
		return ErrInvalidAdminQuery
	}
	user, err := s.users.FindUserByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrRecordNotFound
		}
		return err
	}
	if user.IsGuest || user.Email == nil {
		return ErrInvalidConfirmationAccount
	}
	if user.EmailVerifiedAt != nil {
		return nil
	}
	verifiedAt := time.Now().Unix()
	user.EmailVerifiedAt = &verifiedAt
	updated, err := s.users.UpdateUser(ctx, user, user.Version)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrRecordNotFound
		}
		return err
	}
	s.record(ctx, actor, AuditActionEmailConfirmed, updated, adminAccountDetail(updated))
	return nil
}

// SendConfirmation issues a fresh confirmation link for an account. The link
// token is delivered by mail and never returned to the caller.
func (s *AdminConfirmationService) SendConfirmation(ctx context.Context, actor AdminActionContext, targetID int64) error {
	if s == nil || s.users == nil || s.confirmation == nil {
		return ErrNilConfirmationManager
	}
	if ctx == nil {
		return errors.New("service: nil admin confirmation context")
	}
	if actor.ActorID <= 0 || targetID <= 0 {
		return ErrInvalidAdminQuery
	}
	user, err := s.users.FindUserByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrRecordNotFound
		}
		return err
	}
	if user.IsGuest || user.Email == nil {
		return ErrInvalidConfirmationAccount
	}
	if err := s.confirmation.Issue(ctx, targetID); err != nil {
		return fmt.Errorf("issue admin confirmation: %w", err)
	}
	s.record(ctx, actor, AuditActionConfirmationSent, user, adminAccountDetail(user))
	return nil
}

func (s *AdminConfirmationService) record(ctx context.Context, actor AdminActionContext, action string, target User, detail string) {
	if s == nil || s.auditor == nil {
		return
	}
	record := AuditRecord{
		ActorUserID: actor.ActorID,
		Action:      action,
		TargetType:  "user",
		TargetID:    strconv.FormatInt(target.ID, 10),
		Detail:      detail,
		IP:          actor.Origin,
	}
	if actorUser, err := s.users.FindUserByID(ctx, actor.ActorID); err == nil && actorUser.Email != nil {
		record.ActorEmail = *actorUser.Email
	}
	_ = s.auditor.Record(ctx, record)
}
