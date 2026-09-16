package service

import (
	"context"
	"errors"
	"strconv"
)

var (
	// ErrNilIdentityManager identifies missing administrator identity wiring.
	ErrNilIdentityManager = errors.New("service: nil admin identity service")
)

// IdentityRemover removes one linked external identity unless it is the
// account's last sign-in method.
type IdentityRemover interface {
	Unlink(context.Context, int64, int64) error
}

// AdminIdentityService owns administrator external identity removal. It
// enforces the last-credential rule and never exposes provider subjects.
type AdminIdentityService struct {
	users    UserRepository
	unlinker IdentityRemover
	auditor  AuditRecorder
}

// NewAdminIdentityService constructs administrator identity actions with
// explicit account, unlink, and audit dependencies.
func NewAdminIdentityService(users UserRepository, unlinker IdentityRemover, auditor AuditRecorder) (*AdminIdentityService, error) {
	if users == nil || unlinker == nil {
		return nil, ErrNilIdentityManager
	}
	return &AdminIdentityService{users: users, unlinker: unlinker, auditor: auditor}, nil
}

// RemoveIdentity removes one linked provider after enforcing the last-credential
// rule. A missing account or identity is reported to the caller.
func (s *AdminIdentityService) RemoveIdentity(ctx context.Context, actor AdminActionContext, targetID, identityID int64) error {
	if s == nil || s.users == nil || s.unlinker == nil {
		return ErrNilIdentityManager
	}
	if ctx == nil {
		return errors.New("service: nil admin identity context")
	}
	if actor.ActorID <= 0 || targetID <= 0 || identityID <= 0 {
		return ErrInvalidAdminQuery
	}
	user, err := s.users.FindUserByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return ErrRecordNotFound
		}
		return err
	}
	if err := s.unlinker.Unlink(ctx, targetID, identityID); err != nil {
		return err
	}
	if s.auditor == nil {
		return nil
	}
	record := AuditRecord{
		ActorUserID: actor.ActorID,
		Action:      AuditActionIdentityRemoved,
		TargetType:  "user",
		TargetID:    strconv.FormatInt(targetID, 10),
		Detail:      adminAccountDetail(user),
		IP:          actor.Origin,
	}
	if actorUser, err := s.users.FindUserByID(ctx, actor.ActorID); err == nil && actorUser.Email != nil {
		record.ActorEmail = *actorUser.Email
	}
	_ = s.auditor.Record(ctx, record)
	return nil
}
