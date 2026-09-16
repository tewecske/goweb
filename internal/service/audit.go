package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxAuditActionLength = 64
	maxAuditTargetType   = 32
	maxAuditTargetID     = 64
	maxAuditDetailLength = 1000
	maxAuditActorEmail   = 255
	maxAuditOrigin       = 64
)

// Stable administrator action codes recorded in the audit trail.
const (
	AuditActionAccountCreated   = "admin.account.created"
	AuditActionAccountUpdated   = "admin.account.updated"
	AuditActionAccountDeleted   = "admin.account.deleted"
	AuditActionSessionsRevoked  = "admin.sessions.revoked"
	AuditActionEmailConfirmed   = "admin.email.confirmed"
	AuditActionConfirmationSent = "admin.email.confirmation_sent"
	AuditActionIdentityRemoved  = "admin.identity.removed"
	AuditActionLockoutCleared   = "admin.lockout.cleared"
)

var (
	// ErrInvalidAuditEntry identifies unusable administrator action input.
	ErrInvalidAuditEntry = errors.New("service: invalid audit entry")
	// ErrNilAuditRepository identifies missing audit persistence.
	ErrNilAuditRepository = errors.New("service: nil audit repository")
)

// AuditEntry is one durable administrator action record. Nullable columns use
// pointers so a deleted actor or target leaves a historical snapshot intact.
type AuditEntry struct {
	ID          int64
	OccurredAt  int64
	ActorUserID *int64
	ActorEmail  *string
	Action      string
	TargetType  *string
	TargetID    *string
	Detail      *string
	IP          *string
}

// AuditRepository stores administrator action history. Rows are never
// cascade-deleted when an actor or target account is removed.
type AuditRepository interface {
	CreateAuditEntry(context.Context, AuditEntry) error
}

// AuditRecord is the safe, validated input for one administrator action. It
// must never carry passwords, session credentials, tokens, or provider secrets.
type AuditRecord struct {
	ActorUserID int64
	ActorEmail  string
	Action      string
	TargetType  string
	TargetID    string
	Detail      string
	IP          string
}

// AuditRecorder records administrator actions for a use case.
type AuditRecorder interface {
	Record(context.Context, AuditRecord) error
}

// AuditSink receives a stored administrator action so it can be emitted to the
// separately identifiable security log stream. Sinks must never block or fail
// an already completed action.
type AuditSink interface {
	AuditRecorded(context.Context, AuditRecord)
}

// AuditService validates and stores administrator action records. A storage
// failure is returned to the caller so it can be logged without undoing an
// already completed account action.
type AuditService struct {
	repository AuditRepository
	sink       AuditSink
	now        func() time.Time
}

// NewAuditService constructs audit recording with its persistence port.
func NewAuditService(repository AuditRepository) (*AuditService, error) {
	if repository == nil {
		return nil, ErrNilAuditRepository
	}
	return &AuditService{repository: repository, now: time.Now}, nil
}

// SetSink attaches the security-log sink. It is intended to be called once
// during startup before the server begins serving requests.
func (s *AuditService) SetSink(sink AuditSink) {
	if s == nil {
		return
	}
	s.sink = sink
}

// Record validates and stores one administrator action, then emits it to the
// security log sink. A sink failure cannot affect the stored record.
func (s *AuditService) Record(ctx context.Context, record AuditRecord) error {
	if s == nil || s.repository == nil || s.now == nil {
		return ErrInvalidAuditEntry
	}
	if ctx == nil {
		return errors.New("service: nil audit context")
	}
	entry, err := buildAuditEntry(record, s.now().Unix())
	if err != nil {
		return err
	}
	if err := s.repository.CreateAuditEntry(ctx, entry); err != nil {
		return fmt.Errorf("create audit entry: %w", err)
	}
	if s.sink != nil {
		s.sink.AuditRecorded(ctx, record)
	}
	return nil
}

func buildAuditEntry(record AuditRecord, occurredAt int64) (AuditEntry, error) {
	if record.ActorUserID <= 0 || occurredAt <= 0 {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	action := strings.TrimSpace(record.Action)
	if action == "" || len(action) > maxAuditActionLength || !printable(action) {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	actorEmail := strings.TrimSpace(record.ActorEmail)
	if utf8.RuneCountInString(actorEmail) > maxAuditActorEmail || !printable(actorEmail) {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	targetType := strings.TrimSpace(record.TargetType)
	if len(targetType) > maxAuditTargetType || !printable(targetType) {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	targetID := strings.TrimSpace(record.TargetID)
	if len(targetID) > maxAuditTargetID || !printable(targetID) {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	detail := strings.TrimSpace(record.Detail)
	if utf8.RuneCountInString(detail) > maxAuditDetailLength || !printable(detail) {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	ip := strings.TrimSpace(record.IP)
	if len(ip) > maxAuditOrigin || !printable(ip) {
		return AuditEntry{}, ErrInvalidAuditEntry
	}
	actorID := record.ActorUserID
	entry := AuditEntry{
		OccurredAt:  occurredAt,
		ActorUserID: &actorID,
		Action:      action,
	}
	entry.ActorEmail = optionalString(actorEmail)
	entry.TargetType = optionalString(targetType)
	entry.TargetID = optionalString(targetID)
	entry.Detail = optionalString(detail)
	entry.IP = optionalString(ip)
	return entry, nil
}

func printable(value string) bool {
	for _, character := range value {
		if character == 0 || (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}
	return true
}
