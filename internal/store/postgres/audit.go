package postgres

import (
	"context"
	"database/sql"

	"github.com/tewecske/goweb/internal/service"
)

// AuditLogRepository stores administrator action history in PostgreSQL.
type AuditLogRepository struct {
	adapter *Adapter
}

// NewAuditLogRepository constructs an administrator audit repository.
func NewAuditLogRepository(db *sql.DB) (*AuditLogRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &AuditLogRepository{adapter: adapter}, nil
}

var _ service.AuditRepository = (*AuditLogRepository)(nil)

// CreateAuditEntry inserts one administrator action record.
func (r *AuditLogRepository) CreateAuditEntry(ctx context.Context, entry service.AuditEntry) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	if entry.Action == "" || entry.OccurredAt <= 0 {
		return ErrInvalidData
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_log (
			occurred_at, actor_user_id, actor_email, action,
			target_type, target_id, detail, ip
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, entry.OccurredAt, entry.ActorUserID, entry.ActorEmail, entry.Action,
		entry.TargetType, entry.TargetID, entry.Detail, entry.IP); err != nil {
		return wrapOperation("create audit entry", err)
	}
	return nil
}

func (r *AuditLogRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}
