package postgres

import (
	"context"
	"database/sql"

	"github.com/tewecske/goweb/internal/service"
)

// RetentionRepository removes expired credentials and old operational history.
type RetentionRepository struct {
	adapter *Adapter
}

// NewRetentionRepository constructs a PostgreSQL retention repository.
func NewRetentionRepository(db *sql.DB) (*RetentionRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &RetentionRepository{adapter: adapter}, nil
}

var _ service.RetentionRepository = (*RetentionRepository)(nil)

// DeleteExpiredEmailConfirmationTokens removes consumed or expired confirmation
// links.
func (r *RetentionRepository) DeleteExpiredEmailConfirmationTokens(ctx context.Context, now int64) (int, error) {
	return r.delete(ctx, "delete expired email confirmation tokens",
		`DELETE FROM email_verification_tokens WHERE consumed_at IS NOT NULL OR expires_at <= $1`, now)
}

// DeleteExpiredPasswordResetTokens removes consumed or expired reset links.
func (r *RetentionRepository) DeleteExpiredPasswordResetTokens(ctx context.Context, now int64) (int, error) {
	return r.delete(ctx, "delete expired password reset tokens",
		`DELETE FROM password_reset_tokens WHERE consumed_at IS NOT NULL OR expires_at <= $1`, now)
}

// DeleteExpiredOAuthStates removes consumed or expired OAuth flow states.
func (r *RetentionRepository) DeleteExpiredOAuthStates(ctx context.Context, now int64) (int, error) {
	return r.delete(ctx, "delete expired oauth states",
		`DELETE FROM oauth_states WHERE consumed_at IS NOT NULL OR expires_at <= $1`, now)
}

// DeleteLoginAttemptsBefore removes sign-in history older than cutoff.
func (r *RetentionRepository) DeleteLoginAttemptsBefore(ctx context.Context, cutoff int64) (int, error) {
	return r.delete(ctx, "delete old login attempts",
		`DELETE FROM login_attempts WHERE created_at < $1`, cutoff)
}

// DeleteUsageEventsBefore removes usage events older than cutoff.
func (r *RetentionRepository) DeleteUsageEventsBefore(ctx context.Context, cutoff int64) (int, error) {
	return r.delete(ctx, "delete old usage events",
		`DELETE FROM usage_events WHERE created_at < $1`, cutoff)
}

func (r *RetentionRepository) delete(ctx context.Context, operation, query string, cutoff int64) (int, error) {
	db, err := r.database(ctx)
	if err != nil {
		return 0, err
	}
	if cutoff <= 0 {
		return 0, ErrInvalidData
	}
	result, err := db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, wrapOperation(operation, err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, wrapOperation(operation, err)
	}
	return int(removed), nil
}

func (r *RetentionRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}
