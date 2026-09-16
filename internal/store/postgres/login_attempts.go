package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/tewecske/goweb/internal/service"
)

// LoginAttemptRepository persists durable sign-in history, including attempts
// against unknown accounts.
type LoginAttemptRepository struct {
	adapter *Adapter
}

// NewLoginAttemptRepository constructs a PostgreSQL sign-in history repository.
func NewLoginAttemptRepository(db *sql.DB) (*LoginAttemptRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &LoginAttemptRepository{adapter: adapter}, nil
}

var _ service.LoginAttemptRepository = (*LoginAttemptRepository)(nil)

// RecordLoginAttempt inserts one sign-in history row.
func (r *LoginAttemptRepository) RecordLoginAttempt(ctx context.Context, attempt service.LoginAttempt) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	if attempt.Email == "" || attempt.Outcome == "" {
		return ErrInvalidData
	}
	createdAt := attempt.CreatedAt
	if createdAt <= 0 {
		createdAt = time.Now().Unix()
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO login_attempts (email, user_id, ip, outcome, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, attempt.Email, attempt.UserID, attempt.IP, attempt.Outcome, createdAt); err != nil {
		return wrapOperation("record login attempt", err)
	}
	return nil
}

// ListLoginAttemptsForUser returns the most recent attempts, newest first.
func (r *LoginAttemptRepository) ListLoginAttemptsForUser(ctx context.Context, userID int64, limit int) ([]service.LoginAttempt, error) {
	db, err := r.database(ctx)
	if err != nil {
		return nil, err
	}
	if userID <= 0 {
		return nil, service.ErrInvalidUserID
	}
	if limit <= 0 || limit > service.MaxAdminLoginAttempts {
		limit = service.MaxAdminLoginAttempts
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, email, user_id, ip, outcome, created_at
		FROM login_attempts
		WHERE user_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2
	`, userID, limit)
	if err != nil {
		return nil, wrapOperation("list login attempts", err)
	}
	defer func() { _ = rows.Close() }()

	attempts := make([]service.LoginAttempt, 0, limit)
	for rows.Next() {
		var (
			attempt service.LoginAttempt
			userID  sql.NullInt64
			ip      sql.NullString
		)
		if err := rows.Scan(&attempt.ID, &attempt.Email, &userID, &ip, &attempt.Outcome, &attempt.CreatedAt); err != nil {
			return nil, wrapOperation("scan login attempt", err)
		}
		if attempt.ID <= 0 || attempt.Email == "" || attempt.Outcome == "" {
			return nil, ErrInvalidData
		}
		attempt.UserID = nullableInt64(userID)
		attempt.IP = nullableString(ip)
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapOperation("iterate login attempts", err)
	}
	return attempts, nil
}

func (r *LoginAttemptRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}
