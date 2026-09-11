package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tewecske/goweb/internal/service"
)

// EmailConfirmationTokenRepository persists confirmation links.
type EmailConfirmationTokenRepository struct {
	adapter *Adapter
}

// NewEmailConfirmationTokenRepository constructs confirmation-token storage.
func NewEmailConfirmationTokenRepository(db *sql.DB) (*EmailConfirmationTokenRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &EmailConfirmationTokenRepository{adapter: adapter}, nil
}

var _ service.EmailConfirmationTokenRepository = (*EmailConfirmationTokenRepository)(nil)

// CreateEmailConfirmationToken stores one confirmation link.
func (r *EmailConfirmationTokenRepository) CreateEmailConfirmationToken(ctx context.Context, token service.EmailConfirmationToken) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (user_id, token, created_at, expires_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5)
	`, token.UserID, token.Token, token.CreatedAt, token.ExpiresAt, token.ConsumedAt)
	return mapTokenError(err, service.ErrEmailConfirmationTokenNotFound)
}

// ConsumeEmailConfirmationToken atomically marks an active link consumed.
func (r *EmailConfirmationTokenRepository) ConsumeEmailConfirmationToken(ctx context.Context, token string, now int64) (service.EmailConfirmationToken, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.EmailConfirmationToken{}, err
	}
	consumed, err := scanEmailConfirmationToken(db.QueryRowContext(ctx, `
		UPDATE email_verification_tokens
		SET consumed_at = $2
		WHERE token = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING user_id, token, created_at, expires_at, consumed_at
	`, token, now))
	if err != nil {
		return service.EmailConfirmationToken{}, mapTokenError(err, service.ErrEmailConfirmationTokenNotFound)
	}
	return consumed, nil
}

// PasswordResetTokenRepository persists password-reset links.
type PasswordResetTokenRepository struct {
	adapter *Adapter
}

// NewPasswordResetTokenRepository constructs password-reset-token storage.
func NewPasswordResetTokenRepository(db *sql.DB) (*PasswordResetTokenRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &PasswordResetTokenRepository{adapter: adapter}, nil
}

var _ service.PasswordResetTokenRepository = (*PasswordResetTokenRepository)(nil)

// CreatePasswordResetToken stores one password-reset link.
func (r *PasswordResetTokenRepository) CreatePasswordResetToken(ctx context.Context, token service.PasswordResetToken) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, consumed_at)
		VALUES ($1, $2, $3, $4, $5)
	`, token.UserID, token.Token, token.CreatedAt, token.ExpiresAt, token.ConsumedAt)
	return mapTokenError(err, service.ErrPasswordResetTokenNotFound)
}

// ConsumePasswordResetToken atomically marks an active link consumed.
func (r *PasswordResetTokenRepository) ConsumePasswordResetToken(ctx context.Context, token string, now int64) (service.PasswordResetToken, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.PasswordResetToken{}, err
	}
	consumed, err := scanPasswordResetToken(db.QueryRowContext(ctx, `
		UPDATE password_reset_tokens
		SET consumed_at = $2
		WHERE token = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING user_id, token, created_at, expires_at, consumed_at
	`, token, now))
	if err != nil {
		return service.PasswordResetToken{}, mapTokenError(err, service.ErrPasswordResetTokenNotFound)
	}
	return consumed, nil
}

func (r *EmailConfirmationTokenRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}

func (r *PasswordResetTokenRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}

func scanEmailConfirmationToken(row rowScanner) (service.EmailConfirmationToken, error) {
	var token service.EmailConfirmationToken
	var consumedAt sql.NullInt64
	if err := row.Scan(&token.UserID, &token.Token, &token.CreatedAt, &token.ExpiresAt, &consumedAt); err != nil {
		return service.EmailConfirmationToken{}, err
	}
	if token.UserID <= 0 || token.Token == "" || len(token.Token) > 64 || token.ExpiresAt <= token.CreatedAt {
		return service.EmailConfirmationToken{}, ErrInvalidData
	}
	token.ConsumedAt = nullableInt64(consumedAt)
	return token, nil
}

func scanPasswordResetToken(row rowScanner) (service.PasswordResetToken, error) {
	var token service.PasswordResetToken
	var consumedAt sql.NullInt64
	if err := row.Scan(&token.UserID, &token.Token, &token.CreatedAt, &token.ExpiresAt, &consumedAt); err != nil {
		return service.PasswordResetToken{}, err
	}
	if token.UserID <= 0 || token.Token == "" || len(token.Token) > 64 || token.ExpiresAt <= token.CreatedAt {
		return service.PasswordResetToken{}, ErrInvalidData
	}
	token.ConsumedAt = nullableInt64(consumedAt)
	return token, nil
}

func mapTokenError(err, notFound error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrNotFound) {
		return notFound
	}
	return ClassifyError(err)
}
