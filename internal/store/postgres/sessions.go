package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tewecske/goweb/internal/service"
)

// SessionRepository persists opaque account sessions.
type SessionRepository struct {
	adapter *Adapter
}

// NewSessionRepository constructs session storage over db.
func NewSessionRepository(db *sql.DB) (*SessionRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &SessionRepository{adapter: adapter}, nil
}

var _ service.SessionRepository = (*SessionRepository)(nil)

// CreateSession stores one opaque session credential.
func (r *SessionRepository) CreateSession(ctx context.Context, session service.Session) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	if session.ID == "" || len(session.ID) > 64 || session.UserID <= 0 {
		return ErrInvalidData
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return mapSessionError(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockUserSessions(ctx, tx, session.UserID); err != nil {
		return mapSessionError(err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, created_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5)
	`, sessionDigest(session.ID), session.UserID, session.CreatedAt, session.ExpiresAt, session.RevokedAt)
	if err != nil {
		return mapSessionError(err)
	}
	if err := tx.Commit(); err != nil {
		return mapSessionError(err)
	}
	return mapSessionError(err)
}

// FindSession returns stored state, including expired and revoked rows. The
// service layer owns authentication policy for those states.
func (r *SessionRepository) FindSession(ctx context.Context, id string) (service.Session, error) {
	db, err := r.database(ctx)
	if err != nil {
		return service.Session{}, err
	}
	if id == "" || len(id) > 64 {
		return service.Session{}, service.ErrSessionNotFound
	}
	session, err := scanSession(db.QueryRowContext(ctx, `
		SELECT id, user_id, created_at, expires_at, revoked_at
		FROM sessions
		WHERE id = $1
	`, sessionDigest(id)))
	if err != nil {
		return service.Session{}, mapSessionError(err)
	}
	session.ID = id
	return session, nil
}

// RevokeSession records the first revocation time. Repeated revocation is an
// idempotent success while an absent session remains distinguishable.
func (r *SessionRepository) RevokeSession(ctx context.Context, id string, revokedAt int64) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	if id == "" || len(id) > 64 {
		return service.ErrSessionNotFound
	}
	result, err := db.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1
	`, sessionDigest(id), revokedAt)
	if err != nil {
		return mapSessionError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return mapSessionError(err)
	}
	if rows == 0 {
		return service.ErrSessionNotFound
	}
	return nil
}

// RevokeUserSessions revokes every session for userID in one atomic update.
// Accounts without sessions are a successful no-op.
func (r *SessionRepository) RevokeUserSessions(ctx context.Context, userID int64) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	if userID <= 0 {
		return service.ErrInvalidSessionUserID
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return mapSessionError(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockUserSessions(ctx, tx, userID); err != nil {
		return mapSessionError(err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE user_id = $1
	`, userID, time.Now().Unix())
	if err != nil {
		return mapSessionError(err)
	}
	return mapSessionError(tx.Commit())
}

func (r *SessionRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}

func scanSession(row rowScanner) (service.Session, error) {
	var (
		session   service.Session
		revokedAt sql.NullInt64
	)
	if err := row.Scan(&session.ID, &session.UserID, &session.CreatedAt, &session.ExpiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return service.Session{}, service.ErrSessionNotFound
		}
		return service.Session{}, err
	}
	if session.ID == "" || len(session.ID) > 64 || session.UserID <= 0 || session.ExpiresAt <= session.CreatedAt {
		return service.Session{}, ErrInvalidData
	}
	session.RevokedAt = nullableInt64(revokedAt)
	return session, nil
}

func lockUserSessions(ctx context.Context, tx *sql.Tx, userID int64) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT pg_advisory_xact_lock(hashtextextended('goweb:sessions:' || $1::bigint::text, 0))
	`, userID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := rows.Scan(new(any)); err != nil {
			return err
		}
	}
	return rows.Err()
}

func sessionDigest(id string) string {
	digest := sha256.Sum256([]byte(id))
	return hex.EncodeToString(digest[:])
}

func mapSessionError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, service.ErrSessionNotFound) || errors.Is(err, sql.ErrNoRows) {
		return service.ErrSessionNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return ClassifyError(err)
}
