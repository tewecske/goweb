package postgres

import (
	"context"
	"database/sql"
	"strings"

	"github.com/tewecske/goweb/internal/service"
)

// SSOLoginSessionRepository stores the Hydra login session IDs seen per
// account so revocation can reach every client app.
type SSOLoginSessionRepository struct {
	adapter *Adapter
}

// NewSSOLoginSessionRepository constructs single sign-on session storage.
func NewSSOLoginSessionRepository(db *sql.DB) (*SSOLoginSessionRepository, error) {
	adapter, err := New(db)
	if err != nil {
		return nil, err
	}
	return &SSOLoginSessionRepository{adapter: adapter}, nil
}

var _ service.SSOLoginSessionRepository = (*SSOLoginSessionRepository)(nil)

// RecordSSOLoginSession stores a session ID. Hydra reports the same ID on
// every sign-in during the session, so a repeat keeps the latest expiry.
func (r *SSOLoginSessionRepository) RecordSSOLoginSession(ctx context.Context, session service.SSOLoginSession) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	if strings.TrimSpace(session.SessionID) == "" || session.UserID <= 0 || session.ExpiresAt <= session.CreatedAt {
		return ErrInvalidData
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO sso_login_sessions (sid, user_id, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (sid) DO UPDATE
		SET expires_at = GREATEST(sso_login_sessions.expires_at, EXCLUDED.expires_at)
		WHERE sso_login_sessions.user_id = EXCLUDED.user_id
	`, session.SessionID, session.UserID, session.CreatedAt, session.ExpiresAt)
	return wrapOperation("record sso login session", err)
}

// ListSSOLoginSessions returns every recorded session ID for an account.
func (r *SSOLoginSessionRepository) ListSSOLoginSessions(ctx context.Context, userID int64) ([]string, error) {
	db, err := r.database(ctx)
	if err != nil {
		return nil, err
	}
	if userID <= 0 {
		return nil, service.ErrInvalidSessionUserID
	}
	rows, err := db.QueryContext(ctx, `SELECT sid FROM sso_login_sessions WHERE user_id = $1 ORDER BY created_at, sid`, userID)
	if err != nil {
		return nil, wrapOperation("list sso login sessions", err)
	}
	defer func() { _ = rows.Close() }()
	sids := make([]string, 0)
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return nil, wrapOperation("scan sso login session", err)
		}
		sids = append(sids, sid)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapOperation("list sso login sessions", err)
	}
	return sids, nil
}

// DeleteSSOLoginSession forgets one session ID. Deleting an absent ID succeeds.
func (r *SSOLoginSessionRepository) DeleteSSOLoginSession(ctx context.Context, sid string) error {
	db, err := r.database(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM sso_login_sessions WHERE sid = $1`, sid)
	return wrapOperation("delete sso login session", err)
}

func (r *SSOLoginSessionRepository) database(ctx context.Context) (*sql.DB, error) {
	if err := ValidateContext(ctx); err != nil {
		return nil, err
	}
	if r == nil || r.adapter == nil {
		return nil, ErrNilDatabase
	}
	return r.adapter.DB()
}
