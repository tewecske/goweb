package service

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNilAdminDiagnosticsRepository identifies missing diagnostics persistence.
	ErrNilAdminDiagnosticsRepository = errors.New("service: nil admin diagnostics repository")
)

// AdminSessionRepository reads active sessions for an account. It never
// returns credential-bearing identifiers to a diagnostic caller.
type AdminSessionRepository interface {
	ListActiveSessions(context.Context, int64) ([]Session, error)
	CountActiveSessions(context.Context, int64) (int, error)
}

// AdminUserDetail is the safe account diagnostics aggregate. It contains no
// session identifiers, tokens, provider subjects, or password material.
type AdminUserDetail struct {
	User                   User
	Confirmed              bool
	ConfirmationLinkActive bool
	ConfirmationLinkExpiry int64
	Sessions               []Session
	LoginAttempts          []LoginAttempt
	Identities             []OAuthIdentity
}

// AdminDiagnosticsService aggregates safe account diagnostics for the
// administrator area.
type AdminDiagnosticsService struct {
	users        UserRepository
	sessions     AdminSessionRepository
	attempts     LoginAttemptRepository
	identities   OAuthIdentityRepository
	confirmation EmailConfirmationTokenRepository
}

// NewAdminDiagnosticsService constructs diagnostics with explicit account,
// session, history, identity, and confirmation ports.
func NewAdminDiagnosticsService(users UserRepository, sessions AdminSessionRepository, attempts LoginAttemptRepository, identities OAuthIdentityRepository, confirmation EmailConfirmationTokenRepository) (*AdminDiagnosticsService, error) {
	if users == nil || sessions == nil || attempts == nil || identities == nil || confirmation == nil {
		return nil, ErrNilAdminDiagnosticsRepository
	}
	return &AdminDiagnosticsService{users: users, sessions: sessions, attempts: attempts, identities: identities, confirmation: confirmation}, nil
}

// Detail returns the safe diagnostics for one account. A vanished account is
// reported as not-found so the caller can render a not-found result.
func (s *AdminDiagnosticsService) Detail(ctx context.Context, userID int64) (AdminUserDetail, error) {
	if s == nil || s.users == nil || s.sessions == nil || s.attempts == nil || s.identities == nil || s.confirmation == nil {
		return AdminUserDetail{}, ErrNilAdminDiagnosticsRepository
	}
	if ctx == nil {
		return AdminUserDetail{}, errors.New("service: nil admin diagnostics context")
	}
	if userID <= 0 {
		return AdminUserDetail{}, ErrInvalidUserID
	}
	user, err := s.users.FindUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return AdminUserDetail{}, ErrRecordNotFound
		}
		return AdminUserDetail{}, err
	}
	sessions, err := s.sessions.ListActiveSessions(ctx, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	attempts, err := s.attempts.ListLoginAttemptsForUser(ctx, userID, MaxAdminLoginAttempts)
	if err != nil {
		return AdminUserDetail{}, err
	}
	identities, err := s.identities.ListOAuthIdentities(ctx, userID)
	if err != nil {
		return AdminUserDetail{}, err
	}
	user.PasswordHash = nil
	detail := AdminUserDetail{
		User:          user,
		Confirmed:     user.EmailVerifiedAt != nil,
		Sessions:      sessions,
		LoginAttempts: attempts,
		Identities:    identities,
	}
	link, err := s.confirmation.FindActiveEmailConfirmationToken(ctx, userID, time.Now().Unix())
	switch {
	case err == nil:
		detail.ConfirmationLinkActive = true
		detail.ConfirmationLinkExpiry = link.ExpiresAt
	case errors.Is(err, ErrEmailConfirmationTokenNotFound):
		// No active link is a normal diagnostic result.
	default:
		return AdminUserDetail{}, err
	}
	return detail, nil
}
