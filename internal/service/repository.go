package service

import "context"

// User is the persistence-facing account model. Nullable database columns use
// pointers so repositories cannot silently turn NULL into an application value.
type User struct {
	ID              int64
	Email           *string
	PasswordHash    *string
	Username        *string
	DisplayName     *string
	IsGuest         bool
	IsAdmin         bool
	Theme           string
	Locale          string
	CreatedAt       int64
	EmailVerifiedAt *int64
	Version         int64
}

// Session is an opaque account session. Repositories must never expose its ID
// through logs, diagnostics, or user-facing responses.
type Session struct {
	ID        string
	UserID    int64
	CreatedAt int64
	ExpiresAt int64
	RevokedAt *int64
}

// UserRepository persists account records. Update and Delete require the
// revision read by the caller so stale writes can be reported as conflicts.
type UserRepository interface {
	CreateUser(context.Context, User) (User, error)
	FindUserByID(context.Context, int64) (User, error)
	FindUserByEmail(context.Context, string) (User, error)
	FindUserByUsername(context.Context, string) (User, error)
	UpdateUser(context.Context, User, int64) (User, error)
	DeleteUser(context.Context, int64, int64) error
}

// SessionRepository persists and revokes account sessions.
type SessionRepository interface {
	CreateSession(context.Context, Session) error
	FindSession(context.Context, string) (Session, error)
	RevokeSession(context.Context, string, int64) error
	RevokeUserSessions(context.Context, int64) error
}
