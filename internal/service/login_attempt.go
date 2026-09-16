package service

import (
	"context"
	"errors"
)

// Stable login-attempt outcome codes stored in the durable history.
const (
	LoginOutcomeSuccess            = "success"
	LoginOutcomeInvalidCredentials = "invalid_credentials"
	LoginOutcomeUnconfirmed        = "unconfirmed"
	LoginOutcomeRateLimited        = "rate_limited"
	LoginOutcomeError              = "error"
)

// MaxAdminLoginAttempts bounds how many recent attempts a diagnostic page reads.
const MaxAdminLoginAttempts = 50

var (
	// ErrInvalidLoginAttempt identifies an unusable sign-in history record.
	ErrInvalidLoginAttempt = errors.New("service: invalid login attempt")
	// ErrNilLoginAttemptRepository identifies missing sign-in history persistence.
	ErrNilLoginAttemptRepository = errors.New("service: nil login attempt repository")
)

// LoginAttempt is one durable sign-in history row. The normalized email is kept
// even when no account matched, and the account reference clears on deletion.
type LoginAttempt struct {
	ID        int64
	Email     string
	UserID    *int64
	IP        *string
	Outcome   string
	CreatedAt int64
}

// LoginAttemptRepository stores and reads durable sign-in history.
type LoginAttemptRepository interface {
	RecordLoginAttempt(context.Context, LoginAttempt) error
	ListLoginAttemptsForUser(context.Context, int64, int) ([]LoginAttempt, error)
	ListLoginAttemptsForEmail(context.Context, string, int) ([]LoginAttempt, error)
}

// LoginAttemptRecorder is the small port consumed by sign-in flows so history
// recording never becomes a hard dependency of authentication.
type LoginAttemptRecorder interface {
	RecordLoginAttempt(context.Context, LoginAttempt) error
}

// RecordLoginAttempt stores one attempt as a best-effort history row. A
// recording failure must never change the sign-in outcome.
func RecordLoginAttempt(ctx context.Context, recorder LoginAttemptRecorder, attempt LoginAttempt) {
	if recorder == nil || ctx == nil {
		return
	}
	if attempt.Outcome == "" || attempt.CreatedAt <= 0 {
		return
	}
	_ = recorder.RecordLoginAttempt(ctx, attempt)
}
