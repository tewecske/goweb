package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRateLimiterUsesIndependentBudgetsAndExpiry(t *testing.T) {
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 2, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v, want nil", err)
	}
	now := time.Unix(100, 0)
	limiter.now = func() time.Time { return now }

	for range 2 {
		decision, err := limiter.Allow("signin", "user@example.com")
		if err != nil || !decision.Allowed {
			t.Fatalf("Allow() = %#v, %v; want allowed", decision, err)
		}
	}
	decision, err := limiter.Allow("signin", "user@example.com")
	if err != nil || decision.Allowed || decision.RetryAfter != time.Minute {
		t.Fatalf("blocked Allow() = %#v, %v; want blocked one-minute retry", decision, err)
	}
	decision, err = limiter.Allow("password-reset", "user@example.com")
	if err != nil || !decision.Allowed {
		t.Fatalf("independent action Allow() = %#v, %v; want allowed", decision, err)
	}
	now = now.Add(time.Minute)
	decision, err = limiter.Allow("signin", "user@example.com")
	if err != nil || !decision.Allowed {
		t.Fatalf("expired Allow() = %#v, %v; want allowed", decision, err)
	}
	if err := limiter.Clear("signin", "user@example.com"); err != nil {
		t.Fatalf("Clear() error = %v, want nil", err)
	}
}

func TestRateLimiterBoundsKeysAndConfig(t *testing.T) {
	if _, err := NewRateLimiter(RateLimitConfig{}); !errors.Is(err, ErrInvalidRateLimitConfig) {
		t.Fatalf("NewRateLimiter(zero) error = %v, want %v", err, ErrInvalidRateLimitConfig)
	}
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 1})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v, want nil", err)
	}
	if _, err := limiter.Allow("signin", ""); !errors.Is(err, ErrInvalidRateLimitKey) {
		t.Fatalf("Allow(empty key) error = %v, want %v", err, ErrInvalidRateLimitKey)
	}
	if _, err := limiter.Allow("signin", "first"); err != nil {
		t.Fatalf("Allow(first) error = %v, want nil", err)
	}
	if _, err := limiter.Allow("signin", "second"); !errors.Is(err, ErrRateLimitCapacity) {
		t.Fatalf("Allow(capacity) error = %v, want %v", err, ErrRateLimitCapacity)
	}
}

func TestRateLimitedSignInClearsIdentifierAndOriginOnSuccess(t *testing.T) {
	verifiedAt := int64(100)
	users := &signinUserRepositoryStub{user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}}
	attempts := &failedAttemptStateStub{}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	base, err := NewSignInService(users, signinVerifierStub{valid: true}, sessions, attempts, false)
	if err != nil {
		t.Fatalf("NewSignInService() error = %v, want nil", err)
	}
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v, want nil", err)
	}
	limited, err := NewRateLimitedSignInService(base, limiter)
	if err != nil {
		t.Fatalf("NewRateLimitedSignInService() error = %v, want nil", err)
	}

	if _, err := limited.SignIn(context.Background(), SignInInput{Identifier: " USER@example.com ", Password: "hunter42"}, "127.0.0.1"); err != nil {
		t.Fatalf("SignIn() error = %v, want nil", err)
	}
	if _, err := limited.SignIn(context.Background(), SignInInput{Identifier: "user@example.com", Password: "hunter42"}, "127.0.0.1"); err != nil {
		t.Fatalf("SignIn() after clear error = %v, want nil", err)
	}
}

func TestRateLimitedSignInRecordsAttemptOutcomes(t *testing.T) {
	verifiedAt := int64(100)
	newService := func(valid bool, limit int) (*RateLimitedSignInService, *loginAttemptRecorderStub) {
		t.Helper()
		users := &signinUserRepositoryStub{user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}}
		base, err := NewSignInService(users, signinVerifierStub{valid: valid}, &SessionService{sessions: &sessionRepositoryStub{}, lifetime: time.Hour}, &failedAttemptStateStub{}, false)
		if err != nil {
			t.Fatalf("NewSignInService() error = %v", err)
		}
		limiter, err := NewRateLimiter(RateLimitConfig{Limit: limit, Window: time.Minute, MaxKeys: 10})
		if err != nil {
			t.Fatalf("NewRateLimiter() error = %v", err)
		}
		recorder := &loginAttemptRecorderStub{}
		limited, err := NewRateLimitedSignInServiceWithRecorder(base, limiter, recorder)
		if err != nil {
			t.Fatalf("NewRateLimitedSignInServiceWithRecorder() error = %v", err)
		}
		return limited, recorder
	}

	t.Run("success records account id", func(t *testing.T) {
		limited, recorder := newService(true, 5)
		if _, err := limited.SignIn(context.Background(), SignInInput{Identifier: "user@example.com", Password: "hunter42"}, "127.0.0.1"); err != nil {
			t.Fatalf("SignIn() error = %v", err)
		}
		if len(recorder.attempts) != 1 || recorder.attempts[0].Outcome != LoginOutcomeSuccess {
			t.Fatalf("attempts = %+v, want one success", recorder.attempts)
		}
		if recorder.attempts[0].UserID == nil || *recorder.attempts[0].UserID != 42 {
			t.Fatalf("attempt user id = %v, want 42", recorder.attempts[0].UserID)
		}
	})

	t.Run("invalid credentials recorded", func(t *testing.T) {
		limited, recorder := newService(false, 5)
		_, _ = limited.SignIn(context.Background(), SignInInput{Identifier: "user@example.com", Password: "wrong"}, "127.0.0.1")
		if len(recorder.attempts) != 1 || recorder.attempts[0].Outcome != LoginOutcomeInvalidCredentials {
			t.Fatalf("attempts = %+v, want invalid credentials", recorder.attempts)
		}
	})

	t.Run("rate limited recorded", func(t *testing.T) {
		limited, recorder := newService(false, 1)
		input := SignInInput{Identifier: "user@example.com", Password: "wrong"}
		_, _ = limited.SignIn(context.Background(), input, "127.0.0.1")
		_, err := limited.SignIn(context.Background(), input, "127.0.0.1")
		if !errors.Is(err, ErrRateLimited) {
			t.Fatalf("second SignIn() error = %v, want rate limited", err)
		}
		last := recorder.attempts[len(recorder.attempts)-1]
		if last.Outcome != LoginOutcomeRateLimited {
			t.Fatalf("last attempt = %+v, want rate limited", last)
		}
	})
}

func TestRateLimitedSignInReturnsRateLimitError(t *testing.T) {
	verifiedAt := int64(100)
	users := &signinUserRepositoryStub{user: User{ID: 42, PasswordHash: stringPointer("stored-hash"), EmailVerifiedAt: &verifiedAt}}
	base, err := NewSignInService(users, signinVerifierStub{}, &SessionService{sessions: &sessionRepositoryStub{}, lifetime: time.Hour}, &failedAttemptStateStub{}, false)
	if err != nil {
		t.Fatalf("NewSignInService() error = %v, want nil", err)
	}
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: 1, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v, want nil", err)
	}
	limited, err := NewRateLimitedSignInService(base, limiter)
	if err != nil {
		t.Fatalf("NewRateLimitedSignInService() error = %v, want nil", err)
	}
	input := SignInInput{Identifier: "user@example.com", Password: "hunter42"}
	_, _ = limited.SignIn(context.Background(), input, "127.0.0.1")
	_, err = limited.SignIn(context.Background(), input, "127.0.0.1")
	var rateLimitErr RateLimitError
	if !errors.As(err, &rateLimitErr) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("blocked SignIn() error = %v, want RateLimitError", err)
	}
}

type loginAttemptRecorderStub struct {
	attempts []LoginAttempt
	err      error
}

func (s *loginAttemptRecorderStub) RecordLoginAttempt(_ context.Context, attempt LoginAttempt) error {
	s.attempts = append(s.attempts, attempt)
	return s.err
}
