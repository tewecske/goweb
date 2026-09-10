package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEmailConfirmationResenderUsesUniformResponses(t *testing.T) {
	tests := []struct {
		name string
		user User
	}{
		{name: "unknown", user: User{}},
		{name: "confirmed", user: User{ID: 42, Email: stringPointer("user@example.com"), EmailVerifiedAt: int64Pointer(10)}},
		{name: "guest", user: User{ID: 42, Email: stringPointer("user@example.com"), IsGuest: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &confirmationUserRepositoryStub{emailUser: test.user}
			tokens := &confirmationTokenRepositoryStub{}
			mailer := &confirmationMailSenderStub{}
			confirmation := newConfirmationServiceForTest(t, users, tokens, mailer)
			limiter := newConfirmationResendLimiter(t, 1)
			resender, err := NewEmailConfirmationResender(confirmation, limiter)
			if err != nil {
				t.Fatalf("NewEmailConfirmationResender() error = %v, want nil", err)
			}
			if err := resender.Resend(context.Background(), " USER@example.com "); err != nil {
				t.Fatalf("Resend() error = %v, want nil", err)
			}
			if len(mailer.messages) != 0 || tokens.calls != 0 {
				t.Fatal("uniform no-send request created token or mail")
			}
		})
	}
}

func TestEmailConfirmationResenderSendsForUnconfirmedAccount(t *testing.T) {
	users := &confirmationUserRepositoryStub{
		emailUser: User{ID: 42, Email: stringPointer("user@example.com")},
		user:      User{ID: 42, Email: stringPointer("user@example.com")},
	}
	tokens := &confirmationTokenRepositoryStub{}
	mailer := &confirmationMailSenderStub{}
	confirmation := newConfirmationServiceForTest(t, users, tokens, mailer)
	resender, err := NewEmailConfirmationResender(confirmation, newConfirmationResendLimiter(t, 1))
	if err != nil {
		t.Fatalf("NewEmailConfirmationResender() error = %v, want nil", err)
	}

	if err := resender.Resend(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("Resend() error = %v, want nil", err)
	}
	if tokens.calls != 1 || len(mailer.messages) != 1 {
		t.Fatalf("token/mail calls = %d/%d, want 1/1", tokens.calls, len(mailer.messages))
	}
}

func TestEmailConfirmationResenderHasIndependentRateLimit(t *testing.T) {
	users := &confirmationUserRepositoryStub{
		emailUser: User{ID: 42, Email: stringPointer("user@example.com")},
		user:      User{ID: 42, Email: stringPointer("user@example.com")},
	}
	limiter := newConfirmationResendLimiter(t, 1)
	confirmation := newConfirmationServiceForTest(t, users, &confirmationTokenRepositoryStub{}, &confirmationMailSenderStub{})
	resender, err := NewEmailConfirmationResender(confirmation, limiter)
	if err != nil {
		t.Fatalf("NewEmailConfirmationResender() error = %v, want nil", err)
	}
	if err := resender.Resend(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("first Resend() error = %v, want nil", err)
	}
	if err := resender.Resend(context.Background(), "user@example.com"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second Resend() error = %v, want ErrRateLimited", err)
	}
	if _, err := limiter.Allow("signin.identifier", "user@example.com"); err != nil {
		t.Fatalf("independent sign-in budget error = %v, want nil", err)
	}
}

func TestEmailConfirmationResenderPropagatesOperationalFailures(t *testing.T) {
	lookupErr := errors.New("lookup unavailable")
	tests := []struct {
		name     string
		users    *confirmationUserRepositoryStub
		expected error
	}{
		{name: "lookup", users: &confirmationUserRepositoryStub{emailErr: lookupErr}, expected: lookupErr},
		{name: "issue", users: &confirmationUserRepositoryStub{emailUser: User{ID: 42, Email: stringPointer("user@example.com")}, user: User{ID: 42, Email: stringPointer("user@example.com")}}, expected: ErrUserNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var tokens *confirmationTokenRepositoryStub
			if test.name == "issue" {
				tokens = &confirmationTokenRepositoryStub{err: test.expected}
			} else {
				tokens = &confirmationTokenRepositoryStub{}
			}
			confirmation := newConfirmationServiceForTest(t, test.users, tokens, &confirmationMailSenderStub{})
			resender, err := NewEmailConfirmationResender(confirmation, newConfirmationResendLimiter(t, 1))
			if err != nil {
				t.Fatalf("NewEmailConfirmationResender() error = %v, want nil", err)
			}
			if err := resender.Resend(context.Background(), "user@example.com"); !errors.Is(err, test.expected) {
				t.Fatalf("Resend() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

func TestEmailConfirmationResenderRejectsMalformedAndNilContext(t *testing.T) {
	confirmation := newConfirmationServiceForTest(t, &confirmationUserRepositoryStub{}, &confirmationTokenRepositoryStub{}, &confirmationMailSenderStub{})
	resender, err := NewEmailConfirmationResender(confirmation, newConfirmationResendLimiter(t, 1))
	if err != nil {
		t.Fatalf("NewEmailConfirmationResender() error = %v, want nil", err)
	}
	if err := resender.Resend(context.Background(), "not-an-email"); err != nil {
		t.Fatalf("malformed Resend() error = %v, want nil", err)
	}
	if err := resender.Resend(nil, "user@example.com"); err == nil {
		t.Fatal("Resend(nil context) error = nil, want error")
	}
}

func newConfirmationServiceForTest(t *testing.T, users *confirmationUserRepositoryStub, tokens *confirmationTokenRepositoryStub, mailer *confirmationMailSenderStub) *EmailConfirmationService {
	t.Helper()
	service, err := NewEmailConfirmationService(users, tokens, mailer, confirmationURL(t), time.Hour)
	if err != nil {
		t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
	}
	service.now = func() time.Time { return time.Unix(100, 0) }
	return service
}

func newConfirmationResendLimiter(t *testing.T, limit int) *RateLimiter {
	t.Helper()
	limiter, err := NewRateLimiter(RateLimitConfig{Limit: limit, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v, want nil", err)
	}
	return limiter
}
