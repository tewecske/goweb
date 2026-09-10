package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasswordResetServiceRequestSendsForPasswordAccount(t *testing.T) {
	users := &confirmationUserRepositoryStub{
		emailUser: User{ID: 42, Email: stringPointer(" User@Example.COM "), PasswordHash: stringPointer("hash")},
	}
	tokens := &passwordResetTokenRepositoryStub{}
	mailer := &confirmationMailSenderStub{}
	service := newPasswordResetServiceForTest(t, users, tokens, mailer)

	if err := service.Request(context.Background(), " USER@example.com "); err != nil {
		t.Fatalf("Request() error = %v, want nil", err)
	}
	if tokens.created.UserID != 42 || tokens.created.CreatedAt != 100 || tokens.created.ExpiresAt != 3_700 {
		t.Fatalf("created reset token = %#v, want user 42 and 100..3700", tokens.created)
	}
	if len(tokens.created.Token) != maxPasswordResetTokenLength {
		t.Fatalf("token length = %d, want %d", len(tokens.created.Token), maxPasswordResetTokenLength)
	}
	if len(mailer.messages) != 1 || mailer.messages[0].To != "user@example.com" {
		t.Fatalf("mail messages = %#v, want one normalized recipient", mailer.messages)
	}
	if !strings.Contains(mailer.messages[0].TextBody, "/app/reset-password?token=") {
		t.Errorf("mail body missing reset link: %q", mailer.messages[0].TextBody)
	}
}

func TestPasswordResetServiceRequestUsesUniformNoSendResults(t *testing.T) {
	tests := []struct {
		name string
		user User
	}{
		{name: "unknown", user: User{}},
		{name: "guest", user: User{ID: 42, IsGuest: true, Email: stringPointer("user@example.com"), PasswordHash: stringPointer("hash")}},
		{name: "external only", user: User{ID: 42, Email: stringPointer("user@example.com")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &confirmationUserRepositoryStub{emailUser: test.user}
			tokens := &passwordResetTokenRepositoryStub{}
			mailer := &confirmationMailSenderStub{}
			service := newPasswordResetServiceForTest(t, users, tokens, mailer)
			if err := service.Request(context.Background(), "user@example.com"); err != nil {
				t.Fatalf("Request() error = %v, want nil", err)
			}
			if tokens.calls != 0 || len(mailer.messages) != 0 {
				t.Fatal("no-send reset request created token or mail")
			}
		})
	}
}

func TestPasswordResetServiceRequestHasIndependentRateLimit(t *testing.T) {
	users := &confirmationUserRepositoryStub{emailUser: User{ID: 42, Email: stringPointer("user@example.com"), PasswordHash: stringPointer("hash")}}
	limiter := newConfirmationResendLimiter(t, 1)
	service := newPasswordResetServiceForTestWithLimiter(t, users, &passwordResetTokenRepositoryStub{}, &confirmationMailSenderStub{}, limiter)
	if err := service.Request(context.Background(), "user@example.com"); err != nil {
		t.Fatalf("first Request() error = %v, want nil", err)
	}
	if err := service.Request(context.Background(), "user@example.com"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second Request() error = %v, want ErrRateLimited", err)
	}
	if _, err := limiter.Allow("email-confirmation.resend", "user@example.com"); err != nil {
		t.Fatalf("independent confirmation budget error = %v, want nil", err)
	}
}

func TestPasswordResetServiceRequestPropagatesFailures(t *testing.T) {
	lookupErr := errors.New("lookup unavailable")
	tokenErr := errors.New("token store unavailable")
	mailErr := errors.New("mail transport unavailable")
	tests := []struct {
		name     string
		users    *confirmationUserRepositoryStub
		tokens   *passwordResetTokenRepositoryStub
		mailer   *confirmationMailSenderStub
		expected error
	}{
		{name: "lookup", users: &confirmationUserRepositoryStub{emailErr: lookupErr}, tokens: &passwordResetTokenRepositoryStub{}, mailer: &confirmationMailSenderStub{}, expected: lookupErr},
		{name: "token store", users: &confirmationUserRepositoryStub{emailUser: User{ID: 42, Email: stringPointer("user@example.com"), PasswordHash: stringPointer("hash")}}, tokens: &passwordResetTokenRepositoryStub{err: tokenErr}, mailer: &confirmationMailSenderStub{}, expected: tokenErr},
		{name: "mail sender", users: &confirmationUserRepositoryStub{emailUser: User{ID: 42, Email: stringPointer("user@example.com"), PasswordHash: stringPointer("hash")}}, tokens: &passwordResetTokenRepositoryStub{}, mailer: &confirmationMailSenderStub{err: mailErr}, expected: mailErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newPasswordResetServiceForTest(t, test.users, test.tokens, test.mailer)
			if err := service.Request(context.Background(), "user@example.com"); !errors.Is(err, test.expected) {
				t.Fatalf("Request() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

func TestPasswordResetServiceRequestRejectsMalformedAndNilContext(t *testing.T) {
	service := newPasswordResetServiceForTest(t, &confirmationUserRepositoryStub{}, &passwordResetTokenRepositoryStub{}, &confirmationMailSenderStub{})
	if err := service.Request(context.Background(), "not-an-email"); err != nil {
		t.Fatalf("malformed Request() error = %v, want nil", err)
	}
	if err := service.Request(nil, "user@example.com"); err == nil {
		t.Fatal("Request(nil context) error = nil, want error")
	}
}

func newPasswordResetServiceForTest(t *testing.T, users *confirmationUserRepositoryStub, tokens *passwordResetTokenRepositoryStub, mailer *confirmationMailSenderStub) *PasswordResetService {
	t.Helper()
	return newPasswordResetServiceForTestWithLimiter(t, users, tokens, mailer, newConfirmationResendLimiter(t, 10))
}

func newPasswordResetServiceForTestWithLimiter(t *testing.T, users *confirmationUserRepositoryStub, tokens *passwordResetTokenRepositoryStub, mailer *confirmationMailSenderStub, limiter *RateLimiter) *PasswordResetService {
	t.Helper()
	service, err := NewPasswordResetService(users, tokens, mailer, limiter, confirmationURL(t), time.Hour)
	if err != nil {
		t.Fatalf("NewPasswordResetService() error = %v, want nil", err)
	}
	service.now = func() time.Time { return time.Unix(100, 0) }
	return service
}

type passwordResetTokenRepositoryStub struct {
	created       PasswordResetToken
	consumed      PasswordResetToken
	consumedToken string
	consumedAt    int64
	consumeErr    error
	err           error
	calls         int
}

func (r *passwordResetTokenRepositoryStub) CreatePasswordResetToken(_ context.Context, token PasswordResetToken) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.created = token
	return nil
}

func (r *passwordResetTokenRepositoryStub) ConsumePasswordResetToken(_ context.Context, token string, now int64) (PasswordResetToken, error) {
	r.consumedToken = token
	r.consumedAt = now
	if r.consumeErr != nil {
		return PasswordResetToken{}, r.consumeErr
	}
	return r.consumed, nil
}
