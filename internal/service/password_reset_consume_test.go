package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPasswordResetConsumerRedeemsAndRevokesSessions(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com"), Version: 4}}
	tokens := &passwordResetTokenRepositoryStub{consumed: PasswordResetToken{
		UserID: 42, Token: token, CreatedAt: 90, ExpiresAt: 200,
	}}
	sessionRepository := &sessionRepositoryStub{}
	sessions, err := NewSessionService(sessionRepository, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	consumer, err := NewPasswordResetConsumer(users, tokens, signupHasherStub{}, sessions)
	if err != nil {
		t.Fatalf("NewPasswordResetConsumer() error = %v, want nil", err)
	}
	consumer.now = func() time.Time { return time.Unix(100, 0) }

	if err := consumer.Redeem(context.Background(), token, "new hunter42"); err != nil {
		t.Fatalf("Redeem() error = %v, want nil", err)
	}
	if tokens.consumedToken != token || tokens.consumedAt != 100 {
		t.Errorf("consumed token/time = %q/%d, want %q/100", tokens.consumedToken, tokens.consumedAt, token)
	}
	if users.updated.PasswordHash == nil || *users.updated.PasswordHash != "hashed-password" {
		t.Errorf("updated password hash = %v, want hashed-password", users.updated.PasswordHash)
	}
	if users.updateExpectedVersion != 4 {
		t.Errorf("expected user version = %d, want 4", users.updateExpectedVersion)
	}
	if sessionRepository.revokedUserID != 42 {
		t.Errorf("revoked user id = %d, want 42", sessionRepository.revokedUserID)
	}
}

func TestPasswordResetConsumerUsesUniformTokenFailure(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		rawToken   string
		consumeErr error
		consumed   PasswordResetToken
	}{
		{name: "malformed", rawToken: "not-a-token"},
		{name: "unknown", rawToken: token, consumeErr: ErrPasswordResetTokenNotFound},
		{name: "expired", rawToken: token, consumed: PasswordResetToken{UserID: 42, Token: token, ExpiresAt: 100}},
		{name: "already used", rawToken: token, consumed: PasswordResetToken{UserID: 42, Token: token, ExpiresAt: 200, ConsumedAt: int64Pointer(90)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}}
			tokens := &passwordResetTokenRepositoryStub{consumeErr: test.consumeErr, consumed: test.consumed}
			sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
			if err != nil {
				t.Fatalf("NewSessionService() error = %v, want nil", err)
			}
			consumer, err := NewPasswordResetConsumer(users, tokens, signupHasherStub{}, sessions)
			if err != nil {
				t.Fatalf("NewPasswordResetConsumer() error = %v, want nil", err)
			}
			consumer.now = func() time.Time { return time.Unix(100, 0) }
			if err := consumer.Redeem(context.Background(), test.rawToken, "new hunter42"); !errors.Is(err, ErrInvalidPasswordResetToken) {
				t.Fatalf("Redeem() error = %v, want ErrInvalidPasswordResetToken", err)
			}
			if users.updateCalls != 0 {
				t.Error("invalid reset updated user")
			}
		})
	}
}

func TestPasswordResetConsumerValidatesPasswordBeforeConsuming(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokens := &passwordResetTokenRepositoryStub{consumed: PasswordResetToken{UserID: 42, Token: token, ExpiresAt: 200}}
	users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}}
	sessions, err := NewSessionService(&sessionRepositoryStub{}, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionService() error = %v, want nil", err)
	}
	consumer, err := NewPasswordResetConsumer(users, tokens, signupHasherStub{}, sessions)
	if err != nil {
		t.Fatalf("NewPasswordResetConsumer() error = %v, want nil", err)
	}
	if err := consumer.Redeem(context.Background(), token, "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Redeem() error = %v, want ErrPasswordTooShort", err)
	}
	if tokens.consumedToken != "" {
		t.Error("invalid password consumed reset token")
	}
}

func TestPasswordResetConsumerPropagatesOperationalFailures(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokenErr := errors.New("token store unavailable")
	lookupErr := errors.New("user store unavailable")
	updateErr := errors.New("user update unavailable")
	sessionErr := errors.New("session store unavailable")
	tests := []struct {
		name     string
		tokens   *passwordResetTokenRepositoryStub
		users    *confirmationUserRepositoryStub
		sessions SessionRepository
		expected error
	}{
		{name: "token store", tokens: &passwordResetTokenRepositoryStub{consumeErr: tokenErr}, users: &confirmationUserRepositoryStub{}, sessions: &sessionRepositoryStub{}, expected: tokenErr},
		{name: "user lookup", tokens: &passwordResetTokenRepositoryStub{consumed: PasswordResetToken{UserID: 42, Token: token, ExpiresAt: 200}}, users: &confirmationUserRepositoryStub{findErr: lookupErr}, sessions: &sessionRepositoryStub{}, expected: lookupErr},
		{name: "user update", tokens: &passwordResetTokenRepositoryStub{consumed: PasswordResetToken{UserID: 42, Token: token, ExpiresAt: 200}}, users: &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}, updateErr: updateErr}, sessions: &sessionRepositoryStub{}, expected: updateErr},
		{name: "session revoke", tokens: &passwordResetTokenRepositoryStub{consumed: PasswordResetToken{UserID: 42, Token: token, ExpiresAt: 200}}, users: &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}}, sessions: &resetSessionRepositoryStub{revokeErr: sessionErr}, expected: sessionErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sessions, err := NewSessionService(test.sessions, time.Hour)
			if err != nil {
				t.Fatalf("NewSessionService() error = %v, want nil", err)
			}
			consumer, err := NewPasswordResetConsumer(test.users, test.tokens, signupHasherStub{}, sessions)
			if err != nil {
				t.Fatalf("NewPasswordResetConsumer() error = %v, want nil", err)
			}
			consumer.now = func() time.Time { return time.Unix(100, 0) }
			if err := consumer.Redeem(context.Background(), token, "new hunter42"); !errors.Is(err, test.expected) {
				t.Fatalf("Redeem() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

type resetSessionRepositoryStub struct {
	revokeErr error
}

func (r *resetSessionRepositoryStub) CreateSession(context.Context, Session) error {
	return nil
}

func (r *resetSessionRepositoryStub) FindSession(context.Context, string) (Session, error) {
	return Session{}, ErrSessionNotFound
}

func (r *resetSessionRepositoryStub) RevokeSession(context.Context, string, int64) error {
	return nil
}

func (r *resetSessionRepositoryStub) RevokeUserSessions(context.Context, int64) error {
	return r.revokeErr
}
