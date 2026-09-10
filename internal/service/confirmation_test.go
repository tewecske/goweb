package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEmailConfirmationServiceIssue(t *testing.T) {
	users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer(" User@Example.COM ")}}
	tokens := &confirmationTokenRepositoryStub{}
	mailer := &confirmationMailSenderStub{}
	service, err := NewEmailConfirmationService(users, tokens, mailer, confirmationURL(t), 2*time.Hour)
	if err != nil {
		t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
	}
	service.now = func() time.Time { return time.Unix(100, 0) }

	if err := service.Issue(context.Background(), 42); err != nil {
		t.Fatalf("Issue() error = %v, want nil", err)
	}
	if tokens.created.UserID != 42 || tokens.created.CreatedAt != 100 || tokens.created.ExpiresAt != 7_300 {
		t.Fatalf("created token = %#v, want user 42 and 100..7300", tokens.created)
	}
	if len(tokens.created.Token) != maxConfirmationTokenLength {
		t.Fatalf("token length = %d, want %d", len(tokens.created.Token), maxConfirmationTokenLength)
	}
	if len(mailer.messages) != 1 {
		t.Fatalf("mail count = %d, want 1", len(mailer.messages))
	}
	message := mailer.messages[0]
	if message.To != "user@example.com" {
		t.Errorf("mail recipient = %q, want normalized email", message.To)
	}
	if !strings.Contains(message.TextBody, "https://example.test/app/confirm-email?token=") || !strings.Contains(message.TextBody, tokens.created.Token) {
		t.Errorf("mail body does not contain confirmation link: %q", message.TextBody)
	}
}

func TestEmailConfirmationServiceIssueGeneratesDistinctTokens(t *testing.T) {
	users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}}
	tokens := &confirmationTokenRepositoryStub{}
	mailer := &confirmationMailSenderStub{}
	service, err := NewEmailConfirmationService(users, tokens, mailer, confirmationURL(t), time.Hour)
	if err != nil {
		t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
	}

	for range 2 {
		if err := service.Issue(context.Background(), 42); err != nil {
			t.Fatalf("Issue() error = %v, want nil", err)
		}
	}
	if tokens.created.Token == tokens.previous.Token {
		t.Fatal("consecutive confirmation tokens are identical")
	}
}

func TestEmailConfirmationServiceIssueRejectsInvalidUsers(t *testing.T) {
	tests := []struct {
		name string
		user User
	}{
		{name: "guest", user: User{ID: 42, IsGuest: true, Email: stringPointer("user@example.com")}},
		{name: "missing email", user: User{ID: 42}},
		{name: "invalid email", user: User{ID: 42, Email: stringPointer("not-an-email")}},
		{name: "wrong returned id", user: User{ID: 99, Email: stringPointer("user@example.com")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokens := &confirmationTokenRepositoryStub{}
			mailer := &confirmationMailSenderStub{}
			service, err := NewEmailConfirmationService(
				&confirmationUserRepositoryStub{user: test.user}, tokens, mailer, confirmationURL(t), time.Hour,
			)
			if err != nil {
				t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
			}
			if err := service.Issue(context.Background(), 42); !errors.Is(err, ErrInvalidConfirmationUser) {
				t.Fatalf("Issue() error = %v, want ErrInvalidConfirmationUser", err)
			}
			if tokens.calls != 0 || len(mailer.messages) != 0 {
				t.Fatal("invalid confirmation user caused token or mail delivery")
			}
		})
	}
}

func TestEmailConfirmationServiceIssuePropagatesFailuresWithoutToken(t *testing.T) {
	repositoryErr := errors.New("token store unavailable")
	mailErr := errors.New("mail transport unavailable")
	tests := []struct {
		name     string
		tokens   *confirmationTokenRepositoryStub
		mailer   *confirmationMailSenderStub
		expected error
		wantMail bool
	}{
		{name: "token repository", tokens: &confirmationTokenRepositoryStub{err: repositoryErr}, mailer: &confirmationMailSenderStub{}, expected: repositoryErr},
		{name: "mail sender", tokens: &confirmationTokenRepositoryStub{}, mailer: &confirmationMailSenderStub{err: mailErr}, expected: mailErr, wantMail: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewEmailConfirmationService(
				&confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}},
				test.tokens, test.mailer, confirmationURL(t), time.Hour,
			)
			if err != nil {
				t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
			}
			issueErr := service.Issue(context.Background(), 42)
			if !errors.Is(issueErr, test.expected) {
				t.Fatalf("Issue() error = %v, want errors.Is(_, %v)", issueErr, test.expected)
			}
			if test.tokens.created.Token != "" && strings.Contains(issueErr.Error(), test.tokens.created.Token) {
				t.Error("Issue() error exposes confirmation token")
			}
			if len(test.mailer.messages) != 0 && !test.wantMail {
				t.Error("mail sender was called after token persistence failure")
			}
		})
	}
}

func TestNewEmailConfirmationServiceRejectsInvalidConfiguration(t *testing.T) {
	users := &confirmationUserRepositoryStub{}
	tokens := &confirmationTokenRepositoryStub{}
	mailer := &confirmationMailSenderStub{}
	validURL := confirmationURL(t)
	tests := []struct {
		name      string
		usersNil  bool
		tokensNil bool
		mailerNil bool
		publicURL url.URL
		lifetime  time.Duration
	}{
		{name: "nil users", usersNil: true, publicURL: validURL, lifetime: time.Hour},
		{name: "nil tokens", tokensNil: true, publicURL: validURL, lifetime: time.Hour},
		{name: "nil mailer", mailerNil: true, publicURL: validURL, lifetime: time.Hour},
		{name: "invalid scheme", publicURL: url.URL{Host: "example.test"}, lifetime: time.Hour},
		{name: "query in url", publicURL: url.URL{Scheme: "https", Host: "example.test", RawQuery: "x=1"}, lifetime: time.Hour},
		{name: "short lifetime", publicURL: validURL, lifetime: time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testUsers UserRepository = users
			var testTokens EmailConfirmationTokenRepository = tokens
			var testMailer MailSender = mailer
			if test.usersNil {
				testUsers = nil
			}
			if test.tokensNil {
				testTokens = nil
			}
			if test.mailerNil {
				testMailer = nil
			}
			if _, err := NewEmailConfirmationService(testUsers, testTokens, testMailer, test.publicURL, test.lifetime); !errors.Is(err, ErrInvalidConfirmationConfig) {
				t.Fatalf("NewEmailConfirmationService() error = %v, want ErrInvalidConfirmationConfig", err)
			}
		})
	}
}

func TestEmailConfirmationServiceIssueRejectsNilContext(t *testing.T) {
	service, err := NewEmailConfirmationService(
		&confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}},
		&confirmationTokenRepositoryStub{}, &confirmationMailSenderStub{}, confirmationURL(t), time.Hour,
	)
	if err != nil {
		t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
	}
	if err := service.Issue(nil, 42); err == nil {
		t.Fatal("Issue(nil context) error = nil, want error")
	}
}

func TestEmailConfirmationServiceConfirmMarksEmailVerified(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com"), Version: 3}}
	tokens := &confirmationTokenRepositoryStub{consumed: EmailConfirmationToken{
		UserID: 42, Token: token, CreatedAt: 90, ExpiresAt: 200,
	}}
	service, err := NewEmailConfirmationService(
		users, tokens, &confirmationMailSenderStub{}, confirmationURL(t), time.Hour,
	)
	if err != nil {
		t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
	}
	service.now = func() time.Time { return time.Unix(100, 0) }

	if err := service.Confirm(context.Background(), token); err != nil {
		t.Fatalf("Confirm() error = %v, want nil", err)
	}
	if tokens.consumedToken != token || tokens.consumedAt != 100 {
		t.Errorf("consumed token/time = %q/%d, want %q/100", tokens.consumedToken, tokens.consumedAt, token)
	}
	if users.updated.EmailVerifiedAt == nil || *users.updated.EmailVerifiedAt != 100 {
		t.Errorf("verified at = %v, want 100", users.updated.EmailVerifiedAt)
	}
	if users.updateExpectedVersion != 3 {
		t.Errorf("expected user version = %d, want 3", users.updateExpectedVersion)
	}
}

func TestEmailConfirmationServiceConfirmUsesUniformTokenFailure(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		rawToken   string
		consumeErr error
		consumed   EmailConfirmationToken
	}{
		{name: "malformed", rawToken: "not-a-token"},
		{name: "unknown", rawToken: token, consumeErr: ErrEmailConfirmationTokenNotFound},
		{name: "expired", rawToken: token, consumed: EmailConfirmationToken{UserID: 42, Token: token, ExpiresAt: 100}},
		{name: "already used", rawToken: token, consumed: EmailConfirmationToken{UserID: 42, Token: token, ExpiresAt: 200, ConsumedAt: int64Pointer(90)}},
		{name: "wrong token returned", rawToken: token, consumed: EmailConfirmationToken{UserID: 42, Token: "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", ExpiresAt: 200}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users := &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com")}}
			tokens := &confirmationTokenRepositoryStub{consumeErr: test.consumeErr, consumed: test.consumed}
			service, err := NewEmailConfirmationService(
				users, tokens, &confirmationMailSenderStub{}, confirmationURL(t), time.Hour,
			)
			if err != nil {
				t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
			}
			service.now = func() time.Time { return time.Unix(100, 0) }
			if err := service.Confirm(context.Background(), test.rawToken); !errors.Is(err, ErrInvalidConfirmationToken) {
				t.Fatalf("Confirm() error = %v, want ErrInvalidConfirmationToken", err)
			}
			if users.updateCalls != 0 {
				t.Error("invalid confirmation updated user")
			}
		})
	}
}

func TestEmailConfirmationServiceConfirmPropagatesOperationalFailures(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	repositoryErr := errors.New("confirmation store unavailable")
	userErr := errors.New("user store unavailable")
	updateErr := errors.New("user update unavailable")
	tests := []struct {
		name     string
		tokens   *confirmationTokenRepositoryStub
		users    *confirmationUserRepositoryStub
		expected error
	}{
		{name: "token store", tokens: &confirmationTokenRepositoryStub{consumeErr: repositoryErr}, users: &confirmationUserRepositoryStub{}, expected: repositoryErr},
		{name: "user lookup", tokens: &confirmationTokenRepositoryStub{consumed: EmailConfirmationToken{UserID: 42, Token: token, ExpiresAt: 200}}, users: &confirmationUserRepositoryStub{findErr: userErr}, expected: userErr},
		{name: "user update", tokens: &confirmationTokenRepositoryStub{consumed: EmailConfirmationToken{UserID: 42, Token: token, ExpiresAt: 200}}, users: &confirmationUserRepositoryStub{user: User{ID: 42, Email: stringPointer("user@example.com"), Version: 1}, updateErr: updateErr}, expected: updateErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewEmailConfirmationService(test.users, test.tokens, &confirmationMailSenderStub{}, confirmationURL(t), time.Hour)
			if err != nil {
				t.Fatalf("NewEmailConfirmationService() error = %v, want nil", err)
			}
			service.now = func() time.Time { return time.Unix(100, 0) }
			if err := service.Confirm(context.Background(), token); !errors.Is(err, test.expected) {
				t.Fatalf("Confirm() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
		})
	}
}

func confirmationURL(t *testing.T) url.URL {
	t.Helper()
	parsed, err := url.Parse("https://example.test/app")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	return *parsed
}

type confirmationUserRepositoryStub struct {
	user                  User
	findErr               error
	updated               User
	updateExpectedVersion int64
	updateErr             error
	updateCalls           int
}

func (r *confirmationUserRepositoryStub) CreateUser(context.Context, User) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *confirmationUserRepositoryStub) FindUserByID(context.Context, int64) (User, error) {
	if r.findErr != nil {
		return User{}, r.findErr
	}
	return r.user, nil
}

func (r *confirmationUserRepositoryStub) FindUserByEmail(context.Context, string) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *confirmationUserRepositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	return User{}, ErrUserNotFound
}

func (r *confirmationUserRepositoryStub) UpdateUser(_ context.Context, user User, expectedVersion int64) (User, error) {
	r.updateCalls++
	r.updateExpectedVersion = expectedVersion
	if r.updateErr != nil {
		return User{}, r.updateErr
	}
	r.updated = user
	r.updated.Version++
	return r.updated, nil
}

func (r *confirmationUserRepositoryStub) DeleteUser(context.Context, int64, int64) error {
	return ErrUserNotFound
}

type confirmationTokenRepositoryStub struct {
	created       EmailConfirmationToken
	previous      EmailConfirmationToken
	consumed      EmailConfirmationToken
	consumedToken string
	consumedAt    int64
	consumeErr    error
	err           error
	calls         int
}

func (r *confirmationTokenRepositoryStub) CreateEmailConfirmationToken(_ context.Context, token EmailConfirmationToken) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.previous = r.created
	r.created = token
	return nil
}

func (r *confirmationTokenRepositoryStub) ConsumeEmailConfirmationToken(_ context.Context, token string, now int64) (EmailConfirmationToken, error) {
	r.consumedToken = token
	r.consumedAt = now
	if r.consumeErr != nil {
		return EmailConfirmationToken{}, r.consumeErr
	}
	return r.consumed, nil
}

type confirmationMailSenderStub struct {
	messages []Mail
	err      error
}

func (s *confirmationMailSenderStub) Send(_ context.Context, message Mail) error {
	if s.err != nil {
		return s.err
	}
	s.messages = append(s.messages, message)
	return nil
}

func int64Pointer(value int64) *int64 {
	return &value
}
