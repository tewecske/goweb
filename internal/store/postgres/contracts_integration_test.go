//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
)

func TestPostgresRepositoryContractsExerciseAuthenticationAndGuestServices(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	users, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	sessionsRepository, err := NewSessionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := service.NewSessionService(sessionsRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := service.NewPasswordHasher(service.PasswordHashConfig{
		Memory: 8192, Time: 1, Threads: 1, SaltLength: 8, KeyLength: 16,
	})
	if err != nil {
		t.Fatal(err)
	}

	// M3: real user/session repositories through sign-up and sign-in services.
	signUp, err := service.NewSignUpService(users, hasher, sessions, false)
	if err != nil {
		t.Fatal(err)
	}
	signUpResult, err := signUp.SignUp(context.Background(), service.SignUpInput{
		Email: "contract@example.test", Password: "hunter42", Username: "contract-user",
	})
	if err != nil {
		t.Fatalf("SignUp() error = %v", err)
	}
	if signUpResult.User.PasswordHash != nil || signUpResult.User.ID <= 0 {
		t.Fatal("SignUp() returned credential data or no user ID")
	}
	attempts := &contractAttemptState{}
	signIn, err := service.NewSignInService(users, hasher, sessions, attempts, false)
	if err != nil {
		t.Fatal(err)
	}
	signInResult, err := signIn.SignIn(context.Background(), service.SignInInput{Identifier: "CONTRACT@EXAMPLE.TEST", Password: "hunter42"})
	if err != nil {
		t.Fatalf("SignIn() error = %v", err)
	}
	if signInResult.User.ID != signUpResult.User.ID || signInResult.Session.UserID != signUpResult.User.ID || signInResult.User.PasswordHash != nil {
		t.Fatal("SignIn() did not resolve the persisted account")
	}

	// M4: confirmation and password recovery use real token/session/user stores.
	confirmationTokens, err := NewEmailConfirmationTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	mail := &contractMailSender{}
	publicURL, err := url.Parse("https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := service.NewEmailConfirmationService(users, confirmationTokens, mail, *publicURL, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmation.Issue(context.Background(), signUpResult.User.ID); err != nil {
		t.Fatalf("confirmation Issue() error = %v", err)
	}
	confirmationToken := readStoredToken(t, harness.DB, "email_verification_tokens", signUpResult.User.ID)
	if len(mail.mails) != 1 || !strings.Contains(mail.mails[0].TextBody, confirmationToken) {
		t.Fatal("confirmation mail did not contain issued token")
	}
	if err := confirmation.Confirm(context.Background(), confirmationToken); err != nil {
		t.Fatalf("confirmation Confirm() error = %v", err)
	}
	confirmed, err := users.FindUserByID(context.Background(), signUpResult.User.ID)
	if err != nil || confirmed.EmailVerifiedAt == nil {
		t.Fatalf("confirmed user = verified %v/error %v", confirmed.EmailVerifiedAt, err)
	}

	resetTokens, err := NewPasswordResetTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := service.NewRateLimiter(service.RateLimitConfig{Limit: 5, Window: time.Minute, MaxKeys: 10})
	if err != nil {
		t.Fatal(err)
	}
	reset, err := service.NewPasswordResetService(users, resetTokens, mail, limiter, *publicURL, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := reset.Request(context.Background(), "contract@example.test"); err != nil {
		t.Fatalf("password reset Request() error = %v", err)
	}
	resetToken := readStoredToken(t, harness.DB, "password_reset_tokens", signUpResult.User.ID)
	if len(mail.mails) != 2 || !strings.Contains(mail.mails[1].TextBody, resetToken) {
		t.Fatal("password reset mail did not contain issued token")
	}
	consumer, err := service.NewPasswordResetConsumer(users, resetTokens, hasher, sessions)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Redeem(context.Background(), resetToken, "newhunter42"); err != nil {
		t.Fatalf("password reset Redeem() error = %v", err)
	}
	resetUser, err := users.FindUserByID(context.Background(), signUpResult.User.ID)
	if err != nil || resetUser.PasswordHash == nil {
		t.Fatalf("reset user hash missing/error = %v", err)
	}
	newPasswordMatches, err := hasher.Verify("newhunter42", *resetUser.PasswordHash)
	if err != nil || !newPasswordMatches {
		t.Fatalf("new password verification = %v/error %v", newPasswordMatches, err)
	}
	oldPasswordMatches, err := hasher.Verify("hunter42", *resetUser.PasswordHash)
	if err != nil || oldPasswordMatches {
		t.Fatalf("old password verification = %v/error %v", oldPasswordMatches, err)
	}
	if err := consumer.Redeem(context.Background(), resetToken, "another42"); !errors.Is(err, service.ErrInvalidPasswordResetToken) {
		t.Fatalf("reused reset token error = %v, want %v", err, service.ErrInvalidPasswordResetToken)
	}
	if _, err := sessions.Lookup(context.Background(), signUpResult.Session.ID); !errors.Is(err, service.ErrSessionRevoked) {
		t.Fatalf("old session lookup error = %v, want revoked", err)
	}

	// M5: real guest account, claim-code, session, upgrade, and revocation stores.
	guestSession, err := service.NewGuestSessionService(users, sessions)
	if err != nil {
		t.Fatal(err)
	}
	guestResult, err := guestSession.CreateWithTheme(context.Background(), "dark")
	if err != nil {
		t.Fatalf("guest CreateWithTheme() error = %v", err)
	}
	claims, err := NewGuestClaimCodeRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	claimService, err := service.NewGuestClaimService(users, claims)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := claimService.Issue(context.Background(), guestResult.User.ID)
	if err != nil {
		t.Fatalf("guest claim Issue() error = %v", err)
	}
	redemption, err := service.NewGuestRedemptionService(users, claims, sessions)
	if err != nil {
		t.Fatal(err)
	}
	secondDevice, err := redemption.Redeem(context.Background(), claim.Code)
	if err != nil {
		t.Fatalf("guest claim Redeem() error = %v", err)
	}
	if secondDevice.User.ID != guestResult.User.ID || secondDevice.User.Theme != "dark" {
		t.Fatal("guest redemption did not preserve account identity and theme")
	}
	upgrade, err := service.NewGuestUpgradeService(users, hasher, claims)
	if err != nil {
		t.Fatal(err)
	}
	upgraded, err := upgrade.Upgrade(context.Background(), guestResult.User.ID, service.GuestUpgradeInput{Email: "upgraded@example.test", Password: "upgrade42"})
	if err != nil {
		t.Fatalf("guest Upgrade() error = %v", err)
	}
	if upgraded.ID != guestResult.User.ID || upgraded.IsGuest || upgraded.PasswordHash != nil {
		t.Fatal("guest upgrade changed account identity incorrectly")
	}
	if _, err := claims.FindGuestClaimCodeByCode(context.Background(), claim.Code); !errors.Is(err, service.ErrGuestClaimCodeNotFound) {
		t.Fatalf("upgraded guest claim lookup error = %v, want not found", err)
	}
}

func TestPostgresRepositoryContractsDoNotExposeBearerValuesInErrors(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	sessions, err := NewSessionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	userID := insertTokenUser(t, harness.DB, "secret-contract@example.test")
	secretSessionID := "session-secret-contract-value"
	if err := sessions.CreateSession(context.Background(), service.Session{ID: secretSessionID, UserID: userID, CreatedAt: 100, ExpiresAt: 200}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.RevokeSession(context.Background(), "unknown-session-secret", 100); !errors.Is(err, service.ErrSessionNotFound) {
		t.Fatal(err)
	} else if strings.Contains(err.Error(), "unknown-session-secret") {
		t.Fatal("session error exposed bearer value")
	}

	claims, err := NewGuestClaimCodeRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	secretCode := "SECRET2345"
	if _, err := claims.FindGuestClaimCodeByCode(context.Background(), secretCode); !errors.Is(err, service.ErrGuestClaimCodeNotFound) {
		t.Fatal(err)
	} else if strings.Contains(err.Error(), secretCode) {
		t.Fatal("claim error exposed bearer value")
	}
}

type contractMailSender struct {
	mails []service.Mail
}

func (s *contractMailSender) Send(_ context.Context, mail service.Mail) error {
	s.mails = append(s.mails, mail)
	return nil
}

type contractAttemptState struct{}

func (contractAttemptState) Clear(context.Context, string) error { return nil }

func readStoredToken(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, table string, userID int64) string {
	t.Helper()
	var token string
	if err := db.QueryRowContext(context.Background(), "SELECT token FROM "+table+" WHERE user_id = $1 ORDER BY id DESC LIMIT 1", userID).Scan(&token); err != nil {
		t.Fatalf("read stored token: %v", err)
	}
	return token
}
