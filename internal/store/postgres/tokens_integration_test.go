//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/tewecske/goweb/internal/service"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestEmailConfirmationTokensConsumeOnceAndRejectInactive(t *testing.T) {
	harness := newTokenRepositoryHarness(t)
	userID := insertTokenUser(t, harness.DB, "confirmation@example.test")
	repository, err := NewEmailConfirmationTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	token := service.EmailConfirmationToken{UserID: userID, Token: "confirmation-token", CreatedAt: 100, ExpiresAt: 200}
	if err := repository.CreateEmailConfirmationToken(context.Background(), token); err != nil {
		t.Fatalf("CreateEmailConfirmationToken() error = %v", err)
	}
	consumed, err := repository.ConsumeEmailConfirmationToken(context.Background(), token.Token, 150)
	if err != nil {
		t.Fatalf("ConsumeEmailConfirmationToken() error = %v", err)
	}
	if consumed.UserID != userID || consumed.ConsumedAt != nil {
		t.Fatalf("consumed token metadata = user %d/timestamp %v, want user %d/pre-consumption", consumed.UserID, consumed.ConsumedAt, userID)
	}
	var consumedAt sql.NullInt64
	if err := harness.DB.QueryRowContext(context.Background(), "SELECT consumed_at FROM email_verification_tokens WHERE token = $1", token.Token).Scan(&consumedAt); err != nil {
		t.Fatal(err)
	}
	if !consumedAt.Valid || consumedAt.Int64 != 150 {
		t.Fatalf("stored consumed timestamp = %v, want 150", consumedAt)
	}
	if _, err := repository.ConsumeEmailConfirmationToken(context.Background(), token.Token, 151); !errors.Is(err, service.ErrEmailConfirmationTokenNotFound) {
		t.Fatalf("reused token error = %v, want %v", err, service.ErrEmailConfirmationTokenNotFound)
	}
	if _, err := repository.ConsumeEmailConfirmationToken(context.Background(), "unknown-token", 150); !errors.Is(err, service.ErrEmailConfirmationTokenNotFound) {
		t.Fatalf("unknown token error = %v, want %v", err, service.ErrEmailConfirmationTokenNotFound)
	}
	if err := repository.CreateEmailConfirmationToken(context.Background(), token); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate token error = %v, want %v", err, ErrConflict)
	}

	expired := token
	expired.Token = "expired-confirmation"
	if err := repository.CreateEmailConfirmationToken(context.Background(), expired); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	if _, err := repository.ConsumeEmailConfirmationToken(context.Background(), expired.Token, expired.ExpiresAt); !errors.Is(err, service.ErrEmailConfirmationTokenNotFound) {
		t.Fatalf("expired token error = %v, want %v", err, service.ErrEmailConfirmationTokenNotFound)
	}
}

func TestPasswordResetTokensConsumeOnceAndRejectInactive(t *testing.T) {
	harness := newTokenRepositoryHarness(t)
	userID := insertTokenUser(t, harness.DB, "reset@example.test")
	repository, err := NewPasswordResetTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	token := service.PasswordResetToken{UserID: userID, Token: "reset-token", CreatedAt: 100, ExpiresAt: 200}
	if err := repository.CreatePasswordResetToken(context.Background(), token); err != nil {
		t.Fatalf("CreatePasswordResetToken() error = %v", err)
	}
	consumed, err := repository.ConsumePasswordResetToken(context.Background(), token.Token, 150)
	if err != nil {
		t.Fatalf("ConsumePasswordResetToken() error = %v", err)
	}
	if consumed.UserID != userID || consumed.ConsumedAt != nil {
		t.Fatalf("consumed token metadata = user %d/timestamp %v, want user %d/pre-consumption", consumed.UserID, consumed.ConsumedAt, userID)
	}
	var consumedAt sql.NullInt64
	if err := harness.DB.QueryRowContext(context.Background(), "SELECT consumed_at FROM password_reset_tokens WHERE token = $1", token.Token).Scan(&consumedAt); err != nil {
		t.Fatal(err)
	}
	if !consumedAt.Valid || consumedAt.Int64 != 150 {
		t.Fatalf("stored consumed timestamp = %v, want 150", consumedAt)
	}
	if _, err := repository.ConsumePasswordResetToken(context.Background(), token.Token, 151); !errors.Is(err, service.ErrPasswordResetTokenNotFound) {
		t.Fatalf("reused token error = %v, want %v", err, service.ErrPasswordResetTokenNotFound)
	}
	if _, err := repository.ConsumePasswordResetToken(context.Background(), "unknown-reset", 150); !errors.Is(err, service.ErrPasswordResetTokenNotFound) {
		t.Fatalf("unknown token error = %v, want %v", err, service.ErrPasswordResetTokenNotFound)
	}
	expired := token
	expired.Token = "expired-reset"
	if err := repository.CreatePasswordResetToken(context.Background(), expired); err != nil {
		t.Fatalf("create expired reset token: %v", err)
	}
	if _, err := repository.ConsumePasswordResetToken(context.Background(), expired.Token, expired.ExpiresAt); !errors.Is(err, service.ErrPasswordResetTokenNotFound) {
		t.Fatalf("expired reset token error = %v, want %v", err, service.ErrPasswordResetTokenNotFound)
	}
}

func TestEmailConfirmationTokenConsumptionAllowsOneConcurrentWinner(t *testing.T) {
	harness := newTokenRepositoryHarness(t)
	userID := insertTokenUser(t, harness.DB, "concurrent@example.test")
	repository, err := NewEmailConfirmationTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	token := service.EmailConfirmationToken{UserID: userID, Token: "concurrent-confirmation", CreatedAt: 100, ExpiresAt: 200}
	if err := repository.CreateEmailConfirmationToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	results := make(chan error, 2)
	for timestamp := int64(150); timestamp <= 151; timestamp++ {
		wait.Add(1)
		go func(now int64) {
			defer wait.Done()
			_, consumeErr := repository.ConsumeEmailConfirmationToken(context.Background(), token.Token, now)
			results <- consumeErr
		}(timestamp)
	}
	wait.Wait()
	close(results)

	var successes, notFound int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, service.ErrEmailConfirmationTokenNotFound):
			notFound++
		default:
			t.Fatalf("concurrent consume error = %v", err)
		}
	}
	if successes != 1 || notFound != 1 {
		t.Fatalf("concurrent consume results = successes %d, not found %d, want 1/1", successes, notFound)
	}
}

func TestPasswordResetTokenConsumptionAllowsOneConcurrentWinner(t *testing.T) {
	harness := newTokenRepositoryHarness(t)
	userID := insertTokenUser(t, harness.DB, "concurrent-reset@example.test")
	repository, err := NewPasswordResetTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	token := service.PasswordResetToken{UserID: userID, Token: "concurrent-reset", CreatedAt: 100, ExpiresAt: 200}
	if err := repository.CreatePasswordResetToken(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	results := make(chan error, 2)
	for timestamp := int64(150); timestamp <= 151; timestamp++ {
		wait.Add(1)
		go func(now int64) {
			defer wait.Done()
			_, consumeErr := repository.ConsumePasswordResetToken(context.Background(), token.Token, now)
			results <- consumeErr
		}(timestamp)
	}
	wait.Wait()
	close(results)

	var successes, notFound int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, service.ErrPasswordResetTokenNotFound):
			notFound++
		default:
			t.Fatalf("concurrent consume error = %v", err)
		}
	}
	if successes != 1 || notFound != 1 {
		t.Fatalf("concurrent consume results = successes %d, not found %d, want 1/1", successes, notFound)
	}
}

func TestTokenDeletionCascadesWithUserDeletion(t *testing.T) {
	harness := newTokenRepositoryHarness(t)
	userID := insertTokenUser(t, harness.DB, "cascade@example.test")
	ctx := context.Background()
	if _, err := harness.DB.ExecContext(ctx, "INSERT INTO email_verification_tokens (user_id, token, created_at, expires_at) VALUES ($1, 'cascade-confirmation', 100, 200)", userID); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, "INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at) VALUES ($1, 'cascade-reset', 100, 200)", userID); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, "DELETE FROM users WHERE id = $1", userID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"email_verification_tokens", "password_reset_tokens"} {
		var count int
		if err := harness.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE user_id = $1", userID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s count = %d, want 0", table, count)
		}
	}
}

func TestTokenRepositoriesPropagateCancellation(t *testing.T) {
	harness := newTokenRepositoryHarness(t)
	confirmation, err := NewEmailConfirmationTokenRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := confirmation.ConsumeEmailConfirmationToken(ctx, "cancelled-token", 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("confirmation canceled error = %v, want %v", err, context.Canceled)
	}
}

func newTokenRepositoryHarness(t *testing.T) *testpostgres.Harness {
	t.Helper()
	harness := newUserRepositoryHarness(t)
	return harness
}

func insertTokenUser(t *testing.T, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, email string) int64 {
	t.Helper()
	var userID int64
	if err := db.QueryRowContext(context.Background(), "INSERT INTO users (email, theme, locale, created_at) VALUES ($1, 'light', 'en', 100) RETURNING id", email).Scan(&userID); err != nil {
		t.Fatalf("insert token user: %v", err)
	}
	return userID
}
