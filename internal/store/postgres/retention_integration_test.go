//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
	testfixtures "github.com/tewecske/goweb/tests/fixtures"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestRetentionRepositoryRemovesOnlyEligibleRecords(t *testing.T) {
	harness := testpostgres.New(t)
	runner, err := store.NewMigrator(harness.DB, migrations.FS)
	if err != nil {
		t.Fatalf("NewMigrator() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runner.Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	userID, err := testfixtures.InsertUser(ctx, harness.DB, testfixtures.NewUser())
	if err != nil {
		t.Fatal(err)
	}

	now := int64(200_000)
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (user_id, token, created_at, expires_at, consumed_at)
		VALUES
			($1, 'expired-email', 1, 100, NULL),
			($1, 'consumed-email', 1, 999_999, 100),
			($1, 'valid-email', 1, 999_999, NULL)
	`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, consumed_at)
		VALUES
			($1, 'expired-reset', 1, 100, NULL),
			($1, 'valid-reset', 1, 999_999, NULL)
	`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO oauth_states (state, provider, action, user_id, created_at, expires_at, consumed_at)
		VALUES
			('expired-state', 'example', 'sign-in', NULL, 1, 100, NULL),
			('consumed-state', 'example', 'sign-in', NULL, 1, 999_999, 100),
			('valid-state', 'example', 'sign-in', NULL, 1, 999_999, NULL)
	`); err != nil {
		t.Fatal(err)
	}
	loginCutoff := int64(100_000)
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO login_attempts (email, user_id, ip, outcome, created_at)
		VALUES
			('old@example.test', NULL, NULL, 'invalid_credentials', 50),
			('new@example.test', NULL, NULL, 'invalid_credentials', 150_000)
	`); err != nil {
		t.Fatal(err)
	}
	usageCutoff := int64(120_000)
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO usage_events (created_at, method, route, status, user_id, ip)
		VALUES
			(50, 'GET', '/en/', 200, NULL, NULL),
			(150_000, 'GET', '/en/', 200, NULL, NULL)
	`); err != nil {
		t.Fatal(err)
	}

	repository, err := NewRetentionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}

	removed, err := repository.DeleteExpiredEmailConfirmationTokens(ctx, now)
	if err != nil || removed != 2 {
		t.Fatalf("email tokens removed = %d, err = %v; want 2", removed, err)
	}
	removed, err = repository.DeleteExpiredPasswordResetTokens(ctx, now)
	if err != nil || removed != 1 {
		t.Fatalf("reset tokens removed = %d, err = %v; want 1", removed, err)
	}
	removed, err = repository.DeleteExpiredOAuthStates(ctx, now)
	if err != nil || removed != 2 {
		t.Fatalf("oauth states removed = %d, err = %v; want 2", removed, err)
	}
	removed, err = repository.DeleteLoginAttemptsBefore(ctx, loginCutoff)
	if err != nil || removed != 1 {
		t.Fatalf("login attempts removed = %d, err = %v; want 1", removed, err)
	}
	removed, err = repository.DeleteUsageEventsBefore(ctx, usageCutoff)
	if err != nil || removed != 1 {
		t.Fatalf("usage events removed = %d, err = %v; want 1", removed, err)
	}

	assertRemainingRowCount(t, harness.DB, ctx, "email_verification_tokens", 1)
	assertRemainingRowCount(t, harness.DB, ctx, "password_reset_tokens", 1)
	assertRemainingRowCount(t, harness.DB, ctx, "oauth_states", 1)
	assertRemainingRowCount(t, harness.DB, ctx, "login_attempts", 1)
	assertRemainingRowCount(t, harness.DB, ctx, "usage_events", 1)

	// Running again is a no-op.
	if removed, err := repository.DeleteExpiredEmailConfirmationTokens(ctx, now); err != nil || removed != 0 {
		t.Fatalf("second email cleanup = %d, %v; want 0", removed, err)
	}
}

func TestRetentionServiceIntegrationAgainstPostgres(t *testing.T) {
	harness := testpostgres.New(t)
	runner, err := store.NewMigrator(harness.DB, migrations.FS)
	if err != nil {
		t.Fatalf("NewMigrator() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := runner.Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	repository, err := NewRetentionRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := service.NewRetentionService(repository, 24*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := retention.CleanupTokens(ctx); err != nil || removed != 0 {
		t.Fatalf("CleanupTokens() = %d, %v; want 0", removed, err)
	}
	if removed, err := retention.CleanupLoginAttempts(ctx); err != nil || removed != 0 {
		t.Fatalf("CleanupLoginAttempts() = %d, %v; want 0", removed, err)
	}
	if removed, err := retention.CleanupUsageEvents(ctx); err != nil || removed != 0 {
		t.Fatalf("CleanupUsageEvents() = %d, %v; want 0", removed, err)
	}
}

func assertRemainingRowCount(t *testing.T, db *sql.DB, ctx context.Context, table string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if count != want {
		t.Fatalf("%s rows = %d, want %d", table, count, want)
	}
}
