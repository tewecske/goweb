//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
	testfixtures "github.com/tewecske/goweb/tests/fixtures"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestDatastoreStatsRepositoryCountsSafely(t *testing.T) {
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

	confirmed := int64(100)
	passwordHash := "fixture-hash"
	guestFixture := testfixtures.NewUser()
	guestFixture.Email = nil
	guestFixture.Username = nil
	guestFixture.IsGuest = true
	if _, err := testfixtures.InsertUser(ctx, harness.DB, guestFixture); err != nil {
		t.Fatal(err)
	}
	adminFixture := testfixtures.NewUser()
	adminFixture.Email = testfixtures.String("admin@example.test")
	adminFixture.Username = testfixtures.String("admin-account")
	adminFixture.PasswordHash = &passwordHash
	adminFixture.IsAdmin = true
	adminFixture.EmailVerifiedAt = &confirmed
	if _, err := testfixtures.InsertUser(ctx, harness.DB, adminFixture); err != nil {
		t.Fatal(err)
	}
	unconfirmedFixture := testfixtures.NewUser()
	unconfirmedFixture.Email = testfixtures.String("unconfirmed@example.test")
	unconfirmedFixture.Username = testfixtures.String("unconfirmed-account")
	if _, err := testfixtures.InsertUser(ctx, harness.DB, unconfirmedFixture); err != nil {
		t.Fatal(err)
	}
	confirmedFixture := testfixtures.NewUser()
	confirmedFixture.Email = testfixtures.String("confirmed@example.test")
	confirmedFixture.Username = testfixtures.String("confirmed-account")
	confirmedFixture.PasswordHash = &passwordHash
	confirmedFixture.EmailVerifiedAt = &confirmed
	if _, err := testfixtures.InsertUser(ctx, harness.DB, confirmedFixture); err != nil {
		t.Fatal(err)
	}

	now := int64(1_000_000)
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, created_at, expires_at, revoked_at)
		VALUES
			('active-session', 1, 1, $1, NULL),
			('expired-session', 1, 1, 100, NULL),
			('revoked-session', 1, 1, $1, 50)
	`, now+10_000); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO email_verification_tokens (user_id, token, created_at, expires_at, consumed_at)
		VALUES (1, 'pending-email', 1, 100, NULL)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at, consumed_at)
		VALUES (1, 'pending-reset', 1, 100, NULL)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO oauth_states (state, provider, action, user_id, created_at, expires_at, consumed_at)
		VALUES ('pending-state', 'example', 'sign-in', NULL, 1, 100, NULL)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.DB.ExecContext(ctx, `
		INSERT INTO login_attempts (email, user_id, ip, outcome, created_at)
		VALUES
			('a@example.test', NULL, NULL, $1, $2),
			('b@example.test', NULL, NULL, $1, $3)
	`, service.LoginOutcomeInvalidCredentials, now, now-50); err != nil {
		t.Fatal(err)
	}

	repository, err := NewDatastoreStatsRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := repository.CountAccounts(ctx)
	if err != nil {
		t.Fatalf("CountAccounts() error = %v", err)
	}
	if accounts.Total != 4 || accounts.Guests != 1 || accounts.Administrators != 1 || accounts.Unconfirmed != 1 || accounts.WithoutPassword != 2 {
		t.Fatalf("accounts = %+v, want total 4 guests 1 admins 1 unconfirmed 1 no-password 2", accounts)
	}
	active, err := repository.CountActiveSessions(ctx, now)
	if err != nil || active != 1 {
		t.Fatalf("active sessions = %d, %v; want 1", active, err)
	}
	expired, err := repository.CountExpiredSessions(ctx, now)
	if err != nil || expired != 2 {
		t.Fatalf("expired sessions = %d, %v; want 2", expired, err)
	}
	for name, count := range map[string]func(context.Context, int64) (int, error){
		"email":  repository.CountExpiredEmailTokens,
		"reset":  repository.CountExpiredPasswordResetTokens,
		"states": repository.CountExpiredOAuthStates,
	} {
		got, err := count(ctx, now)
		if err != nil || got != 1 {
			t.Fatalf("expired %s = %d, %v; want 1", name, got, err)
		}
	}
	failed, err := repository.CountRecentFailedSignIns(ctx, now-100)
	if err != nil || failed != 2 {
		t.Fatalf("recent failed sign-ins = %d, %v; want 2", failed, err)
	}
	recent, err := repository.CountRecentFailedSignIns(ctx, now)
	if err != nil || recent != 1 {
		t.Fatalf("recent failed sign-ins at now = %d, %v; want 1", recent, err)
	}
}
