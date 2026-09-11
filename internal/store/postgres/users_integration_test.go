//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestUserRepositoryRoundTripsNullableAndGeneratedFields(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	repository, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}

	email := "user@example.test"
	hash := "argon2id-hash"
	username := "user-name"
	created, err := repository.CreateUser(context.Background(), service.User{
		Email:        &email,
		PasswordHash: &hash,
		Username:     &username,
		IsAdmin:      true,
		CreatedAt:    100,
		Version:      0,
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if created.ID <= 0 || created.Version != 0 {
		t.Fatalf("CreateUser() = %#v, want generated ID and version 0", created)
	}
	if created.DisplayName != nil || created.EmailVerifiedAt != nil {
		t.Fatalf("CreateUser() nullable fields = %#v, want nils", created)
	}

	byEmail, err := repository.FindUserByEmail(context.Background(), " USER@EXAMPLE.TEST ")
	if err != nil {
		t.Fatalf("FindUserByEmail() error = %v", err)
	}
	if byEmail.ID != created.ID || byEmail.PasswordHash == nil || *byEmail.PasswordHash != hash {
		t.Fatalf("FindUserByEmail() = %#v, want persisted user", byEmail)
	}
	byUsername, err := repository.FindUserByUsername(context.Background(), " USER-NAME ")
	if err != nil {
		t.Fatalf("FindUserByUsername() error = %v", err)
	}
	if byUsername.ID != created.ID {
		t.Fatalf("FindUserByUsername().ID = %d, want %d", byUsername.ID, created.ID)
	}
}

func TestUserRepositoryMapsDuplicatesAndMissingRows(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	repository, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	first := service.User{Email: stringPointer("duplicate@example.test"), Username: stringPointer("duplicate"), Theme: "light", Locale: "en", CreatedAt: 100}
	created, err := repository.CreateUser(context.Background(), first)
	if err != nil {
		t.Fatalf("CreateUser(first) error = %v", err)
	}

	_, err = repository.CreateUser(context.Background(), service.User{Email: stringPointer("duplicate@example.test"), Theme: "light", Locale: "en", CreatedAt: 101})
	if !errors.Is(err, service.ErrDuplicateEmail) {
		t.Fatalf("duplicate email error = %v, want %v", err, service.ErrDuplicateEmail)
	}
	_, err = repository.CreateUser(context.Background(), service.User{Username: stringPointer("duplicate"), Theme: "light", Locale: "en", CreatedAt: 102})
	if !errors.Is(err, service.ErrDuplicateUsername) {
		t.Fatalf("duplicate username error = %v, want %v", err, service.ErrDuplicateUsername)
	}
	if _, err := repository.FindUserByID(context.Background(), created.ID+1_000_000); !errors.Is(err, service.ErrUserNotFound) {
		t.Fatalf("missing FindUserByID() error = %v, want %v", err, service.ErrUserNotFound)
	}
}

func TestUserRepositoryOptimisticLockingDistinguishesConflictAndMissing(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	repository, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	created, err := repository.CreateUser(context.Background(), service.User{Email: stringPointer("lock@example.test"), Theme: "light", Locale: "en", CreatedAt: 100})
	if err != nil {
		t.Fatal(err)
	}

	updatedInput := created
	updatedInput.Theme = "dark"
	updatedInput.CreatedAt = 999
	updated, err := repository.UpdateUser(context.Background(), updatedInput, created.Version)
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	if updated.Version != created.Version+1 || updated.Theme != "dark" || updated.CreatedAt != created.CreatedAt {
		t.Fatalf("UpdateUser() = %#v, want incremented dark revision", updated)
	}

	stale := updated
	stale.Theme = "light"
	if _, err := repository.UpdateUser(context.Background(), stale, created.Version); !errors.Is(err, service.ErrOptimisticLockConflict) {
		t.Fatalf("stale UpdateUser() error = %v, want %v", err, service.ErrOptimisticLockConflict)
	}
	current, err := repository.FindUserByID(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Theme != "dark" || current.Version != updated.Version {
		t.Fatalf("stale update changed row: %#v", current)
	}

	if err := repository.DeleteUser(context.Background(), created.ID, created.Version); !errors.Is(err, service.ErrOptimisticLockConflict) {
		t.Fatalf("stale DeleteUser() error = %v, want %v", err, service.ErrOptimisticLockConflict)
	}
	if err := repository.DeleteUser(context.Background(), created.ID, updated.Version); err != nil {
		t.Fatalf("current DeleteUser() error = %v", err)
	}
	if err := repository.DeleteUser(context.Background(), created.ID, updated.Version); !errors.Is(err, service.ErrUserNotFound) {
		t.Fatalf("missing DeleteUser() error = %v, want %v", err, service.ErrUserNotFound)
	}
	if _, err := repository.UpdateUser(context.Background(), updated, updated.Version); !errors.Is(err, service.ErrUserNotFound) {
		t.Fatalf("missing UpdateUser() error = %v, want %v", err, service.ErrUserNotFound)
	}
}

func TestUserRepositoryDeleteHonorsCascadeAndHistoricalReferences(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	repository, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	created, err := repository.CreateUser(context.Background(), service.User{Email: stringPointer("delete@example.test"), Theme: "light", Locale: "en", CreatedAt: 100})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dependentInserts := []struct {
		name  string
		query string
	}{
		{name: "session", query: "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES ('delete-session', $1, 100, 200)"},
		{name: "identity", query: "INSERT INTO oauth_identities (user_id, provider, subject, created_at) VALUES ($1, 'google', 'delete-subject', 100)"},
		{name: "confirmation", query: "INSERT INTO email_verification_tokens (user_id, token, created_at, expires_at) VALUES ($1, 'delete-confirmation', 100, 200)"},
		{name: "reset", query: "INSERT INTO password_reset_tokens (user_id, token, created_at, expires_at) VALUES ($1, 'delete-reset', 100, 200)"},
		{name: "claim", query: "INSERT INTO guest_claim_codes (user_id, code, created_at) VALUES ($1, 'delete-code', 100)"},
		{name: "login attempt", query: "INSERT INTO login_attempts (email, user_id, outcome, created_at) VALUES ('delete@example.test', $1, 'success', 100)"},
		{name: "audit", query: "INSERT INTO audit_log (occurred_at, actor_user_id, actor_email, action, ip) VALUES (100, $1, 'delete@example.test', 'test', '127.0.0.1')"},
		{name: "usage", query: "INSERT INTO usage_events (created_at, method, route, status, user_id) VALUES (100, 'GET', '/test', 200, $1)"},
	}
	for _, insert := range dependentInserts {
		if _, err := harness.DB.ExecContext(ctx, insert.query, created.ID); err != nil {
			t.Fatalf("insert %s: %v", insert.name, err)
		}
	}

	if err := repository.DeleteUser(ctx, created.ID, created.Version); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
	for _, table := range []string{"sessions", "oauth_identities", "email_verification_tokens", "password_reset_tokens", "guest_claim_codes"} {
		var count int
		if err := harness.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE user_id = $1", created.ID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s count = %d, want 0", table, count)
		}
	}
	historicalReferences := []struct {
		table  string
		column string
	}{
		{table: "login_attempts", column: "user_id"},
		{table: "audit_log", column: "actor_user_id"},
		{table: "usage_events", column: "user_id"},
	}
	for _, reference := range historicalReferences {
		var userID sql.NullInt64
		if err := harness.DB.QueryRowContext(ctx, "SELECT "+reference.column+" FROM "+reference.table+" LIMIT 1").Scan(&userID); err != nil {
			t.Fatalf("scan %s history: %v", reference.table, err)
		}
		if userID.Valid {
			t.Fatalf("%s %s = %d, want NULL", reference.table, reference.column, userID.Int64)
		}
	}
}

func TestUserRepositoryPropagatesCancellation(t *testing.T) {
	harness := newUserRepositoryHarness(t)
	repository, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.FindUserByID(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("FindUserByID(canceled) error = %v, want %v", err, context.Canceled)
	}
}

func newUserRepositoryHarness(t *testing.T) *testpostgres.Harness {
	t.Helper()
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
	return harness
}

func stringPointer(value string) *string {
	return &value
}
