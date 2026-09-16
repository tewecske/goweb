//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestAuditLogRepositoryPreservesHistoryAfterActorDeletion(t *testing.T) {
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

	users, err := NewUserRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	email := "actor@example.test"
	actor, err := users.CreateUser(ctx, service.User{Email: &email, Theme: "light", Locale: "en", CreatedAt: 100})
	if err != nil {
		t.Fatal(err)
	}

	repository, err := NewAuditLogRepository(harness.DB)
	if err != nil {
		t.Fatal(err)
	}
	actorID := actor.ID
	actorEmail := email
	targetType, targetID, detail, ip := "user", "99", "created account", "203.0.113.9"
	if err := repository.CreateAuditEntry(ctx, service.AuditEntry{
		OccurredAt:  100,
		ActorUserID: &actorID,
		ActorEmail:  &actorEmail,
		Action:      service.AuditActionAccountCreated,
		TargetType:  &targetType,
		TargetID:    &targetID,
		Detail:      &detail,
		IP:          &ip,
	}); err != nil {
		t.Fatalf("CreateAuditEntry() error = %v", err)
	}

	if err := users.DeleteUser(ctx, actor.ID, actor.Version); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	var (
		action      string
		storedActor *int64
		snapshot    *string
	)
	if err := harness.DB.QueryRowContext(ctx, "SELECT action, actor_user_id, actor_email FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &storedActor, &snapshot); err != nil {
		t.Fatalf("query audit row: %v", err)
	}
	if action != service.AuditActionAccountCreated {
		t.Fatalf("action = %q, want %q", action, service.AuditActionAccountCreated)
	}
	if storedActor != nil {
		t.Fatalf("actor_user_id = %v, want NULL after deletion", *storedActor)
	}
	if snapshot == nil || *snapshot != actorEmail {
		t.Fatalf("actor_email snapshot = %v, want %q", snapshot, actorEmail)
	}
}
