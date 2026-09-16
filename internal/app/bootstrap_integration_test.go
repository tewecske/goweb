//go:build integration

package app

import (
	"context"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/config"
	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
	testpostgres "github.com/tewecske/goweb/tests/postgres"
)

func TestEnsureBootstrapAdminSeedsIdempotentAdministrator(t *testing.T) {
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

	appConfig, err := config.Load(func(name string) string {
		switch name {
		case config.PublicURLEnv:
			return "https://example.test"
		case config.SessionLifetimeEnv:
			return "1h"
		case config.BootstrapAdminEmailEnv:
			return "Bootstrap@Example.Test"
		case config.BootstrapAdminPasswordEnv:
			return "bootstrap-password"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	graph, err := New(harness.DB, appConfig)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := EnsureBootstrapAdmin(ctx, graph, appConfig); err != nil {
		t.Fatalf("EnsureBootstrapAdmin() error = %v", err)
	}
	created, err := graph.Users.FindUserByEmail(ctx, "bootstrap@example.test")
	if err != nil {
		t.Fatalf("FindUserByEmail() error = %v", err)
	}
	if !created.IsAdmin || created.EmailVerifiedAt == nil || created.PasswordHash == nil {
		t.Fatalf("bootstrap administrator = %+v, want confirmed admin with password", created)
	}

	// Second run is idempotent and does not create a duplicate.
	if err := EnsureBootstrapAdmin(ctx, graph, appConfig); err != nil {
		t.Fatalf("EnsureBootstrapAdmin(second) error = %v", err)
	}
	listed, err := graph.AdminUsers.ListUsers(ctx, service.AdminUserQuery{Size: 10})
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if listed.Total != 1 {
		t.Fatalf("account total = %d, want 1", listed.Total)
	}
}
