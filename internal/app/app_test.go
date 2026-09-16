package app

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/config"
)

func TestNewRejectsNilDatabase(t *testing.T) {
	if _, err := New(nil, config.Config{}); !errors.Is(err, ErrNilDatabase) {
		t.Fatalf("New(nil) error = %v, want %v", err, ErrNilDatabase)
	}
}

func TestNewRejectsProductionWithoutMailDelivery(t *testing.T) {
	appConfig := config.Config{
		Environment:     config.EnvironmentProduction,
		PublicURL:       url.URL{Scheme: "https", Host: "example.test"},
		SessionLifetime: time.Hour,
	}
	if _, err := New(&sql.DB{}, appConfig); !errors.Is(err, ErrMailDeliveryNotConfigured) {
		t.Fatalf("New(production) error = %v, want %v", err, ErrMailDeliveryNotConfigured)
	}
}

func TestNewBuildsCompleteGraphWithoutDatabaseIO(t *testing.T) {
	database := &sql.DB{}
	appConfig := config.Config{
		PublicURL:       url.URL{Scheme: "https", Host: "example.test"},
		SessionLifetime: time.Hour,
	}
	graph, err := New(database, appConfig)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if graph.Database != database {
		t.Fatal("graph does not retain injected database")
	}
	for name, value := range map[string]any{
		"users": graph.Users, "sessions": graph.Sessions, "guest claims": graph.GuestClaimRepository,
		"email tokens": graph.EmailTokens, "password reset": graph.PasswordReset,
		"oauth states": graph.OAuthStates, "oauth identities": graph.OAuthIdentities,
		"session service": graph.SessionService, "password hasher": graph.PasswordHasher, "mail": graph.Mail,
		"signup": graph.SignUp, "signin": graph.SignIn,
		"confirmation": graph.Confirmation, "confirmation resend": graph.ConfirmationResend,
		"password resetter": graph.PasswordResetter, "password consumer": graph.PasswordConsumer,
		"oauth": graph.OAuth, "guest session": graph.GuestSession, "guest claims service": graph.GuestClaim,
		"guest redemption": graph.GuestRedemption, "guest upgrade": graph.GuestUpgrade,
		"guest rate limited": graph.GuestRateLimited, "guest cleanup": graph.GuestCleanup, "theme": graph.Theme,
	} {
		if value == nil {
			t.Fatalf("graph field %s is nil", name)
		}
	}
}

func TestEnsureBootstrapAdminSkipsWhenUnconfigured(t *testing.T) {
	if err := EnsureBootstrapAdmin(nil, nil, config.Config{}); err != nil {
		t.Fatalf("EnsureBootstrapAdmin() error = %v, want nil", err)
	}
}

func TestEnsureBootstrapAdminRejectsProduction(t *testing.T) {
	appConfig := config.Config{
		Environment:            config.EnvironmentProduction,
		BootstrapAdminEmail:    "admin@example.test",
		BootstrapAdminPassword: config.Secret{},
	}
	// IsSet is false for the zero secret, so use a configured value via Load.
	appConfig, err := config.Load(func(name string) string {
		switch name {
		case config.EnvironmentEnv:
			return "development"
		case config.BootstrapAdminEmailEnv:
			return "admin@example.test"
		case config.BootstrapAdminPasswordEnv:
			return "bootstrap-password"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	appConfig.Environment = config.EnvironmentProduction
	if err := EnsureBootstrapAdmin(nil, nil, appConfig); !errors.Is(err, ErrBootstrapAdminForbidden) {
		t.Fatalf("EnsureBootstrapAdmin(production) error = %v, want %v", err, ErrBootstrapAdminForbidden)
	}
}

func TestEnsureBootstrapAdminRejectsMissingDependencies(t *testing.T) {
	appConfig, err := config.Load(func(name string) string {
		switch name {
		case config.BootstrapAdminEmailEnv:
			return "admin@example.test"
		case config.BootstrapAdminPasswordEnv:
			return "bootstrap-password"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureBootstrapAdmin(context.Background(), nil, appConfig); err == nil {
		t.Fatal("EnsureBootstrapAdmin(nil graph) error = nil, want failure")
	}
}

func TestNewMigrationStatusProviderRejectsNilRunner(t *testing.T) {
	if provider := NewMigrationStatusProvider(nil); provider != nil {
		t.Fatalf("NewMigrationStatusProvider(nil) = %v, want nil", provider)
	}
}
