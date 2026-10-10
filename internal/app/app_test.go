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

func TestNewWiresSSOClientOnlyInClientMode(t *testing.T) {
	appConfig := config.Config{
		Environment:     config.EnvironmentDevelopment,
		PublicURL:       url.URL{Scheme: "http", Host: "127.0.0.1:8081"},
		SessionLifetime: time.Hour,
		AuthMode:        config.AuthModeClient,
		SSOIssuerURL:    "http://127.0.0.1:4444",
		SSOClientID:     "app-client",
		SSORedirectURL:  "http://127.0.0.1:8081/en/oauth/sso/callback",
	}
	if _, err := New(&sql.DB{}, appConfig); err == nil {
		t.Fatal("New(client) without a client secret succeeded")
	}
	loaded, err := config.Load(func(name string) string {
		return map[string]string{
			config.AuthModeEnv:        "client",
			config.DatabaseURLEnv:     "postgres://user:pw@127.0.0.1/app",
			config.PublicURLEnv:       "http://127.0.0.1:8081",
			config.SSOIssuerURLEnv:    "http://127.0.0.1:4444",
			config.SSOClientIDEnv:     "app-client",
			config.SSOClientSecretEnv: "client-secret",
		}[name]
	})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := New(&sql.DB{}, loaded)
	if err != nil {
		t.Fatalf("New(client) error = %v", err)
	}
	if graph.SSOClient == nil || graph.SSOProvider != nil {
		t.Fatalf("client mode wiring: client %t provider %t, want only the client", graph.SSOClient != nil, graph.SSOProvider != nil)
	}
}

func TestNewWiresSSOProviderOnlyInProviderMode(t *testing.T) {
	base := config.Config{
		Environment:     config.EnvironmentDevelopment,
		PublicURL:       url.URL{Scheme: "http", Host: "localhost:8080"},
		SessionLifetime: time.Hour,
	}
	local, err := New(&sql.DB{}, base)
	if err != nil {
		t.Fatalf("New(local) error = %v", err)
	}
	if local.SSOProvider != nil {
		t.Fatal("local mode wired an SSO provider")
	}

	provider := base
	provider.AuthMode = config.AuthModeProvider
	provider.HydraAdminURL = "http://127.0.0.1:4445"
	provider.SSOIssuerURL = "http://127.0.0.1:4444"
	graph, err := New(&sql.DB{}, provider)
	if err != nil {
		t.Fatalf("New(provider) error = %v", err)
	}
	if graph.SSOProvider == nil {
		t.Fatal("provider mode did not wire the SSO provider")
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
	if mode := graph.SystemInfo.SystemConfiguration().AuthMode; mode != string(config.AuthModeLocal) {
		t.Fatalf("system AuthMode = %q, want %q for an unset mode", mode, config.AuthModeLocal)
	}
}

func TestNewRegistersGoogleProviderOnlyWhenConfigured(t *testing.T) {
	database := &sql.DB{}

	appConfig, err := config.Load(func(name string) string {
		switch name {
		case config.GoogleClientIDEnv:
			return "client-id"
		case config.GoogleClientSecretEnv:
			return "client-secret"
		case config.PublicURLEnv:
			return "https://example.test"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	graph, err := New(database, appConfig)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	names := graph.Providers.Names()
	if len(names) != 1 || names[0] != "google" {
		t.Fatalf("provider names = %v, want [google]", names)
	}

	unconfigured, err := New(database, config.Config{PublicURL: url.URL{Scheme: "https", Host: "example.test"}, SessionLifetime: time.Hour})
	if err != nil {
		t.Fatalf("New(unconfigured) error = %v", err)
	}
	if len(unconfigured.Providers.Names()) != 0 {
		t.Fatalf("provider names = %v, want none", unconfigured.Providers.Names())
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
