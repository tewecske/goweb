package config

import (
	"errors"
	"strings"
	"testing"
)

func safeProductionValues() map[string]string {
	return map[string]string{
		EnvironmentEnv:               string(EnvironmentProduction),
		HTTPAddressEnv:               "0.0.0.0:8443",
		PublicURLEnv:                 "https://app.example.test",
		SessionCookieSecureEnv:       "true",
		EmailConfirmationRequiredEnv: "true",
		SessionLifetimeEnv:           "12h",
		DatabaseURLEnv:               "postgres://app:db-credential@db.example.test:5432/app",
		SessionSecretEnv:             "01234567890123456789012345678901",
		MailRelayEnv:                 "smtp://mail.example.test:587",
		TrustedProxyEnv:              "10.0.0.0/8",
	}
}

func loadValues(values map[string]string) (Config, error) {
	return Load(func(name string) string { return values[name] })
}

func TestLoadAcceptsSafeProductionConfiguration(t *testing.T) {
	config, err := loadValues(safeProductionValues())
	if err != nil {
		t.Fatalf("Load(safe production) error = %v, want nil", err)
	}
	if config.Environment != EnvironmentProduction {
		t.Fatalf("Environment = %q, want %q", config.Environment, EnvironmentProduction)
	}
	if config.PublicURL.Scheme != "https" || !config.SessionCookieSecure {
		t.Fatalf("safe production config lost required settings: %+v", config)
	}
}

func addSafeClientMode(values map[string]string) {
	values[AuthModeEnv] = string(AuthModeClient)
	values[SSOIssuerURLEnv] = "https://id.example.test"
	values[SSOClientIDEnv] = "app-client"
	values[SSOClientSecretEnv] = "client-secret-value"
}

func TestLoadAcceptsSafeProductionAuthModes(t *testing.T) {
	client := safeProductionValues()
	addSafeClientMode(client)
	loaded, err := loadValues(client)
	if err != nil {
		t.Fatalf("Load(production client) error = %v, want nil", err)
	}
	if loaded.SSORedirectURL != "https://app.example.test/en/oauth/sso/callback" {
		t.Fatalf("SSORedirectURL = %q, want the derived https callback", loaded.SSORedirectURL)
	}

	// The Hydra admin API is reached over a private network, so plain HTTP is
	// accepted for the provider even in production.
	provider := safeProductionValues()
	provider[AuthModeEnv] = string(AuthModeProvider)
	provider[HydraAdminURLEnv] = "http://hydra-admin.internal:4445"
	provider[SSOIssuerURLEnv] = "https://id.example.test"
	if _, err := loadValues(provider); err != nil {
		t.Fatalf("Load(production provider) error = %v, want nil", err)
	}
	provider[SSOIssuerURLEnv] = "http://id.example.test"
	if _, err := loadValues(provider); !errors.Is(err, ErrUnsafeProductionConfig) {
		t.Fatalf("Load(production provider, http issuer) error = %v, want %v", err, ErrUnsafeProductionConfig)
	}
}

func TestLoadRejectsUnsafeProductionConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{
			name: "insecure session cookie",
			mutate: func(values map[string]string) {
				values[SessionCookieSecureEnv] = "false"
			},
		},
		{
			name: "non-https origin",
			mutate: func(values map[string]string) {
				values[PublicURLEnv] = "http://app.example.test"
			},
		},
		{
			name: "missing datastore",
			mutate: func(values map[string]string) {
				delete(values, DatabaseURLEnv)
			},
		},
		{
			name: "missing session secret",
			mutate: func(values map[string]string) {
				delete(values, SessionSecretEnv)
			},
		},
		{
			name: "missing mail relay",
			mutate: func(values map[string]string) {
				delete(values, MailRelayEnv)
			},
		},
		{
			name: "insecure google redirect",
			mutate: func(values map[string]string) {
				values[GoogleClientIDEnv] = "client-id"
				values[GoogleClientSecretEnv] = "client-secret"
				values[GoogleRedirectURLEnv] = "http://app.example.test/en/oauth/google/callback"
			},
		},
		{
			name: "plain-http sso issuer",
			mutate: func(values map[string]string) {
				addSafeClientMode(values)
				values[SSOIssuerURLEnv] = "http://id.example.test"
			},
		},
		{
			name: "plain-http sso callback",
			mutate: func(values map[string]string) {
				addSafeClientMode(values)
				values[SSORedirectURLEnv] = "http://app.example.test/en/oauth/sso/callback"
			},
		},
		{
			name: "plain-http sso account page",
			mutate: func(values map[string]string) {
				addSafeClientMode(values)
				values[SSOAccountURLEnv] = "http://id.example.test/en/account/settings"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := safeProductionValues()
			test.mutate(values)

			config, err := loadValues(values)
			if !errors.Is(err, ErrUnsafeProductionConfig) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrUnsafeProductionConfig)
			}
			if config != (Config{}) {
				t.Fatal("Load() returned non-zero config on unsafe production settings")
			}
			if strings.Contains(err.Error(), "db-credential") || strings.Contains(err.Error(), "01234567890123456789012345678901") {
				t.Fatalf("unsafe-config error leaked a secret value: %v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidProductionProvidersAndProxy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   error
	}{
		{
			name: "credential bearing mail provider",
			mutate: func(values map[string]string) {
				values[MailRelayEnv] = "smtp://user:password@mail.example.test"
			},
			want: ErrInvalidMailRelay,
		},
		{
			name: "invalid trusted proxy",
			mutate: func(values map[string]string) {
				values[TrustedProxyEnv] = "not-a-network"
			},
			want: ErrInvalidTrustedProxy,
		},
		{
			name: "partial google oauth",
			mutate: func(values map[string]string) {
				values[GoogleClientIDEnv] = "client-id"
			},
			want: ErrInvalidOAuth,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := safeProductionValues()
			test.mutate(values)
			if _, err := loadValues(values); !errors.Is(err, test.want) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, test.want)
			}
		})
	}
}

func TestNonProductionEnvironmentsAllowDevelopmentSettings(t *testing.T) {
	for _, environment := range []string{"development", "test", ""} {
		t.Run("environment="+environment, func(t *testing.T) {
			values := safeProductionValues()
			values[EnvironmentEnv] = environment
			delete(values, DatabaseURLEnv)
			delete(values, SessionSecretEnv)
			values[SessionCookieSecureEnv] = "false"
			values[PublicURLEnv] = "http://localhost:8080"

			if _, err := loadValues(values); err != nil {
				t.Fatalf("Load(%q) error = %v, want nil", environment, err)
			}
		})
	}
}
