package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	config, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if config.Environment != EnvironmentDevelopment {
		t.Errorf("Environment = %q, want %q", config.Environment, EnvironmentDevelopment)
	}
	if config.HTTPAddress != DefaultHTTPAddress {
		t.Errorf("HTTPAddress = %q, want %q", config.HTTPAddress, DefaultHTTPAddress)
	}
	if config.PublicURL.String() != DefaultPublicURL {
		t.Errorf("PublicURL = %q, want %q", config.PublicURL.String(), DefaultPublicURL)
	}
	if config.SessionCookieSecure {
		t.Error("SessionCookieSecure = true, want false in development")
	}
	if config.EmailConfirmationRequired {
		t.Error("EmailConfirmationRequired = true, want false")
	}
	if config.SessionLifetime != DefaultSessionLifetime {
		t.Errorf("SessionLifetime = %s, want %s", config.SessionLifetime, DefaultSessionLifetime)
	}
	if config.DatabaseURL.IsSet() || config.SessionSecret.IsSet() {
		t.Error("default secrets are configured, want neither secret set")
	}
}

func TestLoadConfiguredValues(t *testing.T) {
	const sessionSecret = "01234567890123456789012345678901"
	values := map[string]string{
		EnvironmentEnv:               " production ",
		HTTPAddressEnv:               "127.0.0.1:9090",
		PublicURLEnv:                 "https://example.test/app",
		SessionCookieSecureEnv:       "false",
		EmailConfirmationRequiredEnv: "true",
		SessionLifetimeEnv:           "2h",
		DatabaseURLEnv:               "postgres://user:password@example.test/app",
		SessionSecretEnv:             sessionSecret,
	}

	config, err := Load(func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if config.Environment != EnvironmentProduction {
		t.Errorf("Environment = %q, want %q", config.Environment, EnvironmentProduction)
	}
	if config.HTTPAddress != "127.0.0.1:9090" {
		t.Errorf("HTTPAddress = %q, want 127.0.0.1:9090", config.HTTPAddress)
	}
	if config.PublicURL.String() != "https://example.test/app" {
		t.Errorf("PublicURL = %q, want https://example.test/app", config.PublicURL.String())
	}
	if config.SessionCookieSecure {
		t.Error("SessionCookieSecure = true, want false")
	}
	if !config.EmailConfirmationRequired {
		t.Error("EmailConfirmationRequired = false, want true")
	}
	if config.SessionLifetime != 2*time.Hour {
		t.Errorf("SessionLifetime = %s, want 2h", config.SessionLifetime)
	}
	if !config.DatabaseURL.IsSet() || !config.SessionSecret.IsSet() {
		t.Error("configured secrets are not marked as set")
	}
	if config.SessionSecret.Reveal() != sessionSecret {
		t.Error("SessionSecret.Reveal() does not return configured value")
	}
}

func TestLoadProductionCookieDefault(t *testing.T) {
	config, err := Load(func(name string) string {
		if name == EnvironmentEnv {
			return string(EnvironmentProduction)
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !config.SessionCookieSecure {
		t.Error("SessionCookieSecure = false, want true in production")
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		value     string
		expected  error
		wantNoRaw bool
	}{
		{name: "environment", env: EnvironmentEnv, value: "staging", expected: ErrInvalidEnvironment},
		{name: "http address", env: HTTPAddressEnv, value: "localhost", expected: ErrInvalidHTTPAddress},
		{name: "http port", env: HTTPAddressEnv, value: ":65536", expected: ErrInvalidHTTPAddress},
		{name: "public url scheme", env: PublicURLEnv, value: "ftp://example.test", expected: ErrInvalidPublicURL},
		{name: "public url credentials", env: PublicURLEnv, value: "https://user:password@example.test", expected: ErrInvalidPublicURL, wantNoRaw: true},
		{name: "cookie boolean", env: SessionCookieSecureEnv, value: "sometimes", expected: ErrInvalidBoolean},
		{name: "session duration", env: SessionLifetimeEnv, value: "forever", expected: ErrInvalidDuration},
		{name: "weak session secret", env: SessionSecretEnv, value: "too-short", expected: ErrWeakSecret, wantNoRaw: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := Load(func(name string) string {
				if name == test.env {
					return test.value
				}
				return ""
			})
			if !errors.Is(err, test.expected) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, test.expected)
			}
			if config != (Config{}) {
				t.Fatal("Load() returned non-zero config on error")
			}
			if test.wantNoRaw && strings.Contains(err.Error(), test.value) {
				t.Error("Load() error contains raw configured value")
			}
		})
	}
}

func TestSecretRedaction(t *testing.T) {
	const secretValue = "super-secret-value"
	secret := Secret{value: secretValue}

	if secret.String() == secretValue || strings.Contains(secret.String(), secretValue) {
		t.Error("Secret.String() exposes configured value")
	}
	if !strings.Contains(fmt.Sprintf("%#v", secret), "configured:true") {
		t.Errorf("Secret GoString() = %#v, want configured marker", secret)
	}

	encoded, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal(secret) error = %v", err)
	}
	if strings.Contains(string(encoded), secretValue) {
		t.Error("JSON encoding exposes configured value")
	}
}

func TestConfigDiagnosticsRedactSecrets(t *testing.T) {
	const secretValue = "01234567890123456789012345678901"
	config, err := Load(func(name string) string {
		if name == SessionSecretEnv || name == DatabaseURLEnv {
			return secretValue
		}
		return ""
	})
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	for _, diagnostic := range []string{
		config.String(),
		fmt.Sprintf("%+v", config),
		fmt.Sprintf("%#v", config),
	} {
		if strings.Contains(diagnostic, secretValue) {
			t.Errorf("diagnostic contains secret: %q", diagnostic)
		}
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal(config) error = %v", err)
	}
	if strings.Contains(string(encoded), secretValue) {
		t.Error("JSON encoding config exposes secret")
	}
}

func TestLoadNilEnvironmentLookup(t *testing.T) {
	_, err := Load(nil)
	if err == nil {
		t.Fatal("Load(nil) error = nil, want error")
	}
}
