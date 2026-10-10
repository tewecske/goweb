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
		EnvironmentEnv:               " test ",
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

	if config.Environment != EnvironmentTest {
		t.Errorf("Environment = %q, want %q", config.Environment, EnvironmentTest)
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
	values := map[string]string{
		EnvironmentEnv:   string(EnvironmentProduction),
		PublicURLEnv:     "https://example.test",
		DatabaseURLEnv:   "postgres://user:password@example.test/app",
		SessionSecretEnv: "01234567890123456789012345678901",
		MailRelayEnv:     "smtp://mail.example.test:587",
	}
	config, err := Load(func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !config.SessionCookieSecure {
		t.Error("SessionCookieSecure = false, want true in production")
	}
}

func TestLoadSecureCookieDefaultFollowsPublicURLScheme(t *testing.T) {
	for publicURL, want := range map[string]bool{"https://staging.example.test": true, "http://localhost:8080": false} {
		config, err := Load(func(name string) string {
			if name == PublicURLEnv {
				return publicURL
			}
			return ""
		})
		if err != nil {
			t.Fatalf("Load(%s) error = %v", publicURL, err)
		}
		if config.SessionCookieSecure != want {
			t.Errorf("development SessionCookieSecure with %s = %t, want %t", publicURL, config.SessionCookieSecure, want)
		}
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

func TestLoadGoogleOAuthConfiguration(t *testing.T) {
	t.Run("disabled without credentials", func(t *testing.T) {
		config, err := loadValues(map[string]string{})
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if config.GoogleOAuthConfigured() {
			t.Fatal("GoogleOAuthConfigured() = true, want false")
		}
	})

	t.Run("derives redirect from public url", func(t *testing.T) {
		config, err := loadValues(map[string]string{
			GoogleClientIDEnv:     "client-id",
			GoogleClientSecretEnv: "client-secret",
		})
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if !config.GoogleOAuthConfigured() {
			t.Fatal("GoogleOAuthConfigured() = false, want true")
		}
		if config.GoogleClientID != "client-id" || config.GoogleClientSecret.Reveal() != "client-secret" {
			t.Fatalf("Google settings not retained: %+v", config)
		}
		if config.GoogleRedirectURL != "http://localhost:8080/en/oauth/google/callback" {
			t.Fatalf("GoogleRedirectURL = %q", config.GoogleRedirectURL)
		}
	})

	t.Run("honours redirect override", func(t *testing.T) {
		config, err := loadValues(map[string]string{
			GoogleClientIDEnv:     "client-id",
			GoogleClientSecretEnv: "client-secret",
			GoogleRedirectURLEnv:  "https://app.example.test/callback",
		})
		if err != nil {
			t.Fatalf("Load() error = %v, want nil", err)
		}
		if config.GoogleRedirectURL != "https://app.example.test/callback" {
			t.Fatalf("GoogleRedirectURL = %q, want override", config.GoogleRedirectURL)
		}
	})
}

func TestLoadGoogleOAuthRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
	}{
		{name: "missing secret", values: map[string]string{GoogleClientIDEnv: "client-id"}},
		{name: "missing client id", values: map[string]string{GoogleClientSecretEnv: "client-secret"}},
		{name: "credential bearing redirect", values: map[string]string{
			GoogleClientIDEnv:     "client-id",
			GoogleClientSecretEnv: "client-secret",
			GoogleRedirectURLEnv:  "https://user:pass@app.example.test/callback",
		}},
		{name: "relative redirect", values: map[string]string{
			GoogleClientIDEnv:     "client-id",
			GoogleClientSecretEnv: "client-secret",
			GoogleRedirectURLEnv:  "/callback",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadValues(test.values); !errors.Is(err, ErrInvalidOAuth) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrInvalidOAuth)
			}
		})
	}
}

func TestLoadNilEnvironmentLookup(t *testing.T) {
	_, err := Load(nil)
	if err == nil {
		t.Fatal("Load(nil) error = nil, want error")
	}
}

func TestLoadBootstrapAdmin(t *testing.T) {
	values := map[string]string{
		BootstrapAdminEmailEnv:    " Admin@Example.Test ",
		BootstrapAdminPasswordEnv: "bootstrap-password",
	}
	config, err := Load(func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if !config.BootstrapAdminConfigured() {
		t.Fatal("BootstrapAdminConfigured() = false, want true")
	}
	if config.BootstrapAdminEmail != "Admin@Example.Test" {
		t.Fatalf("BootstrapAdminEmail = %q, want trimmed value", config.BootstrapAdminEmail)
	}
	if !config.BootstrapAdminPassword.IsSet() || config.BootstrapAdminPassword.String() != "[redacted]" {
		t.Fatalf("bootstrap password not protected: %q", config.BootstrapAdminPassword.String())
	}
	if strings.Contains(config.String(), "bootstrap-password") || strings.Contains(config.String(), "Admin@Example.Test") {
		t.Fatalf("config summary leaked bootstrap values: %s", config.String())
	}
}

func TestLoadBootstrapAdminRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
		want   error
	}{
		{
			name:   "missing password",
			values: map[string]string{BootstrapAdminEmailEnv: "admin@example.test"},
			want:   ErrInvalidBootstrapAdmin,
		},
		{
			name:   "missing email",
			values: map[string]string{BootstrapAdminPasswordEnv: "bootstrap-password"},
			want:   ErrInvalidBootstrapAdmin,
		},
		{
			name:   "invalid email",
			values: map[string]string{BootstrapAdminEmailEnv: "not-an-email", BootstrapAdminPasswordEnv: "bootstrap-password"},
			want:   ErrInvalidBootstrapAdmin,
		},
		{
			name:   "weak password",
			values: map[string]string{BootstrapAdminEmailEnv: "admin@example.test", BootstrapAdminPasswordEnv: "short"},
			want:   ErrWeakSecret,
		},
		{
			name:   "production forbidden",
			values: map[string]string{EnvironmentEnv: "production", BootstrapAdminEmailEnv: "admin@example.test", BootstrapAdminPasswordEnv: "bootstrap-password"},
			want:   ErrBootstrapAdminForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(func(name string) string { return test.values[name] }); !errors.Is(err, test.want) {
				t.Fatalf("Load() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLoadRetentionDefaults(t *testing.T) {
	config, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.GuestRetention != DefaultGuestRetention ||
		config.LoginAttemptRetention != DefaultLoginAttemptRetention ||
		config.UsageRetention != DefaultUsageRetention {
		t.Fatalf("retention defaults = %s/%s/%s", config.GuestRetention, config.LoginAttemptRetention, config.UsageRetention)
	}
}

func TestLoadConfiguredRetention(t *testing.T) {
	values := map[string]string{
		GuestRetentionEnv:        "48h",
		LoginAttemptRetentionEnv: "72h",
		UsageRetentionEnv:        "168h",
	}
	config, err := Load(func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.GuestRetention != 48*time.Hour || config.LoginAttemptRetention != 72*time.Hour || config.UsageRetention != 168*time.Hour {
		t.Fatalf("retention = %s/%s/%s", config.GuestRetention, config.LoginAttemptRetention, config.UsageRetention)
	}
}

func TestLoadRejectsInvalidRetention(t *testing.T) {
	if _, err := Load(func(name string) string {
		if name == UsageRetentionEnv {
			return "-1h"
		}
		return ""
	}); !errors.Is(err, ErrInvalidDuration) {
		t.Fatalf("Load(invalid retention) error = %v, want %v", err, ErrInvalidDuration)
	}
}

func TestLoadRejectsCredentialBearingMailRelay(t *testing.T) {
	if _, err := Load(func(name string) string {
		if name == MailRelayEnv {
			return "smtp://user:password@mail.example.test"
		}
		return ""
	}); !errors.Is(err, ErrInvalidMailRelay) {
		t.Fatalf("Load(credential relay) error = %v, want %v", err, ErrInvalidMailRelay)
	}
	config, err := Load(func(name string) string {
		if name == MailRelayEnv {
			return "smtp://mail.example.test:587"
		}
		return ""
	})
	if err != nil || !config.MailRelay.IsSet() {
		t.Fatalf("Load(valid relay) = %+v, %v", config, err)
	}
	if strings.Contains(config.String(), "mail.example.test") {
		t.Fatalf("config summary leaked relay address: %s", config.String())
	}
	if config.MailFrom != "no-reply@localhost" {
		t.Fatalf("default MailFrom = %q, want no-reply@ the public URL host", config.MailFrom)
	}
	for name, values := range map[string]map[string]string{
		"non-smtp relay":  {MailRelayEnv: "http://mail.example.test"},
		"display name":    {MailFromEnv: "App <app@example.test>"},
		"invalid address": {MailFromEnv: "not an address"},
	} {
		if _, err := Load(func(key string) string { return values[key] }); !errors.Is(err, ErrInvalidMailRelay) {
			t.Fatalf("Load(%s) error = %v, want %v", name, err, ErrInvalidMailRelay)
		}
	}
	ipv6Host, err := Load(func(name string) string {
		if name == PublicURLEnv {
			return "http://[::1]:8080"
		}
		return ""
	})
	if err != nil || ipv6Host.MailFrom != "no-reply@localhost" {
		t.Fatalf("Load(IPv6 public URL) MailFrom = %q, %v; want fallback sender", ipv6Host.MailFrom, err)
	}
}

func TestLoadValidatesTrustedProxy(t *testing.T) {
	if _, err := Load(func(name string) string {
		if name == TrustedProxyEnv {
			return "not-an-address"
		}
		return ""
	}); !errors.Is(err, ErrInvalidTrustedProxy) {
		t.Fatalf("Load(invalid proxy) error = %v, want %v", err, ErrInvalidTrustedProxy)
	}
	for _, valid := range []string{"10.0.0.1", "10.0.0.0/8", "2001:db8::/32"} {
		config, err := Load(func(name string) string {
			if name == TrustedProxyEnv {
				return valid
			}
			return ""
		})
		if err != nil || config.TrustedProxy != valid {
			t.Fatalf("Load(proxy=%q) = %q, %v", valid, config.TrustedProxy, err)
		}
	}
}

func TestLoadAuthMode(t *testing.T) {
	const databaseURL = "postgres://user:password@example.test/app"
	tests := []struct {
		name   string
		values map[string]string
		want   Config
	}{
		{
			name:   "defaults to local",
			values: map[string]string{},
			want:   Config{AuthMode: AuthModeLocal},
		},
		{
			name: "provider",
			values: map[string]string{
				AuthModeEnv:      " Provider ",
				DatabaseURLEnv:   databaseURL,
				HydraAdminURLEnv: "http://hydra-admin.internal:4445",
				SSOIssuerURLEnv:  "http://127.0.0.1:4444",
			},
			want: Config{AuthMode: AuthModeProvider, HydraAdminURL: "http://hydra-admin.internal:4445", SSOIssuerURL: "http://127.0.0.1:4444"},
		},
		{
			name: "client derives the callback from the public URL",
			values: map[string]string{
				AuthModeEnv:        "client",
				DatabaseURLEnv:     databaseURL,
				PublicURLEnv:       "http://127.0.0.1:8081/",
				SSOIssuerURLEnv:    "http://127.0.0.1:4444",
				SSOClientIDEnv:     "app-client",
				SSOClientSecretEnv: "client-secret",
			},
			want: Config{
				AuthMode:       AuthModeClient,
				SSOIssuerURL:   "http://127.0.0.1:4444",
				SSOClientID:    "app-client",
				SSORedirectURL: "http://127.0.0.1:8081/en/oauth/sso/callback",
			},
		},
		{
			name: "client keeps explicit callback and account page",
			values: map[string]string{
				AuthModeEnv:        "client",
				DatabaseURLEnv:     databaseURL,
				SSOIssuerURLEnv:    "https://id.example.test",
				SSOClientIDEnv:     "app-client",
				SSOClientSecretEnv: "client-secret",
				SSORedirectURLEnv:  "https://app.example.test/hu/oauth/sso/callback",
				SSOAccountURLEnv:   "https://accounts.example.test/en/account/settings",
			},
			want: Config{
				AuthMode:       AuthModeClient,
				SSOIssuerURL:   "https://id.example.test",
				SSOClientID:    "app-client",
				SSORedirectURL: "https://app.example.test/hu/oauth/sso/callback",
				SSOAccountURL:  "https://accounts.example.test/en/account/settings",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loaded, err := loadValues(test.values)
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			got := Config{
				AuthMode:       loaded.AuthMode,
				HydraAdminURL:  loaded.HydraAdminURL,
				SSOIssuerURL:   loaded.SSOIssuerURL,
				SSOClientID:    loaded.SSOClientID,
				SSORedirectURL: loaded.SSORedirectURL,
				SSOAccountURL:  loaded.SSOAccountURL,
			}
			if got != test.want {
				t.Fatalf("auth settings = %+v, want %+v", got, test.want)
			}
			wantSecret := test.values[SSOClientSecretEnv]
			if loaded.SSOClientSecret.Reveal() != wantSecret {
				t.Fatalf("SSOClientSecret set = %t, want %t", loaded.SSOClientSecret.IsSet(), wantSecret != "")
			}
		})
	}
}

func TestLoadRejectsInvalidAuthMode(t *testing.T) {
	const databaseURL = "postgres://user:password@example.test/app"
	client := func(overrides map[string]string) map[string]string {
		values := map[string]string{
			AuthModeEnv:        "client",
			DatabaseURLEnv:     databaseURL,
			SSOIssuerURLEnv:    "https://id.example.test",
			SSOClientIDEnv:     "app-client",
			SSOClientSecretEnv: "client-secret-value",
		}
		for name, value := range overrides {
			if value == "" {
				delete(values, name)
				continue
			}
			values[name] = value
		}
		return values
	}
	tests := []struct {
		name   string
		values map[string]string
	}{
		{name: "unknown mode", values: map[string]string{AuthModeEnv: "sso"}},
		{name: "provider without database", values: map[string]string{AuthModeEnv: "provider", HydraAdminURLEnv: "http://127.0.0.1:4445", SSOIssuerURLEnv: "http://127.0.0.1:4444"}},
		{name: "provider without hydra admin", values: map[string]string{AuthModeEnv: "provider", DatabaseURLEnv: databaseURL, SSOIssuerURLEnv: "http://127.0.0.1:4444"}},
		{name: "provider without issuer", values: map[string]string{AuthModeEnv: "provider", DatabaseURLEnv: databaseURL, HydraAdminURLEnv: "http://127.0.0.1:4445"}},
		{name: "provider hydra admin with credentials", values: map[string]string{AuthModeEnv: "provider", DatabaseURLEnv: databaseURL, HydraAdminURLEnv: "http://admin:pw@127.0.0.1:4445", SSOIssuerURLEnv: "http://127.0.0.1:4444"}},
		{name: "provider issuer with query", values: map[string]string{AuthModeEnv: "provider", DatabaseURLEnv: databaseURL, HydraAdminURLEnv: "http://127.0.0.1:4445", SSOIssuerURLEnv: "http://127.0.0.1:4444/?x=1"}},
		{name: "provider with client settings", values: map[string]string{AuthModeEnv: "provider", DatabaseURLEnv: databaseURL, HydraAdminURLEnv: "http://127.0.0.1:4445", SSOIssuerURLEnv: "http://127.0.0.1:4444", SSOClientIDEnv: "app-client"}},
		{name: "local with issuer", values: map[string]string{SSOIssuerURLEnv: "https://id.example.test"}},
		{name: "local with client id", values: map[string]string{SSOClientIDEnv: "app-client"}},
		{name: "local with client secret", values: map[string]string{SSOClientSecretEnv: "client-secret-value"}},
		{name: "local with hydra admin", values: map[string]string{HydraAdminURLEnv: "http://127.0.0.1:4445"}},
		{name: "client without database", values: client(map[string]string{DatabaseURLEnv: ""})},
		{name: "client without secret", values: client(map[string]string{SSOClientSecretEnv: ""})},
		{name: "client without client id", values: client(map[string]string{SSOClientIDEnv: ""})},
		{name: "client without issuer", values: client(map[string]string{SSOIssuerURLEnv: ""})},
		{name: "client with hydra admin", values: client(map[string]string{HydraAdminURLEnv: "http://127.0.0.1:4445"})},
		{name: "client with google sign-in", values: client(map[string]string{GoogleClientIDEnv: "google-id", GoogleClientSecretEnv: "google-secret"})},
		{name: "client issuer with query", values: client(map[string]string{SSOIssuerURLEnv: "https://id.example.test/?realm=x"})},
		{name: "client relative redirect", values: client(map[string]string{SSORedirectURLEnv: "/en/oauth/sso/callback"})},
		{name: "client non-http account page", values: client(map[string]string{SSOAccountURLEnv: "ftp://accounts.example.test"})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loaded, err := loadValues(test.values)
			if !errors.Is(err, ErrInvalidAuthMode) {
				t.Fatalf("Load() error = %v, want errors.Is(_, %v)", err, ErrInvalidAuthMode)
			}
			if loaded != (Config{}) {
				t.Fatal("Load() returned a non-zero config for an invalid auth mode")
			}
			for _, secret := range []string{"client-secret-value", "pw@", "password"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("auth mode error leaked %q: %v", secret, err)
				}
			}
		})
	}
}
