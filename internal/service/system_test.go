package service

import (
	"strings"
	"testing"
)

func TestSystemInfoServiceSanitizesConnectionAddresses(t *testing.T) {
	info := NewSystemInfoService(SystemInfoSettings{
		Environment:   "production",
		PublicAddress: ":8080",
		PublicURL:     "https://user:password@example.test/app?token=secret#frag",
		MailRelay:     "smtp://relay-user:relay-pass@mail.example.test:587/outbound?key=secret",
		Providers:     []string{" github ", "", "example"},
		AuthMode:      " client ",
		SSOIssuer:     "https://issuer-user:issuer-pass@id.example.test/realm?client_secret=secret",
		HydraAdmin:    "http://hydra-admin.internal:4445/admin/clients",
	})
	configuration := info.SystemConfiguration()
	if configuration.AuthMode != "client" {
		t.Fatalf("AuthMode = %q, want trimmed mode", configuration.AuthMode)
	}
	if configuration.SSOIssuer != "https://id.example.test" {
		t.Fatalf("SSOIssuer = %q, want credential-free host", configuration.SSOIssuer)
	}
	if configuration.HydraAdmin != "http://hydra-admin.internal:4445" {
		t.Fatalf("HydraAdmin = %q, want scheme and host only", configuration.HydraAdmin)
	}

	if configuration.PublicURL != "https://example.test" {
		t.Fatalf("PublicURL = %q, want credential-free host", configuration.PublicURL)
	}
	if configuration.MailRelay != "smtp://mail.example.test:587" {
		t.Fatalf("MailRelay = %q, want credential-free host", configuration.MailRelay)
	}
	if len(configuration.Providers) != 2 || configuration.Providers[0] != "github" || configuration.Providers[1] != "example" {
		t.Fatalf("Providers = %v, want trimmed non-empty names", configuration.Providers)
	}
	summary := configuration.PublicURL + configuration.MailRelay + configuration.SSOIssuer + configuration.HydraAdmin + strings.Join(configuration.Providers, ",")
	for _, secret := range []string{"password", "secret", "relay-pass", "key=", "issuer-pass"} {
		if strings.Contains(summary, secret) {
			t.Fatalf("system configuration leaked %q: %s", secret, summary)
		}
	}
}

func TestSystemInfoServiceReportsRateLimitPolicy(t *testing.T) {
	info := NewSystemInfoService(SystemInfoSettings{})
	configuration := info.SystemConfiguration()
	if configuration.AuthRateLimit != AuthenticationRateLimit ||
		configuration.AuthRateLimitWindow != AuthenticationRateLimitWindow ||
		configuration.AuthRateLimitMaxKeys != AuthenticationRateLimitMaxKeys {
		t.Fatalf("rate limit policy = %+v, want published baseline", configuration)
	}
}

func TestSystemInfoServiceCopiesProviderSlice(t *testing.T) {
	providers := []string{"one"}
	info := NewSystemInfoService(SystemInfoSettings{Providers: providers})
	configuration := info.SystemConfiguration()
	configuration.Providers[0] = "mutated"
	if info.SystemConfiguration().Providers[0] != "one" {
		t.Fatal("SystemConfiguration() exposed the internal provider slice")
	}
}

func TestSystemInfoServiceHandlesNilReceiver(t *testing.T) {
	var info *SystemInfoService
	if configuration := info.SystemConfiguration(); configuration.AuthRateLimit != 0 {
		t.Fatalf("nil receiver = %+v, want zero value", configuration)
	}
}
