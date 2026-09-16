package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestConfigDiagnosticsNeverExposeConfiguredSecrets(t *testing.T) {
	const (
		databaseCredential = "db-credential-5a1b-9c2d-secret"
		sessionCredential  = "session-credential-4e7f-8a1b-c3d5-secret"
		bootstrapPassword  = "bootstrap-password-2f6a-1b8c"
	)
	values := map[string]string{
		DatabaseURLEnv:            "postgres://goweb:" + databaseCredential + "@localhost:5432/goweb",
		SessionSecretEnv:          sessionCredential,
		BootstrapAdminEmailEnv:    "admin@example.test",
		BootstrapAdminPasswordEnv: bootstrapPassword,
		MailRelayEnv:              "smtp://mail.example.test:587",
	}

	loaded, err := Load(func(name string) string { return values[name] })
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("Marshal() error = %v, want nil", err)
	}

	outputs := map[string]string{
		"String()":     loaded.String(),
		"%v":           fmt.Sprintf("%v", loaded),
		"%#v":          fmt.Sprintf("%#v", loaded),
		"json":         string(encoded),
		"secret %v":    fmt.Sprintf("%v", loaded.DatabaseURL),
		"secret %#v":   fmt.Sprintf("%#v", loaded.SessionSecret),
		"bootstrap %v": fmt.Sprintf("%v", loaded.BootstrapAdminPassword),
	}
	secrets := []string{databaseCredential, sessionCredential, bootstrapPassword, "mail.example.test"}
	for format, output := range outputs {
		for _, secret := range secrets {
			if strings.Contains(output, secret) {
				t.Errorf("%s output leaked configured secret: %s", format, output)
			}
		}
	}

	if loaded.DatabaseURL.Reveal() == "" {
		t.Fatal("Reveal() returned an empty database credential to internal callers")
	}
}
