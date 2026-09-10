// Package config loads and validates deployment configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// EnvironmentEnv names the environment classification variable.
	EnvironmentEnv = "GOWEB_ENV"
	// HTTPAddressEnv names the environment variable for the HTTP listen address.
	HTTPAddressEnv = "GOWEB_HTTP_ADDR"
	// PublicURLEnv names the externally visible application URL.
	PublicURLEnv = "GOWEB_PUBLIC_URL"
	// SessionCookieSecureEnv controls the Secure cookie attribute.
	SessionCookieSecureEnv = "GOWEB_SESSION_COOKIE_SECURE"
	// EmailConfirmationRequiredEnv controls whether email confirmation gates sign-in.
	EmailConfirmationRequiredEnv = "GOWEB_EMAIL_CONFIRMATION_REQUIRED"
	// SessionLifetimeEnv names the session lifetime duration.
	SessionLifetimeEnv = "GOWEB_SESSION_LIFETIME"
	// DatabaseURLEnv names the optional database connection URL.
	DatabaseURLEnv = "GOWEB_DATABASE_URL"
	// SessionSecretEnv names the optional session-signing secret.
	SessionSecretEnv = "GOWEB_SESSION_SECRET"

	// DefaultEnvironment is used when EnvironmentEnv is not set.
	DefaultEnvironment Environment = EnvironmentDevelopment
	// DefaultHTTPAddress is used when HTTPAddressEnv is not set.
	DefaultHTTPAddress = ":8080"
	// DefaultPublicURL is used when PublicURLEnv is not set.
	DefaultPublicURL = "http://localhost:8080"
	// DefaultSessionLifetime is used when SessionLifetimeEnv is not set.
	DefaultSessionLifetime = 24 * time.Hour
	// MinimumSessionSecretLength prevents weak configured session secrets.
	MinimumSessionSecretLength = 32
)

var (
	// ErrInvalidEnvironment identifies an unsupported environment value.
	ErrInvalidEnvironment = errors.New("config: invalid environment")
	// ErrInvalidHTTPAddress identifies an invalid HTTP listen address.
	ErrInvalidHTTPAddress = errors.New("config: invalid http address")
	// ErrInvalidPublicURL identifies an unsafe or malformed public URL.
	ErrInvalidPublicURL = errors.New("config: invalid public url")
	// ErrInvalidBoolean identifies a malformed boolean setting.
	ErrInvalidBoolean = errors.New("config: invalid boolean")
	// ErrInvalidDuration identifies a malformed or out-of-range duration.
	ErrInvalidDuration = errors.New("config: invalid duration")
	// ErrWeakSecret identifies a configured secret that is too short.
	ErrWeakSecret = errors.New("config: weak secret")
)

// Environment identifies deployment behavior that may vary by environment.
type Environment string

const (
	// EnvironmentDevelopment is the local-development environment.
	EnvironmentDevelopment Environment = "development"
	// EnvironmentTest is the isolated-test environment.
	EnvironmentTest Environment = "test"
	// EnvironmentProduction is the deployed environment.
	EnvironmentProduction Environment = "production"
)

// Secret stores sensitive configuration without exposing its value through
// formatting or JSON encoding.
type Secret struct {
	value string
}

// IsSet reports whether a secret was configured.
func (s Secret) IsSet() bool {
	return s.value != ""
}

// Reveal returns the configured value for code that must use the secret.
// Callers must not log, serialize, or include the returned value in responses.
func (s Secret) Reveal() string {
	return s.value
}

// String redacts configured secret values.
func (s Secret) String() string {
	if !s.IsSet() {
		return ""
	}
	return "[redacted]"
}

// GoString keeps %#v diagnostics redacted too.
func (s Secret) GoString() string {
	return fmt.Sprintf("config.Secret{configured:%t}", s.IsSet())
}

// MarshalJSON emits only a redacted marker for configured secrets.
func (s Secret) MarshalJSON() ([]byte, error) {
	if !s.IsSet() {
		return []byte("null"), nil
	}
	return json.Marshal("[redacted]")
}

// Config contains validated deployment configuration.
type Config struct {
	Environment               Environment
	HTTPAddress               string
	PublicURL                 url.URL
	SessionCookieSecure       bool
	EmailConfirmationRequired bool
	SessionLifetime           time.Duration
	DatabaseURL               Secret
	SessionSecret             Secret
}

// String returns a safe diagnostic summary without secret values.
func (c Config) String() string {
	return fmt.Sprintf(
		"environment=%s http_address=%s public_url=%s session_cookie_secure=%t email_confirmation_required=%t session_lifetime=%s database_configured=%t session_secret_configured=%t",
		c.Environment,
		c.HTTPAddress,
		c.PublicURL.String(),
		c.SessionCookieSecure,
		c.EmailConfirmationRequired,
		c.SessionLifetime,
		c.DatabaseURL.IsSet(),
		c.SessionSecret.IsSet(),
	)
}

// Load reads configuration through getenv, applies typed defaults, and rejects
// malformed values. Passing getenv explicitly keeps configuration deterministic
// in tests and avoids hidden process-global state.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, errors.New("config: nil environment lookup")
	}

	environment, err := parseEnvironment(getenv(EnvironmentEnv))
	if err != nil {
		return Config{}, err
	}
	httpAddress, err := parseHTTPAddress(valueOrDefault(getenv(HTTPAddressEnv), DefaultHTTPAddress))
	if err != nil {
		return Config{}, err
	}
	publicURL, err := parsePublicURL(valueOrDefault(getenv(PublicURLEnv), DefaultPublicURL))
	if err != nil {
		return Config{}, err
	}
	cookieSecure, err := parseBool(SessionCookieSecureEnv, getenv(SessionCookieSecureEnv), environment == EnvironmentProduction)
	if err != nil {
		return Config{}, err
	}
	emailConfirmationRequired, err := parseBool(EmailConfirmationRequiredEnv, getenv(EmailConfirmationRequiredEnv), false)
	if err != nil {
		return Config{}, err
	}
	sessionLifetime, err := parseSessionLifetime(getenv(SessionLifetimeEnv))
	if err != nil {
		return Config{}, err
	}
	sessionSecret := Secret{value: getenv(SessionSecretEnv)}
	if sessionSecret.IsSet() && len(sessionSecret.value) < MinimumSessionSecretLength {
		return Config{}, fmt.Errorf("%w: %s must contain at least %d characters", ErrWeakSecret, SessionSecretEnv, MinimumSessionSecretLength)
	}

	return Config{
		Environment:               environment,
		HTTPAddress:               httpAddress,
		PublicURL:                 publicURL,
		SessionCookieSecure:       cookieSecure,
		EmailConfirmationRequired: emailConfirmationRequired,
		SessionLifetime:           sessionLifetime,
		DatabaseURL:               Secret{value: getenv(DatabaseURLEnv)},
		SessionSecret:             sessionSecret,
	}, nil
}

func parseEnvironment(raw string) (Environment, error) {
	environment := Environment(strings.ToLower(strings.TrimSpace(raw)))
	if environment == "" {
		return DefaultEnvironment, nil
	}
	if environment != EnvironmentDevelopment && environment != EnvironmentTest && environment != EnvironmentProduction {
		return "", fmt.Errorf("%w: %s", ErrInvalidEnvironment, EnvironmentEnv)
	}
	return environment, nil
}

func parseHTTPAddress(address string) (string, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("%w: value must include host and port", ErrInvalidHTTPAddress)
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalidHTTPAddress)
	}

	return address, nil
}

func parsePublicURL(raw string) (url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return url.URL{}, fmt.Errorf("%w: value must be an http or https URL without credentials or query data", ErrInvalidPublicURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return url.URL{}, fmt.Errorf("%w: scheme must be http or https", ErrInvalidPublicURL)
	}
	return *parsed, nil
}

func parseBool(name, raw string, defaultValue bool) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%w: %s must be true or false", ErrInvalidBoolean, name)
	}
	return value, nil
}

func parseSessionLifetime(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultSessionLifetime, nil
	}
	lifetime, err := time.ParseDuration(raw)
	if err != nil || lifetime <= 0 {
		return 0, fmt.Errorf("%w: %s must be a positive duration", ErrInvalidDuration, SessionLifetimeEnv)
	}
	return lifetime, nil
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
