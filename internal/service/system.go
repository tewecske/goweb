package service

import (
	"net/url"
	"strings"
	"time"
)

// Baseline authentication rate-limit policy. These values are safe to publish
// on the administrator system overview; they never include limiter keys.
const (
	AuthenticationRateLimit        = 10
	AuthenticationRateLimitWindow  = time.Minute
	AuthenticationRateLimitMaxKeys = 10_000
)

// SystemInfoSettings contains the deployment facts assembled at startup. Every
// field is credential-free; connection addresses are sanitized before use.
type SystemInfoSettings struct {
	Environment               string
	PublicAddress             string
	PublicURL                 string
	EmailConfirmationRequired bool
	SecureSessionCookies      bool
	Providers                 []string
	MailConfigured            bool
	MailRelay                 string
	SessionLifetime           time.Duration
	GuestRetention            time.Duration
	LoginAttemptRetention     time.Duration
	UsageRetention            time.Duration
	MaintenanceInterval       time.Duration
	TrustedProxy              string
}

// SystemConfiguration is the safe configuration overview. It never carries
// passwords, hashes, tokens, provider secrets, mail credentials, database
// credentials, or query strings.
type SystemConfiguration struct {
	Environment               string
	PublicAddress             string
	PublicURL                 string
	EmailConfirmationRequired bool
	SecureSessionCookies      bool
	Providers                 []string
	MailConfigured            bool
	MailRelay                 string
	SessionLifetime           time.Duration
	GuestRetention            time.Duration
	LoginAttemptRetention     time.Duration
	UsageRetention            time.Duration
	MaintenanceInterval       time.Duration
	AuthRateLimit             int
	AuthRateLimitWindow       time.Duration
	AuthRateLimitMaxKeys      int
	TrustedProxy              string
}

// SystemConfigurationProvider supplies the safe deployment summary.
type SystemConfigurationProvider interface {
	SystemConfiguration() SystemConfiguration
}

// SystemInfoService reports safe deployment configuration facts.
type SystemInfoService struct {
	settings SystemInfoSettings
}

// NewSystemInfoService constructs the configuration overview and sanitizes
// every connection address.
func NewSystemInfoService(settings SystemInfoSettings) *SystemInfoService {
	settings.PublicURL = sanitizeURL(settings.PublicURL)
	settings.MailRelay = sanitizeURL(settings.MailRelay)
	settings.TrustedProxy = strings.TrimSpace(settings.TrustedProxy)
	providers := make([]string, 0, len(settings.Providers))
	for _, provider := range settings.Providers {
		if name := strings.TrimSpace(provider); name != "" {
			providers = append(providers, name)
		}
	}
	settings.Providers = providers
	return &SystemInfoService{settings: settings}
}

// SystemConfiguration returns a copy of the safe configuration overview.
func (s *SystemInfoService) SystemConfiguration() SystemConfiguration {
	if s == nil {
		return SystemConfiguration{}
	}
	configuration := SystemConfiguration{
		Environment:               s.settings.Environment,
		PublicAddress:             s.settings.PublicAddress,
		PublicURL:                 s.settings.PublicURL,
		EmailConfirmationRequired: s.settings.EmailConfirmationRequired,
		SecureSessionCookies:      s.settings.SecureSessionCookies,
		MailConfigured:            s.settings.MailConfigured,
		MailRelay:                 s.settings.MailRelay,
		SessionLifetime:           s.settings.SessionLifetime,
		GuestRetention:            s.settings.GuestRetention,
		LoginAttemptRetention:     s.settings.LoginAttemptRetention,
		UsageRetention:            s.settings.UsageRetention,
		MaintenanceInterval:       s.settings.MaintenanceInterval,
		AuthRateLimit:             AuthenticationRateLimit,
		AuthRateLimitWindow:       AuthenticationRateLimitWindow,
		AuthRateLimitMaxKeys:      AuthenticationRateLimitMaxKeys,
		TrustedProxy:              s.settings.TrustedProxy,
	}
	configuration.Providers = append([]string(nil), s.settings.Providers...)
	return configuration
}

// sanitizeURL reduces a connection address to scheme and host. Credentials,
// paths, queries, and fragments are removed so nothing sensitive is displayed.
func sanitizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
