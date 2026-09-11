// Package app owns explicit application dependency composition.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	mailadapter "github.com/tewecske/goweb/internal/adapter/mail"
	"github.com/tewecske/goweb/internal/config"
	"github.com/tewecske/goweb/internal/service"
	postgresstore "github.com/tewecske/goweb/internal/store/postgres"
)

var ErrNilDatabase = errors.New("app: nil database")
var ErrMailDeliveryNotConfigured = errors.New("app: mail delivery not configured")

// Graph contains concrete PostgreSQL repositories and all currently
// implemented service use cases. It does not own Database; the server lifecycle
// closes that shared resource after HTTP shutdown.
type Graph struct {
	Database *sql.DB

	Users                *postgresstore.UserRepository
	Sessions             *postgresstore.SessionRepository
	GuestClaimRepository *postgresstore.GuestClaimCodeRepository
	EmailTokens          *postgresstore.EmailConfirmationTokenRepository
	PasswordReset        *postgresstore.PasswordResetTokenRepository
	OAuthStates          *postgresstore.OAuthStateRepository
	OAuthIdentities      *postgresstore.OAuthIdentityRepository
	Providers            *service.ProviderRegistry
	SessionService       *service.SessionService
	PasswordHasher       *service.PasswordHasher
	Mail                 *mailadapter.DevelopmentSender
	SignUp               *service.SignUpService
	SignIn               *service.RateLimitedSignInService
	Confirmation         *service.EmailConfirmationService
	ConfirmationResend   *service.EmailConfirmationResender
	PasswordResetter     *service.PasswordResetService
	PasswordConsumer     *service.PasswordResetConsumer
	OAuth                *service.OAuthSignInService
	GuestSession         *service.GuestSessionService
	GuestClaim           *service.GuestClaimService
	GuestRedemption      *service.GuestRedemptionService
	GuestUpgrade         *service.GuestUpgradeService
	GuestRateLimited     *service.RateLimitedGuestService
	GuestCleanup         *service.GuestCleanupService
	Theme                *service.ThemeService
}

// New constructs the service graph over one migrated database. It performs no
// database I/O; startup owns opening, migration, and closing Database.
func New(database *sql.DB, appConfig config.Config) (*Graph, error) {
	if database == nil {
		return nil, ErrNilDatabase
	}
	if appConfig.Environment == config.EnvironmentProduction {
		return nil, ErrMailDeliveryNotConfigured
	}

	users, err := postgresstore.NewUserRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct user repository: %w", err)
	}
	sessionsRepository, err := postgresstore.NewSessionRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct session repository: %w", err)
	}
	guestClaimsRepository, err := postgresstore.NewGuestClaimCodeRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct guest claim repository: %w", err)
	}
	emailTokens, err := postgresstore.NewEmailConfirmationTokenRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct email token repository: %w", err)
	}
	passwordResetTokens, err := postgresstore.NewPasswordResetTokenRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct password reset repository: %w", err)
	}
	oauthStates, err := postgresstore.NewOAuthStateRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct oauth state repository: %w", err)
	}
	oauthIdentities, err := postgresstore.NewOAuthIdentityRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct oauth identity repository: %w", err)
	}

	sessionService, err := service.NewSessionService(sessionsRepository, appConfig.SessionLifetime)
	if err != nil {
		return nil, fmt.Errorf("construct session service: %w", err)
	}
	passwordHasher, err := service.NewPasswordHasher(service.PasswordHashConfig{})
	if err != nil {
		return nil, fmt.Errorf("construct password hasher: %w", err)
	}
	mailSender := &mailadapter.DevelopmentSender{}
	signInLimiter, err := service.NewRateLimiter(service.RateLimitConfig{
		Limit: 10, Window: time.Minute, MaxKeys: 10_000,
	})
	if err != nil {
		return nil, fmt.Errorf("construct signin rate limiter: %w", err)
	}
	confirmationLimiter, err := service.NewRateLimiter(service.RateLimitConfig{Limit: 10, Window: time.Minute, MaxKeys: 10_000})
	if err != nil {
		return nil, fmt.Errorf("construct confirmation rate limiter: %w", err)
	}
	passwordResetLimiter, err := service.NewRateLimiter(service.RateLimitConfig{Limit: 10, Window: time.Minute, MaxKeys: 10_000})
	if err != nil {
		return nil, fmt.Errorf("construct password reset rate limiter: %w", err)
	}

	signUp, err := service.NewSignUpService(users, passwordHasher, sessionService, appConfig.EmailConfirmationRequired)
	if err != nil {
		return nil, fmt.Errorf("construct signup service: %w", err)
	}
	signInBase, err := service.NewSignInService(users, passwordHasher, sessionService, noopFailedAttemptState{}, appConfig.EmailConfirmationRequired)
	if err != nil {
		return nil, fmt.Errorf("construct signin service: %w", err)
	}
	signIn, err := service.NewRateLimitedSignInService(signInBase, signInLimiter)
	if err != nil {
		return nil, fmt.Errorf("construct rate limited signin service: %w", err)
	}
	confirmation, err := service.NewEmailConfirmationService(users, emailTokens, mailSender, appConfig.PublicURL, service.DefaultEmailConfirmationLifetime)
	if err != nil {
		return nil, fmt.Errorf("construct confirmation service: %w", err)
	}
	confirmationResend, err := service.NewEmailConfirmationResender(confirmation, confirmationLimiter)
	if err != nil {
		return nil, fmt.Errorf("construct confirmation resend service: %w", err)
	}
	passwordResetter, err := service.NewPasswordResetService(users, passwordResetTokens, mailSender, passwordResetLimiter, appConfig.PublicURL, service.DefaultPasswordResetLifetime)
	if err != nil {
		return nil, fmt.Errorf("construct password reset service: %w", err)
	}
	passwordConsumer, err := service.NewPasswordResetConsumer(users, passwordResetTokens, passwordHasher, sessionService)
	if err != nil {
		return nil, fmt.Errorf("construct password reset consumer: %w", err)
	}
	providers, err := service.NewProviderRegistry()
	if err != nil {
		return nil, fmt.Errorf("construct oauth provider registry: %w", err)
	}
	oauth, err := service.NewOAuthSignInService(providers, oauthStates, oauthIdentities, users, sessionService, service.DefaultOAuthStateLifetime)
	if err != nil {
		return nil, fmt.Errorf("construct oauth service: %w", err)
	}
	guestSession, err := service.NewGuestSessionService(users, sessionService)
	if err != nil {
		return nil, fmt.Errorf("construct guest session service: %w", err)
	}
	guestClaims, err := service.NewGuestClaimService(users, guestClaimsRepository)
	if err != nil {
		return nil, fmt.Errorf("construct guest claim service: %w", err)
	}
	guestRedemption, err := service.NewGuestRedemptionService(users, guestClaimsRepository, sessionService)
	if err != nil {
		return nil, fmt.Errorf("construct guest redemption service: %w", err)
	}
	guestUpgrade, err := service.NewGuestUpgradeService(users, passwordHasher, guestClaimsRepository)
	if err != nil {
		return nil, fmt.Errorf("construct guest upgrade service: %w", err)
	}
	guestLimiter, err := service.NewRateLimiter(service.RateLimitConfig{
		Limit: 10, Window: time.Minute, MaxKeys: 10_000,
	})
	if err != nil {
		return nil, fmt.Errorf("construct guest rate limiter: %w", err)
	}
	guestRateLimited, err := service.NewRateLimitedGuestService(guestSession, guestRedemption, guestLimiter)
	if err != nil {
		return nil, fmt.Errorf("construct rate limited guest service: %w", err)
	}
	guestCleanup, err := service.NewGuestCleanupService(guestClaimsRepository, 30*24*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("construct guest cleanup service: %w", err)
	}
	theme, err := service.NewThemeService(users)
	if err != nil {
		return nil, fmt.Errorf("construct theme service: %w", err)
	}

	return &Graph{
		Database: database, Users: users, Sessions: sessionsRepository,
		GuestClaimRepository: guestClaimsRepository, EmailTokens: emailTokens,
		PasswordReset: passwordResetTokens, OAuthStates: oauthStates,
		OAuthIdentities: oauthIdentities, SessionService: sessionService,
		Providers:      providers,
		PasswordHasher: passwordHasher, Mail: mailSender, SignUp: signUp,
		SignIn: signIn, Confirmation: confirmation,
		ConfirmationResend: confirmationResend, PasswordResetter: passwordResetter,
		PasswordConsumer: passwordConsumer, OAuth: oauth,
		GuestSession: guestSession, GuestClaim: guestClaims,
		GuestRedemption: guestRedemption, GuestUpgrade: guestUpgrade,
		GuestRateLimited: guestRateLimited, GuestCleanup: guestCleanup, Theme: theme,
	}, nil
}

type noopFailedAttemptState struct{}

func (noopFailedAttemptState) Clear(ctx context.Context, _ string) error {
	if ctx == nil {
		return errors.New("app: nil failed-attempt context")
	}
	return nil
}
