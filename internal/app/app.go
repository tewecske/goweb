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
	Groups               *postgresstore.GroupRepository
	GroupMemberships     *postgresstore.GroupMembershipRepository
	AdminUsers           *postgresstore.AdminUserRepository
	AuditLogs            *postgresstore.AuditLogRepository
	LoginAttempts        *postgresstore.LoginAttemptRepository
	Retention            *postgresstore.RetentionRepository
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
	ProfileSettings      *service.ProfileSettingsService
	PasswordSettings     *service.PasswordSettingsService
	LocaleSettings       *service.LocaleSettingsService
	Group                *service.GroupService
	GroupJoin            *service.RateLimitedGroupJoiner
	AdminAccounts        *service.AdminAccountService
	AdminConfirmation    *service.AdminConfirmationService
	AdminIdentity        *service.AdminIdentityService
	Lockout              *service.LockoutService
	AdminDiagnostics     *service.AdminDiagnosticsService
	Audit                *service.AuditService
	Maintenance          *service.MaintenanceWorker
	RetentionService     *service.RetentionService
	SystemInfo           *service.SystemInfoService
	RuntimeInfo          *service.RuntimeInfoService
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
	appConfig = withRetentionDefaults(appConfig)

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
	groupsRepository, err := postgresstore.NewGroupRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct group repository: %w", err)
	}
	groupMembershipsRepository, err := postgresstore.NewGroupMembershipRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct group membership repository: %w", err)
	}
	adminUsersRepository, err := postgresstore.NewAdminUserRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct admin user repository: %w", err)
	}
	auditLogRepository, err := postgresstore.NewAuditLogRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct audit log repository: %w", err)
	}
	loginAttemptsRepository, err := postgresstore.NewLoginAttemptRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct login attempt repository: %w", err)
	}
	retentionRepository, err := postgresstore.NewRetentionRepository(database)
	if err != nil {
		return nil, fmt.Errorf("construct retention repository: %w", err)
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
	signInLimiter, err := service.NewRateLimiter(service.DefaultAuthenticationRateLimitConfig)
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
	signIn, err := service.NewRateLimitedSignInServiceWithRecorder(signInBase, signInLimiter, loginAttemptsRepository)
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
	guestCleanup, err := service.NewGuestCleanupService(guestClaimsRepository, appConfig.GuestRetention)
	if err != nil {
		return nil, fmt.Errorf("construct guest cleanup service: %w", err)
	}
	theme, err := service.NewThemeService(users)
	if err != nil {
		return nil, fmt.Errorf("construct theme service: %w", err)
	}
	profileSettings, err := service.NewProfileSettingsService(users)
	if err != nil {
		return nil, fmt.Errorf("construct profile settings service: %w", err)
	}
	passwordSettings, err := service.NewPasswordSettingsService(users, passwordHasher, passwordHasher)
	if err != nil {
		return nil, fmt.Errorf("construct password settings service: %w", err)
	}
	localeSettings, err := service.NewLocaleSettingsService(users)
	if err != nil {
		return nil, fmt.Errorf("construct locale settings service: %w", err)
	}
	groupService, err := service.NewGroupService(groupsRepository, groupMembershipsRepository, users)
	if err != nil {
		return nil, fmt.Errorf("construct group service: %w", err)
	}
	groupJoinLimiter, err := service.NewRateLimiter(service.RateLimitConfig{
		Limit: 20, Window: time.Minute, MaxKeys: 10_000,
	})
	if err != nil {
		return nil, fmt.Errorf("construct group join rate limiter: %w", err)
	}
	groupJoinService, err := service.NewRateLimitedGroupJoiner(groupService, groupJoinLimiter)
	if err != nil {
		return nil, fmt.Errorf("construct group join service: %w", err)
	}
	auditService, err := service.NewAuditService(auditLogRepository)
	if err != nil {
		return nil, fmt.Errorf("construct audit service: %w", err)
	}
	adminAccounts, err := service.NewAdminAccountService(users, adminUsersRepository, passwordHasher, auditService, sessionService)
	if err != nil {
		return nil, fmt.Errorf("construct admin account service: %w", err)
	}
	adminDiagnostics, err := service.NewAdminDiagnosticsService(users, sessionsRepository, loginAttemptsRepository, oauthIdentities, emailTokens)
	if err != nil {
		return nil, fmt.Errorf("construct admin diagnostics service: %w", err)
	}
	adminConfirmation, err := service.NewAdminConfirmationService(users, confirmation, auditService)
	if err != nil {
		return nil, fmt.Errorf("construct admin confirmation service: %w", err)
	}
	adminIdentity, err := service.NewAdminIdentityService(users, oauth, auditService)
	if err != nil {
		return nil, fmt.Errorf("construct admin identity service: %w", err)
	}
	lockoutService, err := service.NewLockoutService(signInLimiter, loginAttemptsRepository, auditService)
	if err != nil {
		return nil, fmt.Errorf("construct lockout service: %w", err)
	}
	retentionService, err := service.NewRetentionService(retentionRepository, appConfig.LoginAttemptRetention, appConfig.UsageRetention)
	if err != nil {
		return nil, fmt.Errorf("construct retention service: %w", err)
	}
	maintenanceWorker, err := service.NewMaintenanceWorker(
		service.DefaultMaintenanceInterval,
		service.MaintenanceJob{Name: service.MaintenanceJobGuestCleanup, Run: guestCleanup.Cleanup},
		service.MaintenanceJob{Name: service.MaintenanceJobTokenRetention, Run: retentionService.CleanupTokens},
		service.MaintenanceJob{Name: service.MaintenanceJobLoginAttemptRetention, Run: retentionService.CleanupLoginAttempts},
		service.MaintenanceJob{Name: service.MaintenanceJobUsageRetention, Run: retentionService.CleanupUsageEvents},
	)
	if err != nil {
		return nil, fmt.Errorf("construct maintenance worker: %w", err)
	}
	runtimeInfo := service.NewRuntimeInfoService(time.Now())
	systemInfo := service.NewSystemInfoService(service.SystemInfoSettings{
		Environment:               string(appConfig.Environment),
		PublicAddress:             appConfig.HTTPAddress,
		PublicURL:                 appConfig.PublicURL.String(),
		EmailConfirmationRequired: appConfig.EmailConfirmationRequired,
		SecureSessionCookies:      appConfig.SessionCookieSecure,
		Providers:                 providers.Names(),
		MailConfigured:            true,
		MailRelay:                 appConfig.MailRelay.Reveal(),
		SessionLifetime:           appConfig.SessionLifetime,
		GuestRetention:            appConfig.GuestRetention,
		LoginAttemptRetention:     appConfig.LoginAttemptRetention,
		UsageRetention:            appConfig.UsageRetention,
		MaintenanceInterval:       maintenanceWorker.Interval(),
		TrustedProxy:              appConfig.TrustedProxy,
	})

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
		ProfileSettings: profileSettings, PasswordSettings: passwordSettings, LocaleSettings: localeSettings,
		Groups: groupsRepository, GroupMemberships: groupMembershipsRepository, Group: groupService, GroupJoin: groupJoinService,
		AdminUsers: adminUsersRepository, AdminAccounts: adminAccounts,
		AuditLogs: auditLogRepository, Audit: auditService,
		LoginAttempts: loginAttemptsRepository, AdminDiagnostics: adminDiagnostics,
		AdminConfirmation: adminConfirmation, AdminIdentity: adminIdentity, Lockout: lockoutService,
		Maintenance: maintenanceWorker, Retention: retentionRepository, RetentionService: retentionService,
		SystemInfo:  systemInfo,
		RuntimeInfo: runtimeInfo,
	}, nil
}

type noopFailedAttemptState struct{}

func (noopFailedAttemptState) Clear(ctx context.Context, _ string) error {
	if ctx == nil {
		return errors.New("app: nil failed-attempt context")
	}
	return nil
}

// withRetentionDefaults keeps graph construction usable when a caller provides
// a partial configuration in tests or tooling.
func withRetentionDefaults(appConfig config.Config) config.Config {
	if appConfig.GuestRetention <= 0 {
		appConfig.GuestRetention = config.DefaultGuestRetention
	}
	if appConfig.LoginAttemptRetention <= 0 {
		appConfig.LoginAttemptRetention = config.DefaultLoginAttemptRetention
	}
	if appConfig.UsageRetention <= 0 {
		appConfig.UsageRetention = config.DefaultUsageRetention
	}
	return appConfig
}
