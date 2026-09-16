package main

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpadapter "github.com/tewecske/goweb/internal/adapter/http"
	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/app"
	"github.com/tewecske/goweb/internal/config"
	appserver "github.com/tewecske/goweb/internal/server"
	"github.com/tewecske/goweb/internal/store"
	"github.com/tewecske/goweb/migrations"
)

func main() {
	appConfig, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	applicationLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	securityLogger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	logger := httpadapter.NewLogger(applicationLogger, securityLogger)
	router := httpadapter.NewLoggedRouter(logger)

	var serverOptions []appserver.Option
	var database *sql.DB
	var applicationGraph *app.Graph
	if appConfig.DatabaseURL.IsSet() {
		startupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var openErr error
		database, openErr = store.Open(startupContext, appConfig.DatabaseURL.Reveal())
		if openErr != nil {
			cancel()
			log.Fatal(openErr)
		}

		migrator, migrateErr := store.NewMigrator(database, migrations.FS)
		if migrateErr != nil {
			cancel()
			_ = database.Close()
			log.Fatal(migrateErr)
		}
		migrateErr = migrator.Apply(startupContext)
		cancel()
		if migrateErr != nil {
			_ = database.Close()
			log.Fatal(migrateErr)
		}
		var composeErr error
		applicationGraph, composeErr = app.New(database, appConfig)
		if composeErr != nil {
			_ = database.Close()
			log.Fatal(composeErr)
		}
		seedContext, seedCancel := context.WithTimeout(context.Background(), 10*time.Second)
		seedErr := app.EnsureBootstrapAdmin(seedContext, applicationGraph, appConfig)
		seedCancel()
		if seedErr != nil {
			_ = database.Close()
			log.Fatal(seedErr)
		}
		sessionCookie, cookieErr := middleware.NewSessionCookie(middleware.SessionCookieConfig{
			Secure:   appConfig.SessionCookieSecure,
			Lifetime: appConfig.SessionLifetime,
		})
		if cookieErr != nil {
			_ = database.Close()
			log.Fatal(cookieErr)
		}
		applicationGraph.Audit.SetSink(httpadapter.NewAuditSecuritySink(logger))
		applicationGraph.RuntimeInfo.SetMigrations(app.NewMigrationStatusProvider(migrator))
		serverOptions = append(serverOptions, appserver.WithDependency(database))
		router = httpadapter.NewLoggedRouterWithServices(logger, httpadapter.Dependencies{
			Users:                applicationGraph.Users,
			Sessions:             applicationGraph.SessionService,
			SessionAdmin:         applicationGraph.SessionService,
			SessionCookie:        sessionCookie,
			SignUp:               applicationGraph.SignUp,
			SignIn:               applicationGraph.SignIn,
			SignOut:              applicationGraph.SessionService,
			ConfirmationIssuer:   applicationGraph.Confirmation,
			ConfirmationResender: applicationGraph.ConfirmationResend,
			ConfirmationConsumer: applicationGraph.Confirmation,
			PasswordResetter:     applicationGraph.PasswordResetter,
			PasswordResetterUse:  applicationGraph.PasswordConsumer,
			OAuth:                applicationGraph.OAuth,
			OAuthProviders:       applicationGraph.Providers,
			GuestCreator:         applicationGraph.GuestRateLimited,
			GuestClaimer:         applicationGraph.GuestClaim,
			GuestRedeemer:        applicationGraph.GuestRateLimited,
			GuestUpgrader:        applicationGraph.GuestUpgrade,
			ProfileSettings:      applicationGraph.ProfileSettings,
			PasswordSettings:     applicationGraph.PasswordSettings,
			LocaleSettings:       applicationGraph.LocaleSettings,
			ThemeUpdater:         applicationGraph.Theme,
			IdentityLister:       applicationGraph.OAuthIdentities,
			IdentityUnlinker:     applicationGraph.OAuth,
			IdentityLink:         applicationGraph.OAuth,
			Groups:               applicationGraph.Group,
			GroupInvites:         applicationGraph.Group,
			JoinGroup:            applicationGraph.GroupJoin,
			AdminAccounts:        applicationGraph.AdminAccounts,
			AdminAccountCreator:  applicationGraph.AdminAccounts,
			AdminAccountEditor:   applicationGraph.AdminAccounts,
			AdminUserDetailer:    applicationGraph.AdminDiagnostics,
			AdminSessionRevoker:  applicationGraph.AdminAccounts,
			AdminConfirmation:    applicationGraph.AdminConfirmation,
			AdminIdentity:        applicationGraph.AdminIdentity,
			AdminLockout:         applicationGraph.Lockout,
			AdminAudit:           applicationGraph.Audit,
			AdminMaintenance:     applicationGraph.Maintenance,
			AdminAuditRecorder:   applicationGraph.Audit,
			AdminSystemConfig:    applicationGraph.SystemInfo,
			AdminRuntime:         applicationGraph.RuntimeInfo,
			AdminDatastoreStats:  applicationGraph.DatastoreStatsService,
			AdminRateLimits:      applicationGraph.RateLimits,
			Usage:                httpadapter.NewUsageRecorder(applicationGraph.Usage),
			AdminUsage:           applicationGraph.UsageReportService,
			AdminSuspicious:      applicationGraph.SuspiciousService,
		})
	}

	server, err := appserver.New(appConfig.HTTPAddress, router, serverOptions...)
	if err != nil {
		if database != nil {
			_ = database.Close()
		}
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if applicationGraph != nil && applicationGraph.Maintenance != nil {
		applicationGraph.Maintenance.SetLogger(applicationLogger)
		go func() {
			if err := applicationGraph.Maintenance.Run(ctx); err != nil {
				applicationLogger.Error("maintenance worker stopped", "error", err)
			}
		}()
	}
	if applicationGraph != nil && applicationGraph.Usage != nil {
		applicationGraph.Usage.SetLogger(applicationLogger)
		go func() {
			if err := applicationGraph.Usage.Run(ctx); err != nil {
				applicationLogger.Error("usage queue stopped", "error", err)
			}
		}()
	}

	logger.Application().Info("server listening", "address", appConfig.HTTPAddress)
	if err := server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
