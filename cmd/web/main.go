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
		applicationGraph, composeErr := app.New(database, appConfig)
		if composeErr != nil {
			_ = database.Close()
			log.Fatal(composeErr)
		}
		sessionCookie, cookieErr := middleware.NewSessionCookie(middleware.SessionCookieConfig{
			Secure:   appConfig.SessionCookieSecure,
			Lifetime: appConfig.SessionLifetime,
		})
		if cookieErr != nil {
			_ = database.Close()
			log.Fatal(cookieErr)
		}
		serverOptions = append(serverOptions, appserver.WithDependency(database))
		router = httpadapter.NewLoggedRouterWithServices(logger, httpadapter.Dependencies{
			Users:         applicationGraph.Users,
			Sessions:      applicationGraph.SessionService,
			SessionAdmin:  applicationGraph.SessionService,
			SessionCookie: sessionCookie,
			SignUp:        applicationGraph.SignUp,
			SignIn:        applicationGraph.SignIn,
			SignOut:       applicationGraph.SessionService,
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

	logger.Application().Info("server listening", "address", appConfig.HTTPAddress)
	if err := server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
