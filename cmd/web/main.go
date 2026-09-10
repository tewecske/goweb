package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpadapter "github.com/tewecske/goweb/internal/adapter/http"
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

	var serverOptions []appserver.Option
	if appConfig.DatabaseURL.IsSet() {
		startupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		database, openErr := store.Open(startupContext, appConfig.DatabaseURL.Reveal())
		cancel()
		if openErr != nil {
			log.Fatal(openErr)
		}

		migrator, migrateErr := store.NewMigrator(database, migrations.FS)
		if migrateErr != nil {
			_ = database.Close()
			log.Fatal(migrateErr)
		}
		if migrateErr := migrator.Apply(context.Background()); migrateErr != nil {
			_ = database.Close()
			log.Fatal(migrateErr)
		}
		serverOptions = append(serverOptions, appserver.WithDependency(database))
	}

	server, err := appserver.New(appConfig.HTTPAddress, httpadapter.NewLoggedRouter(logger), serverOptions...)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Application().Info("server listening", "address", appConfig.HTTPAddress)
	if err := server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
