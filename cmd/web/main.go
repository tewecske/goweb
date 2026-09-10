package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	httpadapter "github.com/tewecske/goweb/internal/adapter/http"
	"github.com/tewecske/goweb/internal/config"
	appserver "github.com/tewecske/goweb/internal/server"
)

func main() {
	appConfig, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	applicationLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	securityLogger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	logger := httpadapter.NewLogger(applicationLogger, securityLogger)

	server, err := appserver.New(appConfig.HTTPAddress, httpadapter.NewLoggedRouter(logger))
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
