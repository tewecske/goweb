package main

import (
	"context"
	"errors"
	"log"
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

	server, err := appserver.New(appConfig.HTTPAddress, httpadapter.NewHandler())
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("listening on %s", appConfig.HTTPAddress)
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
