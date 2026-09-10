package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	httpadapter "github.com/tewecske/goweb/internal/adapter/http"
	"github.com/tewecske/goweb/internal/config"
)

func main() {
	appConfig, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              appConfig.HTTPAddress,
		Handler:           httpadapter.NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", appConfig.HTTPAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
