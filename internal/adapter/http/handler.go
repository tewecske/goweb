// Package httpadapter provides the HTTP transport adapter.
package httpadapter

import (
	"log/slog"
	"net/http"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
)

// NewHandler builds the HTTP handler for public foundation routes.
func NewHandler() http.Handler {
	return NewRouter()
}

// NewRouter builds public routes and applies shared transport boundaries.
func NewRouter(extra ...middleware.Middleware) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)

	shared := []middleware.Middleware{
		middleware.WithRequestInfo(),
		middleware.Recover(slog.Default()),
	}
	shared = append(shared, extra...)
	handler, err := middleware.Chain(mux, shared...)
	if err != nil {
		panic(err)
	}
	return handler
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
