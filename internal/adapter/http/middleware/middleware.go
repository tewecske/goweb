// Package middleware contains reusable HTTP transport boundaries.
package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

var (
	// ErrNilHandler identifies a missing middleware chain handler.
	ErrNilHandler = errors.New("middleware: nil handler")
	// ErrNilMiddleware identifies a missing middleware function.
	ErrNilMiddleware = errors.New("middleware: nil middleware")
	// ErrUnauthenticated identifies a request without valid authentication.
	ErrUnauthenticated = errors.New("middleware: unauthenticated")
)

// Middleware transforms one HTTP handler into another.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares in request order and validates every boundary.
func Chain(handler http.Handler, middlewares ...Middleware) (http.Handler, error) {
	if handler == nil {
		return nil, ErrNilHandler
	}
	for index := len(middlewares) - 1; index >= 0; index-- {
		if middlewares[index] == nil {
			return nil, ErrNilMiddleware
		}
		handler = middlewares[index](handler)
		if handler == nil {
			return nil, ErrNilHandler
		}
	}
	return handler, nil
}

type requestInfoKey struct{}

// RequestInfo contains request-scoped timing metadata.
type RequestInfo struct {
	StartedAt time.Time
}

// WithRequestInfo adds request-scoped metadata to the context.
func WithRequestInfo() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			info := RequestInfo{StartedAt: time.Now()}
			ctx := context.WithValue(request.Context(), requestInfoKey{}, info)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

// RequestInfoFromContext returns request timing metadata when present.
func RequestInfoFromContext(ctx context.Context) (RequestInfo, bool) {
	if ctx == nil {
		return RequestInfo{}, false
	}
	info, ok := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info, ok
}

// Recover converts handler panics into generic server errors and logs only
// stable request fields. Panic values are intentionally not logged.
func Recover(logger *slog.Logger) Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			defer func() {
				if recover() == nil {
					return
				}
				logger.Error("http handler panic", "method", request.Method)
				http.Error(writer, "internal server error", http.StatusInternalServerError)
			}()
			next.ServeHTTP(writer, request)
		})
	}
}

// RequestEvent contains safe, low-cardinality request outcome fields.
type RequestEvent struct {
	Method   string
	Status   int
	Duration time.Duration
}

// RequestLogger receives request events without URL or credential fields.
type RequestLogger interface {
	LogRequest(context.Context, RequestEvent)
}

// Log records request method, status, and duration through logger.
func Log(logger RequestLogger) Middleware {
	return func(next http.Handler) http.Handler {
		if logger == nil {
			return next
		}
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			startedAt := time.Now()
			response := &statusWriter{ResponseWriter: writer}
			next.ServeHTTP(response, request)
			status := response.status
			if status == 0 {
				status = http.StatusOK
			}
			logger.LogRequest(request.Context(), RequestEvent{
				Method:   request.Method,
				Status:   status,
				Duration: time.Since(startedAt),
			})
		})
	}
}

// Tracer starts and finishes a request span using a consuming-side tracer.
type Tracer interface {
	Start(context.Context, string) (context.Context, func())
}

// Trace creates a low-cardinality span named by HTTP method.
func Trace(tracer Tracer) Middleware {
	return func(next http.Handler) http.Handler {
		if tracer == nil {
			return next
		}
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ctx, finish := tracer.Start(request.Context(), request.Method)
			if finish != nil {
				defer finish()
			}
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

// Principal identifies an authenticated account without exposing credentials.
type Principal struct {
	ID      string
	IsAdmin bool
}

// Authenticator resolves the authenticated principal for a request.
type Authenticator interface {
	Authenticate(context.Context, *http.Request) (Principal, error)
}

type principalKey struct{}

// RequireAuth protects routes with an injected authenticator.
func RequireAuth(authenticator Authenticator) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if authenticator == nil {
				http.Error(writer, "internal server error", http.StatusInternalServerError)
				return
			}

			principal, err := authenticator.Authenticate(request.Context(), request)
			if err != nil {
				if errors.Is(err, ErrUnauthenticated) {
					http.Error(writer, "authentication required", http.StatusUnauthorized)
					return
				}
				http.Error(writer, "internal server error", http.StatusInternalServerError)
				return
			}

			ctx := context.WithValue(request.Context(), principalKey{}, principal)
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}

// PrincipalFromContext returns the authenticated principal when present.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalKey{}).(Principal)
	return principal, ok
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}
