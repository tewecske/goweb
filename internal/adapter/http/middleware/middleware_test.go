package middleware

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChain(t *testing.T) {
	called := ""
	first := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			called += "first "
			next.ServeHTTP(writer, request)
		})
	}
	second := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			called += "second "
			next.ServeHTTP(writer, request)
		})
	}

	handler, err := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called += "handler" }), first, second)
	if err != nil {
		t.Fatalf("Chain() error = %v, want nil", err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if called != "first second handler" {
		t.Errorf("middleware order = %q, want %q", called, "first second handler")
	}

	for _, test := range []struct {
		name        string
		handler     http.Handler
		middlewares []Middleware
		wantErr     error
	}{
		{name: "nil handler", wantErr: ErrNilHandler},
		{name: "nil middleware", handler: http.NotFoundHandler(), middlewares: []Middleware{nil}, wantErr: ErrNilMiddleware},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Chain(test.handler, test.middlewares...)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Chain() error = %v, want errors.Is(_, %v)", err, test.wantErr)
			}
		})
	}
}

func TestWithRequestInfo(t *testing.T) {
	var got RequestInfo
	handler := WithRequestInfo()(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		var ok bool
		got, ok = RequestInfoFromContext(request.Context())
		if !ok {
			t.Error("RequestInfoFromContext() found no request info")
		}
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got.StartedAt.IsZero() {
		t.Error("RequestInfo.StartedAt is zero")
	}
}

func TestRecover(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := Recover(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("private value must not enter logs")
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if response.Body.String() != "internal server error\n" {
		t.Errorf("body = %q, want generic error", response.Body.String())
	}
}

func TestLog(t *testing.T) {
	logger := &testRequestLogger{}
	handler := Log(logger)(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/private?token=secret", nil))

	if logger.event.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", logger.event.Method)
	}
	if logger.event.Status != http.StatusNoContent {
		t.Errorf("status = %d, want %d", logger.event.Status, http.StatusNoContent)
	}
	if logger.event.Duration < 0 {
		t.Errorf("duration = %s, want non-negative", logger.event.Duration)
	}
}

func TestTrace(t *testing.T) {
	tracer := &testTracer{}
	handler := Trace(tracer)(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		if request.Context().Value(traceContextKey{}) != "trace" {
			t.Error("trace context value missing")
		}
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if tracer.method != http.MethodGet {
		t.Errorf("trace method = %q, want GET", tracer.method)
	}
	if !tracer.finished {
		t.Error("trace finish was not called")
	}
}

func TestRequireAuth(t *testing.T) {
	tests := []struct {
		name           string
		authenticator  Authenticator
		expectedStatus int
	}{
		{name: "missing authenticator", expectedStatus: http.StatusInternalServerError},
		{name: "unauthenticated", authenticator: authFunc(func(context.Context, *http.Request) (Principal, error) { return Principal{}, ErrUnauthenticated }), expectedStatus: http.StatusUnauthorized},
		{name: "authenticator failure", authenticator: authFunc(func(context.Context, *http.Request) (Principal, error) {
			return Principal{}, errors.New("backend failure")
		}), expectedStatus: http.StatusInternalServerError},
		{name: "authenticated", authenticator: authFunc(func(context.Context, *http.Request) (Principal, error) { return Principal{ID: "user-1"}, nil }), expectedStatus: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := RequireAuth(test.authenticator)(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				principal, ok := PrincipalFromContext(request.Context())
				if !ok || principal.ID != "user-1" {
					t.Error("authenticated principal missing from context")
				}
				writer.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

			if response.Code != test.expectedStatus {
				t.Errorf("status = %d, want %d", response.Code, test.expectedStatus)
			}
		})
	}
}

type authFunc func(context.Context, *http.Request) (Principal, error)

func (f authFunc) Authenticate(ctx context.Context, request *http.Request) (Principal, error) {
	return f(ctx, request)
}

type testRequestLogger struct {
	event RequestEvent
}

func (l *testRequestLogger) LogRequest(_ context.Context, event RequestEvent) {
	l.event = event
}

type traceContextKey struct{}

type testTracer struct {
	method   string
	finished bool
}

func (t *testTracer) Start(ctx context.Context, method string) (context.Context, func()) {
	t.method = method
	return context.WithValue(ctx, traceContextKey{}, "trace"), func() { t.finished = true }
}
