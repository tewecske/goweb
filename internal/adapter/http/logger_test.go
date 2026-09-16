package httpadapter

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

func TestLoggerEmitsSafeStructuredEvents(t *testing.T) {
	var applicationOutput bytes.Buffer
	var securityOutput bytes.Buffer
	logger := NewLogger(
		slog.New(slog.NewJSONHandler(&applicationOutput, nil)),
		slog.New(slog.NewJSONHandler(&securityOutput, nil)),
	)

	logger.LogRequest(context.Background(), middleware.RequestEvent{
		RequestID: "request-123",
		Method:    "GET",
		Status:    200,
		Duration:  4 * time.Millisecond,
	})
	logger.LogSecurity(context.Background(), SecurityEvent{
		RequestID: "request-123",
		Action:    "login",
		Outcome:   "failure",
	})

	applicationLog := applicationOutput.String()
	if !strings.Contains(applicationLog, `"request_id":"request-123"`) || !strings.Contains(applicationLog, `"status":200`) {
		t.Errorf("application log missing stable fields: %s", applicationLog)
	}
	securityLog := securityOutput.String()
	if !strings.Contains(securityLog, `"stream":"security"`) || !strings.Contains(securityLog, `"action":"login"`) {
		t.Errorf("security log missing stable fields: %s", securityLog)
	}
	if strings.Contains(applicationLog+securityLog, "password") {
		t.Error("logs contain credential-related field")
	}
}

func TestAuditSecuritySinkEmitsRequestScopedSecurityEvent(t *testing.T) {
	var securityOutput bytes.Buffer
	logger := NewLogger(nil, slog.New(slog.NewJSONHandler(&securityOutput, nil)))
	sink := NewAuditSecuritySink(logger)

	request := httptest.NewRequest("POST", "/en/admin/users/new", nil)
	handler, err := middleware.Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sink.AuditRecorded(r.Context(), service.AuditRecord{
			ActorUserID: 1,
			Action:      service.AuditActionAccountCreated,
			TargetID:    "9",
			Detail:      "target@example.test",
		})
	}), middleware.WithRequestID(func() (string, error) { return "req-fixed", nil }))
	if err != nil {
		t.Fatalf("Chain() error = %v", err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), request)

	logged := securityOutput.String()
	if !strings.Contains(logged, `"stream":"security"`) ||
		!strings.Contains(logged, `"action":"admin.account.created"`) ||
		!strings.Contains(logged, `"request_id":"req-fixed"`) {
		t.Fatalf("security log missing stable fields: %s", logged)
	}
	if strings.Contains(logged, "target@example.test") || strings.Contains(logged, "detail") {
		t.Fatalf("security log leaked audit detail: %s", logged)
	}
}
