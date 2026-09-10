package httpadapter

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
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
