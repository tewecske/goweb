package httpadapter

import (
	"context"
	"log/slog"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
)

// Logger emits structured application and security events.
type Logger struct {
	application *slog.Logger
	security    *slog.Logger
}

// NewLogger creates a logger with independently identifiable output streams.
// A nil security logger reuses application output with a security stream field.
func NewLogger(application, security *slog.Logger) *Logger {
	if application == nil {
		application = slog.Default()
	}
	if security == nil {
		security = application
	}
	return &Logger{application: application, security: security}
}

// Application returns application logger for lifecycle events.
func (l *Logger) Application() *slog.Logger {
	return l.application
}

// LogRequest implements middleware.RequestLogger with safe stable fields.
func (l *Logger) LogRequest(ctx context.Context, event middleware.RequestEvent) {
	l.application.InfoContext(ctx, "http request",
		"request_id", event.RequestID,
		"method", event.Method,
		"status", event.Status,
		"duration_ms", event.Duration.Milliseconds(),
	)
}

// SecurityEvent contains stable security-event fields without credentials.
type SecurityEvent struct {
	RequestID string
	Action    string
	Outcome   string
}

// LogSecurity emits an identifiable security event without sensitive values.
func (l *Logger) LogSecurity(ctx context.Context, event SecurityEvent) {
	l.security.WarnContext(ctx, "security event",
		"stream", "security",
		"request_id", event.RequestID,
		"action", event.Action,
		"outcome", event.Outcome,
	)
}

var _ middleware.RequestLogger = (*Logger)(nil)
