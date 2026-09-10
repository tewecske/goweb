package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{name: "health check", method: http.MethodGet, path: "/healthz", expectedStatus: http.StatusOK, expectedBody: "ok\n"},
		{name: "wrong method", method: http.MethodPost, path: "/healthz", expectedStatus: http.StatusMethodNotAllowed, expectedBody: "Method Not Allowed\n"},
		{name: "unknown route", method: http.MethodGet, path: "/missing", expectedStatus: http.StatusNotFound, expectedBody: "404 page not found\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()

			NewHandler().ServeHTTP(response, request)

			if response.Code != test.expectedStatus {
				t.Errorf("status = %d, want %d", response.Code, test.expectedStatus)
			}
			if response.Body.String() != test.expectedBody {
				t.Errorf("body = %q, want %q", response.Body.String(), test.expectedBody)
			}
		})
	}
}

func TestNewHandlerAddsRequestID(t *testing.T) {
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	requestID := response.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Fatal("X-Request-ID header is empty")
	}
	if len(requestID) != 32 {
		t.Errorf("request id length = %d, want 32", len(requestID))
	}
}
