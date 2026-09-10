package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestNewHandlerRendersHomeLayout(t *testing.T) {
	response := httptest.NewRecorder()
	NewHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "text/html; charset=utf-8" {
		t.Errorf("content type = %q, want text/html; charset=utf-8", contentType)
	}
	body := response.Body.String()
	for _, fragment := range []string{
		"<!doctype html>",
		`<html lang="en">`,
		"<title>GoWeb</title>",
		`<h1 id="page-heading"`,
		"Welcome to GoWeb",
		`aria-label="Primary navigation"`,
		`id="alerts"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Errorf("home body missing %q", fragment)
		}
	}
}

func TestNewHandlerRendersHTMXFragment(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()

	NewHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if response.Header().Get("Vary") != "HX-Request" {
		t.Errorf("vary = %q, want HX-Request", response.Header().Get("Vary"))
	}
	body := response.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Error("HTMX response contains full document")
	}
	for _, fragment := range []string{`<section aria-labelledby="page-heading">`, `<h1 id="page-heading"`, "Welcome to GoWeb"} {
		if !strings.Contains(body, fragment) {
			t.Errorf("HTMX response missing %q", fragment)
		}
	}
}
