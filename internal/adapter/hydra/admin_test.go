package hydra

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/service"
)

type recordedRequest struct {
	method string
	path   string
	query  string
	body   map[string]any
}

// fakeHydra answers every request with status and body and records requests.
func fakeHydra(t *testing.T, status int, body string) (*AdminClient, *[]recordedRequest) {
	t.Helper()
	var requests []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorded := recordedRequest{method: request.Method, path: request.URL.Path, query: request.URL.RawQuery}
		if raw, _ := io.ReadAll(request.Body); len(raw) > 0 {
			if err := json.Unmarshal(raw, &recorded.body); err != nil {
				t.Errorf("request body is not JSON: %s", raw)
			}
		}
		requests = append(requests, recorded)
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, body)
	}))
	t.Cleanup(server.Close)
	client, err := NewAdminClient(server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	return client, &requests
}

func TestNewAdminClientRejectsUnusableAddresses(t *testing.T) {
	for _, raw := range []string{"", "127.0.0.1:4445", "ftp://hydra", "http://user:pw@hydra:4445"} {
		if _, err := NewAdminClient(raw, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewAdminClient(%q) error = %v, want %v", raw, err, ErrInvalidConfig)
		}
	}
}

func TestLoginRequestAndAccept(t *testing.T) {
	client, requests := fakeHydra(t, http.StatusOK, `{"skip":true,"subject":"42","session_id":"sid-1","client":{"client_id":"notes","client_name":"Notes app"},"redirect_to":"http://127.0.0.1:4444/oauth2/auth?login_verifier=v"}`)
	request, err := client.LoginRequest(context.Background(), "chal=")
	if err != nil {
		t.Fatalf("LoginRequest() error = %v", err)
	}
	if request != (service.SSOLoginRequest{Skip: true, Subject: "42", SessionID: "sid-1", ClientName: "Notes app"}) {
		t.Fatalf("LoginRequest() = %+v", request)
	}
	target, err := client.AcceptLogin(context.Background(), "chal=", "42", 8*time.Hour)
	if err != nil || target != "http://127.0.0.1:4444/oauth2/auth?login_verifier=v" {
		t.Fatalf("AcceptLogin() = %q, %v", target, err)
	}
	got := (*requests)[1]
	if got.method != http.MethodPut || got.path != "/admin/oauth2/auth/requests/login/accept" || got.query != "login_challenge=chal%3D" {
		t.Fatalf("accept request = %s %s?%s", got.method, got.path, got.query)
	}
	if got.body["subject"] != "42" || got.body["remember"] != true || got.body["remember_for"] != float64(28800) {
		t.Fatalf("accept body = %v, want subject 42 remembered for 28800 seconds", got.body)
	}
	if first := (*requests)[0]; first.method != http.MethodGet || first.path != "/admin/oauth2/auth/requests/login" {
		t.Fatalf("login request = %s %s", first.method, first.path)
	}
}

func TestAcceptConsentSendsClaimsInTheIDTokenSession(t *testing.T) {
	client, requests := fakeHydra(t, http.StatusOK, `{"redirect_to":"http://127.0.0.1:4444/oauth2/auth?consent_verifier=v"}`)
	_, err := client.AcceptConsent(context.Background(), "c", service.SSOConsentGrant{
		Scope:         []string{"openid", "email"},
		IDTokenClaims: map[string]any{"email": "ada@example.test"},
		RememberFor:   time.Hour,
	})
	if err != nil {
		t.Fatalf("AcceptConsent() error = %v", err)
	}
	body := (*requests)[0].body
	session, _ := body["session"].(map[string]any)
	idToken, _ := session["id_token"].(map[string]any)
	if idToken["email"] != "ada@example.test" {
		t.Fatalf("session = %v, want claims under session.id_token", body["session"])
	}
	// A nil audience must be sent as [] because Hydra rejects null.
	if audience, ok := body["grant_access_token_audience"].([]any); !ok || len(audience) != 0 {
		t.Fatalf("audience = %#v, want an empty list", body["grant_access_token_audience"])
	}
	if body["remember_for"] != float64(3600) {
		t.Fatalf("remember_for = %v, want 3600", body["remember_for"])
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   error
	}{
		{name: "unknown challenge", status: http.StatusNotFound, want: service.ErrSSOChallengeExpired},
		{name: "already handled", status: http.StatusGone, want: service.ErrSSOChallengeExpired},
		{name: "server failure", status: http.StatusInternalServerError, want: service.ErrSSOUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := fakeHydra(t, test.status, `{"error":"secret-detail-from-hydra"}`)
			_, err := client.ConsentRequest(context.Background(), "c")
			if !errors.Is(err, test.want) {
				t.Fatalf("ConsentRequest() error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), "secret-detail") {
				t.Fatalf("error leaked the response body: %v", err)
			}
		})
	}
}

func TestRejectsUnsafeRedirects(t *testing.T) {
	for _, target := range []string{"", "/relative", "javascript:alert(1)"} {
		client, _ := fakeHydra(t, http.StatusOK, `{"redirect_to":"`+target+`"}`)
		if _, err := client.AcceptLogout(context.Background(), "c"); !errors.Is(err, service.ErrSSOUnavailable) {
			t.Errorf("AcceptLogout() with redirect %q error = %v, want %v", target, err, service.ErrSSOUnavailable)
		}
	}
}

func TestRevocations(t *testing.T) {
	client, requests := fakeHydra(t, http.StatusNoContent, "")
	if err := client.RevokeLoginSession(context.Background(), "sid-1"); err != nil {
		t.Fatalf("RevokeLoginSession() error = %v", err)
	}
	if err := client.RevokeConsentSessions(context.Background(), "42"); err != nil {
		t.Fatalf("RevokeConsentSessions() error = %v", err)
	}
	want := []recordedRequest{
		{method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/login", query: "sid=sid-1"},
		{method: http.MethodDelete, path: "/admin/oauth2/auth/sessions/consent", query: "all=true&subject=42"},
	}
	for index, request := range *requests {
		if request.method != want[index].method || request.path != want[index].path || request.query != want[index].query {
			t.Fatalf("request %d = %s %s?%s, want %s %s?%s", index, request.method, request.path, request.query, want[index].method, want[index].path, want[index].query)
		}
	}

	// A session Hydra no longer knows is already revoked.
	gone, _ := fakeHydra(t, http.StatusNotFound, "")
	if err := gone.RevokeLoginSession(context.Background(), "sid-1"); err != nil {
		t.Fatalf("RevokeLoginSession(unknown) error = %v, want nil", err)
	}
	broken, _ := fakeHydra(t, http.StatusInternalServerError, "")
	if err := broken.RevokeConsentSessions(context.Background(), "42"); !errors.Is(err, service.ErrSSOUnavailable) {
		t.Fatalf("RevokeConsentSessions(failure) error = %v, want %v", err, service.ErrSSOUnavailable)
	}
}
