package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewGoogleClientRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config GoogleConfig
	}{
		{name: "missing client id", config: GoogleConfig{ClientSecret: "secret", RedirectURL: "https://app.example.test/callback"}},
		{name: "missing client secret", config: GoogleConfig{ClientID: "client", RedirectURL: "https://app.example.test/callback"}},
		{name: "missing redirect", config: GoogleConfig{ClientID: "client", ClientSecret: "secret"}},
		{name: "relative redirect", config: GoogleConfig{ClientID: "client", ClientSecret: "secret", RedirectURL: "/callback"}},
		{name: "credential-bearing redirect", config: GoogleConfig{ClientID: "client", ClientSecret: "secret", RedirectURL: "https://user:pass@app.example.test/callback"}},
		{name: "unsupported scheme", config: GoogleConfig{ClientID: "client", ClientSecret: "secret", RedirectURL: "ftp://app.example.test/callback"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewGoogleClient(test.config); !errors.Is(err, ErrInvalidGoogleConfig) {
				t.Fatalf("NewGoogleClient() error = %v, want ErrInvalidGoogleConfig", err)
			}
		})
	}
}

func TestGoogleClientAuthorizationURLContainsRequiredParameters(t *testing.T) {
	client := mustGoogleClient(t)
	const state = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	raw, err := client.AuthorizationURL(context.Background(), state)
	if err != nil {
		t.Fatalf("AuthorizationURL() error = %v", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("authorization URL is not a URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "accounts.google.com" {
		t.Fatalf("authorization URL host = %s, want accounts.google.com", parsed.Host)
	}
	query := parsed.Query()
	if query.Get("client_id") != "client-id" {
		t.Errorf("client_id = %q, want client-id", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://app.example.test/en/oauth/google/callback" {
		t.Errorf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	if query.Get("response_type") != "code" || query.Get("state") != state {
		t.Errorf("response_type/state = %q/%q", query.Get("response_type"), query.Get("state"))
	}
	if query.Get("scope") != "openid email profile" {
		t.Errorf("scope = %q, want openid email profile", query.Get("scope"))
	}
	if query.Get("prompt") != "select_account" {
		t.Errorf("prompt = %q, want select_account", query.Get("prompt"))
	}
}

func TestGoogleClientExchangeReturnsProfile(t *testing.T) {
	var tokenRequest string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/token":
			body, _ := io.ReadAll(request.Body)
			tokenRequest = string(body)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
		case "/userinfo":
			if request.Header.Get("Authorization") != "Bearer access-token" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"sub":"google-subject","email":"Person@Example.COM","email_verified":true,"name":"Person Name"}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := mustGoogleClient(t)
	client.tokenEndpoint = server.URL + "/token"
	client.userInfoEndpoint = server.URL + "/userinfo"
	client.httpClient = server.Client()

	profile, err := client.Exchange(context.Background(), "authorization-code")
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if profile.Subject != "google-subject" || profile.Email != "Person@Example.COM" || !profile.EmailVerified || profile.DisplayName != "Person Name" {
		t.Fatalf("profile = %+v, want provider-asserted fields", profile)
	}
	values, err := url.ParseQuery(tokenRequest)
	if err != nil {
		t.Fatalf("token request is not form encoded: %v", err)
	}
	if values.Get("code") != "authorization-code" || values.Get("grant_type") != "authorization_code" {
		t.Errorf("token request code/grant = %q/%q", values.Get("code"), values.Get("grant_type"))
	}
	if values.Get("client_secret") != "client-secret" || values.Get("redirect_uri") != "https://app.example.test/en/oauth/google/callback" {
		t.Errorf("token request omitted client secret or redirect")
	}
}

func TestGoogleClientExchangeRejectsProviderFailures(t *testing.T) {
	tests := []struct {
		name      string
		tokenCode int
		tokenBody string
		userCode  int
		userBody  string
	}{
		{name: "token status", tokenCode: http.StatusBadRequest, tokenBody: `{}`},
		{name: "token malformed", tokenCode: http.StatusOK, tokenBody: `not-json`},
		{name: "token missing access token", tokenCode: http.StatusOK, tokenBody: `{}`},
		{name: "userinfo status", tokenCode: http.StatusOK, tokenBody: `{"access_token":"token"}`, userCode: http.StatusForbidden, userBody: `{}`},
		{name: "userinfo missing subject", tokenCode: http.StatusOK, tokenBody: `{"access_token":"token"}`, userCode: http.StatusOK, userBody: `{"email":"person@example.test"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if request.URL.Path == "/token" {
					writer.WriteHeader(test.tokenCode)
					_, _ = writer.Write([]byte(test.tokenBody))
					return
				}
				writer.WriteHeader(test.userCode)
				_, _ = writer.Write([]byte(test.userBody))
			}))
			defer server.Close()

			client := mustGoogleClient(t)
			client.tokenEndpoint = server.URL + "/token"
			client.userInfoEndpoint = server.URL + "/userinfo"
			client.httpClient = server.Client()

			profile, err := client.Exchange(context.Background(), "authorization-code")
			if !errors.Is(err, errTokenExchange) && !errors.Is(err, errUserInfo) {
				t.Fatalf("Exchange() error = %v, want provider failure", err)
			}
			if profile.Subject != "" {
				t.Fatalf("Exchange() returned profile %+v on failure", profile)
			}
		})
	}
}

func TestGoogleClientAuthorizationURLRejectsEmptyState(t *testing.T) {
	client := mustGoogleClient(t)
	if _, err := client.AuthorizationURL(context.Background(), " "); !errors.Is(err, ErrInvalidGoogleConfig) {
		t.Fatalf("AuthorizationURL(empty state) error = %v, want ErrInvalidGoogleConfig", err)
	}
}

func TestGoogleClientStringRedactsSecret(t *testing.T) {
	client := mustGoogleClient(t)
	for _, diagnostic := range []string{client.String(), client.GoString()} {
		if strings.Contains(diagnostic, "client-secret") {
			t.Fatalf("diagnostic leaked client secret: %q", diagnostic)
		}
	}
}

func mustGoogleClient(t *testing.T) *GoogleClient {
	t.Helper()
	client, err := NewGoogleClient(GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://app.example.test/en/oauth/google/callback",
	})
	if err != nil {
		t.Fatalf("NewGoogleClient() error = %v", err)
	}
	return client
}
