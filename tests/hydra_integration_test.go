//go:build integration

package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/adapter/hydra"
	"github.com/tewecske/goweb/internal/adapter/oidc"
	"github.com/tewecske/goweb/internal/service"
)

// TestHydraProviderAndRelyingPartyContract drives the provider's Hydra admin
// client and the client app's OpenID Connect relying party against a real
// Hydra, without a browser: authorization, login, consent, token redemption,
// ID token verification, the silent second sign-in, and a real back-channel
// logout.
//
// It runs only when both variables are set:
//
//	GOWEB_HYDRA_TEST_ADMIN_URL   the Hydra admin API, e.g. http://127.0.0.1:4445
//	GOWEB_HYDRA_TEST_ISSUER_URL  Hydra's issuer exactly as configured, e.g. http://127.0.0.1:4444
//
// Hydra must be able to call 127.0.0.1 (compose uses host networking), because
// the test receives the back-channel logout on a loopback listener. The test
// registers and removes its own client; it never touches other clients.
func TestHydraProviderAndRelyingPartyContract(t *testing.T) {
	adminURL := strings.TrimRight(os.Getenv("GOWEB_HYDRA_TEST_ADMIN_URL"), "/")
	issuer := strings.TrimRight(os.Getenv("GOWEB_HYDRA_TEST_ISSUER_URL"), "/")
	if adminURL == "" || issuer == "" {
		t.Skip("set GOWEB_HYDRA_TEST_ADMIN_URL and GOWEB_HYDRA_TEST_ISSUER_URL to run against a real Hydra")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A loopback listener plays the client app's back-channel logout endpoint.
	logoutTokens := make(chan string, 4)
	callback := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		logoutTokens <- request.PostForm.Get("logout_token")
		writer.WriteHeader(http.StatusOK)
	}))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	callback.Listener = listener
	callback.Start()
	defer callback.Close()

	clientID := "contract-" + randomToken(t, 6)
	clientSecret := randomToken(t, 24)
	redirectURL := "http://127.0.0.1:1/en/oauth/sso/callback" // never visited
	registerClient(t, ctx, adminURL, map[string]any{
		"client_id":                           clientID,
		"client_secret":                       clientSecret,
		"grant_types":                         []string{"authorization_code"},
		"response_types":                      []string{"code"},
		"scope":                               "openid email profile",
		"redirect_uris":                       []string{redirectURL},
		"token_endpoint_auth_method":          "client_secret_basic",
		"skip_consent":                        true,
		"backchannel_logout_uri":              callback.URL + "/oauth/sso/backchannel-logout",
		"backchannel_logout_session_required": true,
	})
	defer deleteClient(adminURL, clientID)

	admin, err := hydra.NewAdminClient(adminURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	relyingParty, err := oidc.New(oidc.Config{Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL})
	if err != nil {
		t.Fatal(err)
	}
	// One browser: its cookie jar is Hydra's remembered single sign-on session.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	subject := fmt.Sprintf("%d", 700000+time.Now().UnixNano()%100000)

	// First sign-in: Hydra asks the provider to log in, then to grant consent.
	verifier := randomToken(t, 32)
	state := randomHex(t, 32)
	location := authorize(t, ctx, browser, relyingParty, state, verifier)
	loginChallenge := queryParam(t, location, "login_challenge")
	login, err := admin.LoginRequest(ctx, loginChallenge)
	if err != nil || login.Skip || login.Subject != "" {
		t.Fatalf("first LoginRequest() = %+v, %v; want a fresh login", login, err)
	}
	next, err := admin.AcceptLogin(ctx, loginChallenge, subject, time.Hour)
	if err != nil {
		t.Fatalf("AcceptLogin() error = %v", err)
	}
	location = follow(t, ctx, browser, next)
	consentChallenge := queryParam(t, location, "consent_challenge")
	consent, err := admin.ConsentRequest(ctx, consentChallenge)
	if err != nil {
		t.Fatalf("ConsentRequest() error = %v", err)
	}
	if consent.Subject != subject || consent.LoginSessionID == "" || !contains(consent.RequestedScope, "openid") {
		t.Fatalf("ConsentRequest() = %+v, want subject %s, a login session ID, and the openid scope", consent, subject)
	}
	next, err = admin.AcceptConsent(ctx, consentChallenge, service.SSOConsentGrant{
		Scope:         consent.RequestedScope,
		Audience:      consent.RequestedAudience,
		IDTokenClaims: map[string]any{"email": "contract@example.test", "email_verified": true, "name": "Contract Test", "locale": "hu"},
		RememberFor:   time.Hour,
	})
	if err != nil {
		t.Fatalf("AcceptConsent() error = %v", err)
	}
	location = follow(t, ctx, browser, next)
	if !strings.HasPrefix(location, redirectURL+"?") || queryParam(t, location, "state") != state {
		t.Fatalf("authorization ended at %q, want the client callback with the original state", location)
	}

	// The relying party verifies the ID token Hydra signed.
	identity, err := relyingParty.Exchange(ctx, queryParam(t, location, "code"), verifier)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if identity.Subject != subject || identity.Email != "contract@example.test" || !identity.EmailVerified || identity.Name != "Contract Test" || identity.Locale != "hu" {
		t.Fatalf("identity = %+v", identity)
	}
	if identity.SessionID != consent.LoginSessionID {
		t.Fatalf("ID token sid = %q, consent login session = %q; the provider records the latter for revocation", identity.SessionID, consent.LoginSessionID)
	}

	// Second sign-in in the same browser is silent: Hydra remembers the subject.
	location = authorize(t, ctx, browser, relyingParty, randomHex(t, 32), randomToken(t, 32))
	repeat, err := admin.LoginRequest(ctx, queryParam(t, location, "login_challenge"))
	if err != nil || !repeat.Skip || repeat.Subject != subject || repeat.SessionID != identity.SessionID {
		t.Fatalf("second LoginRequest() = %+v, %v; want skip for subject %s in session %s", repeat, err, subject, identity.SessionID)
	}

	// Revoking the recorded session ID makes Hydra send a real back-channel
	// logout, which the relying party verifies against Hydra's key set.
	if err := admin.RevokeLoginSession(ctx, consent.LoginSessionID); err != nil {
		t.Fatalf("RevokeLoginSession() error = %v", err)
	}
	select {
	case token := <-logoutTokens:
		sid, err := relyingParty.VerifyLogoutToken(ctx, token)
		if err != nil || sid != identity.SessionID {
			t.Fatalf("VerifyLogoutToken() = %q, %v; want sid %q", sid, err, identity.SessionID)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Hydra did not deliver a back-channel logout to the loopback listener (can Hydra reach 127.0.0.1?)")
	}
	// The session is gone, so the next sign-in asks for credentials again.
	location = authorize(t, ctx, browser, relyingParty, randomHex(t, 32), randomToken(t, 32))
	after, err := admin.LoginRequest(ctx, queryParam(t, location, "login_challenge"))
	if err != nil || after.Skip {
		t.Fatalf("LoginRequest() after revocation = %+v, %v; want a fresh login", after, err)
	}
	if err := admin.RevokeConsentSessions(ctx, subject); err != nil {
		t.Fatalf("RevokeConsentSessions() error = %v", err)
	}

	// A challenge Hydra no longer knows maps to the expired error.
	if _, err := admin.LoginRequest(ctx, "not-a-real-challenge"); err == nil {
		t.Fatal("LoginRequest(unknown) succeeded")
	}
}

// authorize starts an authorization request with the relying party's own URL
// and returns where Hydra sends the browser (the provider's login URL).
func authorize(t *testing.T, ctx context.Context, browser *http.Client, relyingParty *oidc.Client, state, verifier string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(verifier))
	target, err := relyingParty.AuthorizationURL(ctx, state, base64.RawURLEncoding.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("AuthorizationURL() error = %v", err)
	}
	return follow(t, ctx, browser, target)
}

// follow fetches one URL without following redirects and returns the Location.
func follow(t *testing.T, ctx context.Context, browser *http.Client, target string) string {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := browser.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", redact(target), err)
	}
	defer func() { _ = response.Body.Close() }()
	location := response.Header.Get("Location")
	if response.StatusCode < 300 || response.StatusCode > 399 || location == "" {
		t.Fatalf("GET %s = %d without a redirect", redact(target), response.StatusCode)
	}
	return location
}

func registerClient(t *testing.T, ctx context.Context, adminURL string, client map[string]any) {
	t.Helper()
	body, _ := json.Marshal(client)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, adminURL+"/admin/clients", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("register client = %d", response.StatusCode)
	}
}

func deleteClient(adminURL, clientID string) {
	request, _ := http.NewRequest(http.MethodDelete, adminURL+"/admin/clients/"+url.PathEscape(clientID), nil)
	if response, err := http.DefaultClient.Do(request); err == nil {
		_ = response.Body.Close()
	}
}

func queryParam(t *testing.T, location, name string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil || parsed.Query().Get(name) == "" {
		t.Fatalf("redirect %q has no %s parameter", redact(location), name)
	}
	return parsed.Query().Get(name)
}

// redact keeps challenges, codes, and verifiers out of failure output.
func redact(raw string) string {
	if before, _, found := strings.Cut(raw, "?"); found {
		return before + "?…"
	}
	return raw
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func randomToken(t *testing.T, bytesCount int) string {
	t.Helper()
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func randomHex(t *testing.T, bytesCount int) string {
	t.Helper()
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", value)
}
