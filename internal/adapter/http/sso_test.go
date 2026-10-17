package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

// A padded base64url value like the challenges Hydra issues.
const testLoginChallenge = "eyJmbG93IjoiYWJjIn0_-xyz=="

type httpSSOProviderStub struct {
	clientName        string
	beginTarget       string
	beginErr          error
	beginCurrentUser  int64
	beginCalls        int
	completeTarget    string
	completeErr       error
	completeChallenge string
	completeUserID    int64
	completeCalls     int
	consentTarget     string
	consentErr        error
	logoutTarget      string
	logoutErr         error
}

func (s *httpSSOProviderStub) BeginLogin(_ context.Context, _ string, currentUserID int64) (string, error) {
	s.beginCalls++
	s.beginCurrentUser = currentUserID
	return s.beginTarget, s.beginErr
}

func (s *httpSSOProviderStub) LoginClientName(_ context.Context, _ string) string {
	return s.clientName
}

func (s *httpSSOProviderStub) CompleteLogin(_ context.Context, challenge string, userID int64) (string, error) {
	s.completeCalls++
	s.completeChallenge = challenge
	s.completeUserID = userID
	return s.completeTarget, s.completeErr
}

func (s *httpSSOProviderStub) Consent(context.Context, string) (string, error) {
	return s.consentTarget, s.consentErr
}

func (s *httpSSOProviderStub) Logout(context.Context, string) (string, error) {
	return s.logoutTarget, s.logoutErr
}

func ssoTestDependencies(t *testing.T, provider *httpSSOProviderStub) Dependencies {
	t.Helper()
	dependencies := newHTTPTestDependencies(t)
	// Account 7, not the default test account 42, so a handler that takes the
	// user from anywhere but the session is caught.
	dependencies.Sessions = httpSessionStub{session: service.Session{ID: "opaque-session", UserID: 7, CreatedAt: 1, ExpiresAt: 1 << 40}}
	dependencies.Users = httpUserStub{user: service.User{ID: 7, Email: stringPointer("user@example.test"), Theme: "light"}}
	dependencies.SSOProvider = provider
	return dependencies
}

func responseCookie(response *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestSSORoutesAreAbsentOutsideProviderMode(t *testing.T) {
	handler := NewRouterWithServices(newHTTPTestDependencies(t))
	for _, path := range []string{"/sso/login?login_challenge=abc", "/sso/consent?consent_challenge=abc", "/sso/logout?logout_challenge=abc"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want %d without provider mode", path, response.Code, http.StatusNotFound)
		}
	}
}

func TestSSOLoginCompletesImmediatelyForSignedInBrowser(t *testing.T) {
	provider := &httpSSOProviderStub{beginTarget: "http://127.0.0.1:4444/oauth2/auth?login_verifier=v"}
	handler := NewRouterWithServices(ssoTestDependencies(t, provider))
	request := httptest.NewRequest(http.MethodGet, "/sso/login?login_challenge="+url.QueryEscape(testLoginChallenge), nil)
	request.AddCookie(&http.Cookie{Name: middleware.DefaultSessionCookieName, Value: "opaque-session"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusFound || response.Header().Get("Location") != provider.beginTarget {
		t.Fatalf("response = %d %q, want redirect to Hydra", response.Code, response.Header().Get("Location"))
	}
	if provider.beginCurrentUser != 7 {
		t.Fatalf("BeginLogin current user = %d, want the signed-in account 7", provider.beginCurrentUser)
	}
	if responseCookie(response, loginChallengeCookieName) != nil {
		t.Fatal("a completed login must not leave a pending challenge cookie")
	}
}

func TestSSOLoginRemembersChallengeAndShowsSignIn(t *testing.T) {
	provider := &httpSSOProviderStub{}
	handler := NewRouterWithServices(ssoTestDependencies(t, provider))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sso/login?login_challenge="+url.QueryEscape(testLoginChallenge), nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/sign-in" {
		t.Fatalf("response = %d %q, want redirect to sign-in", response.Code, response.Header().Get("Location"))
	}
	if provider.beginCurrentUser != 0 {
		t.Fatalf("BeginLogin current user = %d, want 0 for an anonymous visitor", provider.beginCurrentUser)
	}
	cookie := responseCookie(response, loginChallengeCookieName)
	if cookie == nil || cookie.Value != testLoginChallenge || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != 1800 {
		t.Fatalf("challenge cookie = %+v, want HttpOnly Lax cookie on / for 30 minutes", cookie)
	}
}

func TestSSOChallengeEndpointsRejectMalformedChallenges(t *testing.T) {
	provider := &httpSSOProviderStub{beginTarget: "http://127.0.0.1:4444/x", consentTarget: "http://127.0.0.1:4444/x", logoutTarget: "http://127.0.0.1:4444/x"}
	handler := NewRouterWithServices(ssoTestDependencies(t, provider))
	for _, path := range []string{
		"/sso/login",
		"/sso/login?login_challenge=" + url.QueryEscape("abc;def"),
		"/sso/login?login_challenge=" + strings.Repeat("a", maxLoginChallengeBytes+1),
		"/sso/consent?consent_challenge=" + url.QueryEscape("a b"),
		"/sso/logout",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want %d", path, response.Code, http.StatusBadRequest)
		}
	}
	if provider.beginCalls != 0 {
		t.Fatal("a malformed challenge reached the provider service")
	}
}

func TestSignInAndSignUpNameTheAppDuringAnSSOFlow(t *testing.T) {
	get := func(path string, withChallenge bool, clientName string) string {
		t.Helper()
		handler := NewRouterWithServices(ssoTestDependencies(t, &httpSSOProviderStub{clientName: clientName}))
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if withChallenge {
			request.AddCookie(&http.Cookie{Name: loginChallengeCookieName, Value: testLoginChallenge})
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, response.Code)
		}
		return response.Body.String()
	}
	for _, path := range []string{"/en/sign-in", "/en/sign-up"} {
		body := get(path, true, "Notes app")
		if !strings.Contains(body, `data-testid="sso-client-name"`) || !strings.Contains(body, "Signing in to <strong>Notes app</strong>") {
			t.Fatalf("GET %s with a pending challenge does not name the app", path)
		}
		// The name is registered data, but it is still escaped.
		if body := get(path, true, `<img src=x onerror=alert(1)>`); strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;img src=x") {
			t.Fatalf("GET %s rendered the app name unescaped", path)
		}
		// No pending challenge, or an app Hydra cannot name: no banner.
		if body := get(path, false, "Notes app"); strings.Contains(body, "sso-client-name") {
			t.Fatalf("GET %s without a pending challenge named an app", path)
		}
		if body := get(path, true, ""); strings.Contains(body, "sso-client-name") {
			t.Fatalf("GET %s named an app Hydra could not name", path)
		}
	}
	if body := get("/hu/sign-in", true, "Notes app"); !strings.Contains(body, "Bejelentkezés ide: <strong>Notes app</strong>") {
		t.Fatal("the Hungarian sign-in page does not name the app in Hungarian")
	}
}

func TestSSOExpiredChallengeShowsSignInAlert(t *testing.T) {
	provider := &httpSSOProviderStub{beginErr: service.ErrSSOChallengeExpired, consentErr: service.ErrSSOChallengeExpired}
	handler := NewRouterWithServices(ssoTestDependencies(t, provider))
	for _, path := range []string{"/sso/login?login_challenge=abc", "/sso/consent?consent_challenge=abc"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/sign-in?sso=expired" {
			t.Fatalf("GET %s = %d %q, want sign-in with the expired alert", path, response.Code, response.Header().Get("Location"))
		}
	}
	page := serveContract(t, handler, newContractRequest(http.MethodGet, "/en/sign-in?sso=expired"))
	page.assertStatus(t, http.StatusOK).assertCatalogMessage(t, "en", "sso.error.expired")
}

func TestSignInCompletesPendingSSOLogin(t *testing.T) {
	for _, htmx := range []bool{false, true} {
		provider := &httpSSOProviderStub{completeTarget: "http://127.0.0.1:4444/oauth2/auth?login_verifier=v"}
		dependencies := ssoTestDependencies(t, provider)
		dependencies.SignIn = &httpSignInStub{result: service.SignInResult{Session: service.Session{ID: "opaque-session"}}}
		handler := NewRouterWithServices(dependencies)
		csrf := csrfCookie(t, handler)
		request := httptest.NewRequest(http.MethodPost, "/en/sign-in", strings.NewReader(url.Values{"_csrf": {csrf.Value}, "identifier": {"user@example.test"}, "password": {"pw"}}.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(csrf)
		request.AddCookie(&http.Cookie{Name: loginChallengeCookieName, Value: testLoginChallenge})
		if htmx {
			request.Header.Set("HX-Request", "true")
			request.Header.Set("X-CSRF-Token", csrf.Value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if htmx {
			if got := response.Header().Get("HX-Redirect"); got != provider.completeTarget {
				t.Fatalf("HTMX HX-Redirect = %q, want Hydra target", got)
			}
		} else if response.Code != http.StatusSeeOther || response.Header().Get("Location") != provider.completeTarget {
			t.Fatalf("response = %d %q, want redirect back to Hydra", response.Code, response.Header().Get("Location"))
		}
		if provider.completeChallenge != testLoginChallenge || provider.completeUserID != 7 {
			t.Fatalf("CompleteLogin(%q, %d), want the cookie challenge for the session's account 7", provider.completeChallenge, provider.completeUserID)
		}
		if cookie := responseCookie(response, loginChallengeCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatalf("challenge cookie = %+v, want it cleared", cookie)
		}
		if cookie := responseCookie(response, middleware.DefaultSessionCookieName); cookie == nil || cookie.Value != "opaque-session" {
			t.Fatalf("session cookie = %+v, want the new provider session set", cookie)
		}
	}
}

func TestSignInWithoutUsablePendingSSOLoginGoesHome(t *testing.T) {
	tests := []struct {
		name     string
		cookie   *http.Cookie
		provider *httpSSOProviderStub
		calls    int
	}{
		{name: "no pending challenge", provider: &httpSSOProviderStub{completeTarget: "http://127.0.0.1:4444/x"}},
		{name: "expired challenge", cookie: &http.Cookie{Name: loginChallengeCookieName, Value: testLoginChallenge}, provider: &httpSSOProviderStub{completeErr: service.ErrSSOChallengeExpired}, calls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := ssoTestDependencies(t, test.provider)
			dependencies.SignIn = &httpSignInStub{result: service.SignInResult{Session: service.Session{ID: "opaque-session"}}}
			handler := NewRouterWithServices(dependencies)
			csrf := csrfCookie(t, handler)
			cookies := []*http.Cookie{csrf}
			if test.cookie != nil {
				cookies = append(cookies, test.cookie)
			}
			response := csrfRequest(t, handler, http.MethodPost, "/en/sign-in", url.Values{"_csrf": {csrf.Value}, "identifier": {"user@example.test"}, "password": {"pw"}}, cookies...)
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/home" {
				t.Fatalf("response = %d %q, want the normal home redirect", response.Code, response.Header().Get("Location"))
			}
			if test.provider.completeCalls != test.calls {
				t.Fatalf("CompleteLogin calls = %d, want %d", test.provider.completeCalls, test.calls)
			}
		})
	}
}

func TestSSOConsentRedirectsToHydra(t *testing.T) {
	provider := &httpSSOProviderStub{consentTarget: "http://127.0.0.1:4444/oauth2/auth?consent_verifier=v"}
	handler := NewRouterWithServices(ssoTestDependencies(t, provider))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sso/consent?consent_challenge="+url.QueryEscape(testLoginChallenge), nil))
	if response.Code != http.StatusFound || response.Header().Get("Location") != provider.consentTarget {
		t.Fatalf("response = %d %q, want redirect to Hydra", response.Code, response.Header().Get("Location"))
	}
}

func TestSSOLogoutEndsProviderSession(t *testing.T) {
	for _, logoutErr := range []error{nil, service.ErrSSOChallengeExpired} {
		provider := &httpSSOProviderStub{logoutTarget: "http://localhost:8080/en/sign-in", logoutErr: logoutErr}
		dependencies := ssoTestDependencies(t, provider)
		signOut := dependencies.SessionAdmin.(*httpSignOutStub)
		handler := NewRouterWithServices(dependencies)
		request := httptest.NewRequest(http.MethodGet, "/sso/logout?logout_challenge="+url.QueryEscape(testLoginChallenge), nil)
		request.AddCookie(&http.Cookie{Name: middleware.DefaultSessionCookieName, Value: "opaque-session"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if !signOut.called || signOut.sessionID != "opaque-session" {
			t.Fatalf("logout (err %v) did not revoke the provider session", logoutErr)
		}
		if cookie := responseCookie(response, middleware.DefaultSessionCookieName); cookie == nil || cookie.MaxAge >= 0 {
			t.Fatalf("logout (err %v) session cookie = %+v, want cleared", logoutErr, cookie)
		}
		wantStatus, wantLocation := http.StatusFound, provider.logoutTarget
		if errors.Is(logoutErr, service.ErrSSOChallengeExpired) {
			wantStatus, wantLocation = http.StatusSeeOther, "/en/sign-in"
		}
		if response.Code != wantStatus || response.Header().Get("Location") != wantLocation {
			t.Fatalf("logout (err %v) = %d %q, want %d %q", logoutErr, response.Code, response.Header().Get("Location"), wantStatus, wantLocation)
		}
	}
}

func TestProviderSignOutAlsoEndsSSOSession(t *testing.T) {
	dependencies := ssoTestDependencies(t, &httpSSOProviderStub{})
	dependencies.SSOLogoutURL = "http://127.0.0.1:4444/oauth2/sessions/logout"
	signOut := dependencies.SessionAdmin.(*httpSignOutStub)
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	response := csrfRequest(t, handler, http.MethodPost, "/en/sign-out", url.Values{"_csrf": {csrf.Value}}, csrf, &http.Cookie{Name: middleware.DefaultSessionCookieName, Value: "opaque-session"})

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != dependencies.SSOLogoutURL {
		t.Fatalf("sign-out = %d %q, want redirect to Hydra logout", response.Code, response.Header().Get("Location"))
	}
	if !signOut.called {
		t.Fatal("provider sign-out did not revoke the local session first")
	}
}

func TestSSOErrorPageExplainsWithoutEchoingHydraText(t *testing.T) {
	handler := NewRouterWithServices(ssoTestDependencies(t, &httpSSOProviderStub{}))
	tests := map[string]string{
		"invalid_client":     "sso.error_page.invalid_client",
		"invalid_request":    "sso.error_page.invalid_request",
		"access_denied":      "sso.error_page.access_denied",
		"something_else":     "sso.error_page.generic",
		"<script>x</script>": "sso.error_page.generic",
	}
	for code, messageID := range tests {
		query := url.Values{"error": {code}, "error_description": {"injected-description"}, "error_hint": {"injected-hint"}, "error_debug": {"injected-debug"}}
		response := serveContract(t, handler, newContractRequest(http.MethodGet, "/sso/error?"+query.Encode()))
		response.assertStatus(t, http.StatusBadRequest).
			assertCatalogMessage(t, "en", messageID).
			assertBodyContains(t, `href="/en/sign-in"`).
			assertBodyAbsent(t, "injected-").
			assertBodyAbsent(t, "<script>x</script>")
	}
}
