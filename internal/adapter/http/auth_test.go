package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

type httpSignUpStub struct {
	result service.SignUpResult
	err    error
}

func (s *httpSignUpStub) SignUp(context.Context, service.SignUpInput) (service.SignUpResult, error) {
	return s.result, s.err
}

type httpSignInStub struct {
	result service.SignInResult
	err    error
}

func (s *httpSignInStub) SignIn(context.Context, service.SignInInput, string) (service.SignInResult, error) {
	return s.result, s.err
}

type httpUserStub struct {
	user service.User
	err  error
}

func (s httpUserStub) FindUserByID(context.Context, int64) (service.User, error) {
	return s.user, s.err
}

type httpSessionStub struct {
	session service.Session
	err     error
}

func (s httpSessionStub) Lookup(context.Context, string) (service.Session, error) {
	return s.session, s.err
}

type httpSignOutStub struct {
	called bool
	err    error
}

type httpConfirmationStub struct{ err error }

func (s httpConfirmationStub) Issue(context.Context, int64) error    { return s.err }
func (s httpConfirmationStub) Resend(context.Context, string) error  { return s.err }
func (s httpConfirmationStub) Confirm(context.Context, string) error { return s.err }

type httpResetRequestStub struct{ err error }

func (s httpResetRequestStub) Request(context.Context, string) error { return s.err }

type httpResetUseStub struct{ err error }

func (s httpResetUseStub) Redeem(context.Context, string, string) error { return s.err }

type httpOAuthStub struct {
	startURL string
	result   service.OAuthSignInResult
	err      error
}

func (s httpOAuthStub) Start(context.Context, string) (string, error) {
	return s.startURL, s.err
}

func (s httpOAuthStub) Callback(context.Context, string, string, string) (service.OAuthSignInResult, error) {
	return s.result, s.err
}

type httpOAuthProvidersStub struct{ names []string }

func (s httpOAuthProvidersStub) Names() []string { return s.names }

func (s *httpSignOutStub) SignOut(context.Context, string) error {
	s.called = true
	return s.err
}

func newHTTPTestDependencies(t *testing.T) Dependencies {
	t.Helper()
	cookie, err := middleware.NewSessionCookie(middleware.SessionCookieConfig{Lifetime: time.Hour})
	if err != nil {
		t.Fatalf("NewSessionCookie() error = %v", err)
	}
	return Dependencies{
		Users:         httpUserStub{user: service.User{ID: 42, Email: stringPointer("user@example.test"), Theme: "light"}},
		Sessions:      httpSessionStub{session: service.Session{ID: "opaque-session", UserID: 42, CreatedAt: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}},
		SessionAdmin:  &httpSignOutStub{},
		SessionCookie: cookie,
	}
}

func stringPointer(value string) *string { return &value }

func csrfRequest(t *testing.T, handler http.Handler, method, path string, values url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func csrfCookie(t *testing.T, handler http.Handler) *http.Cookie {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/en/sign-up", nil))
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == middleware.CSRFCookieName {
			return cookie
		}
	}
	t.Fatal("GET did not set CSRF cookie")
	return nil
}

func TestSignUpCreatesOpaqueSessionAndNeverRendersPassword(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.SignUp = &httpSignUpStub{result: service.SignUpResult{Session: service.Session{ID: "opaque-session"}}}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	password := "correct-horse-battery-staple"
	response := csrfRequest(t, handler, http.MethodPost, "/en/sign-up", url.Values{
		"_csrf": {csrf.Value}, "email": {"user@example.test"}, "username": {"user"}, "password": {password},
	}, csrf)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/en/home" {
		t.Errorf("location = %q, want /en/home", location)
	}
	if strings.Contains(response.Body.String(), password) {
		t.Fatal("sign-up response rendered submitted password")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == middleware.DefaultSessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || sessionCookie.Value != "opaque-session" {
		t.Fatalf("session cookie = %+v, want opaque HttpOnly credential", sessionCookie)
	}
}

func TestSignInFailureIsUniformAndPreservesOnlyIdentifier(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.SignIn = &httpSignInStub{err: service.ErrInvalidCredentials}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	password := "wrong-password"
	response := csrfRequest(t, handler, http.MethodPost, "/en/sign-in", url.Values{
		"_csrf": {csrf.Value}, "identifier": {"user@example.test"}, "password": {password},
	}, csrf)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	body := response.Body.String()
	if !strings.Contains(body, "user@example.test") {
		t.Fatal("sign-in response did not preserve identifier")
	}
	if strings.Contains(body, password) || strings.Contains(body, "password_hash") || strings.Contains(body, "session_id") {
		t.Fatal("sign-in failure response exposed sensitive data")
	}
}

func TestSignUpValidationShowsFieldErrorWithoutPasswordValue(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.SignUp = &httpSignUpStub{err: service.ErrPasswordTooShort}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	password := "short"
	response := csrfRequest(t, handler, http.MethodPost, "/en/sign-up", url.Values{
		"_csrf": {csrf.Value}, "email": {"user@example.test"}, "password": {password},
	}, csrf)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	body := response.Body.String()
	if !strings.Contains(body, `id="password-error"`) || strings.Contains(body, `value="`+password+`"`) {
		t.Fatalf("validation response did not safely render password error: %s", body)
	}
}

func TestSignOutRevokesAndClearsSession(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	signOut := dependencies.SessionAdmin.(*httpSignOutStub)
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	response := csrfRequest(t, handler, http.MethodPost, "/en/sign-out", url.Values{"_csrf": {csrf.Value}}, csrf, &http.Cookie{Name: middleware.DefaultSessionCookieName, Value: "opaque-session"})

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/sign-in" {
		t.Fatalf("sign-out response = %d %q, want redirect to sign-in", response.Code, response.Header().Get("Location"))
	}
	if !signOut.called {
		t.Fatal("sign-out did not revoke current session")
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == middleware.DefaultSessionCookieName && cookie.MaxAge >= 0 {
			t.Fatalf("session cookie was not expired: %+v", cookie)
		}
	}
}

func TestAuthenticatedHomeRedirectsAnonymousVisitor(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	handler := NewRouterWithServices(dependencies)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/en/home", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/sign-in" {
		t.Fatalf("anonymous home response = %d %q, want sign-in redirect", response.Code, response.Header().Get("Location"))
	}
}

func TestSignInServiceErrorDoesNotLeakInternalError(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.SignIn = &httpSignInStub{err: errors.New("database password secret")}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	response := csrfRequest(t, handler, http.MethodPost, "/en/sign-in", url.Values{
		"_csrf": {csrf.Value}, "identifier": {"user@example.test"}, "password": {"correct-horse"},
	}, csrf)

	if strings.Contains(response.Body.String(), "database password secret") {
		t.Fatal("sign-in response exposed internal error")
	}
}

func TestPasswordRecoveryRequestIsUniformAndCSRFProtected(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.PasswordResetter = httpResetRequestStub{}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	response := csrfRequest(t, handler, http.MethodPost, "/en/forgot-password", url.Values{
		"_csrf": {csrf.Value}, "email": {"unknown@example.test"},
	}, csrf)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "If the address is eligible") {
		t.Fatalf("recovery response = %d %q, want uniform accepted guidance", response.Code, response.Body.String())
	}
	withoutCSRF := httptest.NewRecorder()
	handler.ServeHTTP(withoutCSRF, httptest.NewRequest(http.MethodPost, "/en/forgot-password", strings.NewReader("email=unknown%40example.test")))
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing csrf status = %d, want %d", withoutCSRF.Code, http.StatusForbidden)
	}
}

func TestResetPasswordFailureDoesNotRenderTokenOrPassword(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.PasswordResetterUse = httpResetUseStub{err: service.ErrPasswordTooShort}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	password := "short-password-value"
	response := csrfRequest(t, handler, http.MethodPost, "/en/reset-password?token=secret-reset-token", url.Values{
		"_csrf": {csrf.Value}, "password": {password},
	}, csrf)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	body := response.Body.String()
	if strings.Contains(body, "secret-reset-token") || strings.Contains(body, password) || !strings.Contains(body, "password-error") {
		t.Fatal("reset response exposed token/password or omitted field error")
	}
}

func TestResetPasswordSuccessClearsBrowserSession(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.PasswordResetterUse = httpResetUseStub{}
	handler := NewRouterWithServices(dependencies)
	csrf := csrfCookie(t, handler)
	response := csrfRequest(t, handler, http.MethodPost, "/en/reset-password?token=secret-reset-token", url.Values{
		"_csrf": {csrf.Value}, "password": {"correct-horse-battery-staple"},
	}, csrf, &http.Cookie{Name: middleware.DefaultSessionCookieName, Value: "opaque-session"})

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Password changed") {
		t.Fatalf("success response = %d %q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-reset-token") {
		t.Fatal("reset success response exposed bearer token")
	}
	cleared := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == middleware.DefaultSessionCookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("successful reset did not clear browser session cookie")
	}
}

func TestConfirmationFailuresAreUniform(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.ConfirmationConsumer = httpConfirmationStub{err: service.ErrInvalidConfirmationToken}
	handler := NewRouterWithServices(dependencies)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/en/confirm-email?token=secret-confirmation-token", nil))

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "invalid or no longer available") {
		t.Fatalf("confirmation response = %d %q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-confirmation-token") {
		t.Fatal("confirmation response exposed bearer token")
	}
}

func TestOAuthControlsOnlyRenderConfiguredProviders(t *testing.T) {
	configured := newHTTPTestDependencies(t)
	configured.OAuthProviders = httpOAuthProvidersStub{names: []string{"github"}}
	configured.OAuth = httpOAuthStub{}
	handler := NewRouterWithServices(configured)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/en/sign-in", nil))

	body := response.Body.String()
	if !strings.Contains(body, `data-oauth-provider="github"`) || !strings.Contains(body, "/en/oauth/github") {
		t.Fatal("configured OAuth provider control missing")
	}
	if strings.Contains(body, "client_secret") || strings.Contains(body, "provider_subject") {
		t.Fatal("OAuth diagnostics leaked into sign-in page")
	}

	unconfigured := httptest.NewRecorder()
	handler.ServeHTTP(unconfigured, httptest.NewRequest(http.MethodGet, "/en/oauth/google", nil))
	if unconfigured.Code != http.StatusOK || !strings.Contains(unconfigured.Body.String(), "Page not found") {
		t.Fatalf("unconfigured OAuth route = %d %q", unconfigured.Code, unconfigured.Body.String())
	}
}

func TestOAuthCallbackFailureRedirectsWithoutProviderSecrets(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.OAuthProviders = httpOAuthProvidersStub{names: []string{"github"}}
	dependencies.OAuth = httpOAuthStub{err: service.ErrOAuthAuthenticationFailed}
	handler := NewRouterWithServices(dependencies)
	request := httptest.NewRequest(http.MethodGet, "/en/oauth/github/callback?code=provider-code&state=opaque-state", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/sign-in?oauth=error" {
		t.Fatalf("OAuth failure response = %d %q", response.Code, response.Header().Get("Location"))
	}
	if strings.Contains(response.Header().Get("Location"), "provider-code") || strings.Contains(response.Header().Get("Location"), "opaque-state") {
		t.Fatal("OAuth failure redirect leaked callback credentials")
	}
}

func TestOAuthCallbackSuccessCreatesSessionCookie(t *testing.T) {
	dependencies := newHTTPTestDependencies(t)
	dependencies.OAuthProviders = httpOAuthProvidersStub{names: []string{"github"}}
	dependencies.OAuth = httpOAuthStub{result: service.OAuthSignInResult{Session: service.Session{ID: "oauth-session"}}}
	handler := NewRouterWithServices(dependencies)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/en/oauth/github/callback?code=provider-code&state=opaque-state", nil))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/en/home" {
		t.Fatalf("OAuth success response = %d %q", response.Code, response.Header().Get("Location"))
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == middleware.DefaultSessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || sessionCookie.Value != "oauth-session" {
		t.Fatalf("OAuth success session cookie = %+v", sessionCookie)
	}
}
