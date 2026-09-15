package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

func TestSettingsPageRequiresAuthentication(t *testing.T) {
	handler, _ := newSettingsTestHandler(t, settingsStubDependencies(t))

	request := httptest.NewRequest(http.MethodGet, "/en/account/settings", nil)
	response := httptest.NewRecorder()
	handler.page(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/en/sign-in" {
		t.Fatalf("redirect = %q, want /en/sign-in", location)
	}
}

func TestSettingsPageRendersAccountData(t *testing.T) {
	dependencies := settingsStubDependencies(t)
	dependencies.Users = testUserFinder{user: service.User{ID: 7, Username: strPtr("alice"), DisplayName: strPtr("Alice"), Locale: "en", Theme: "dark", Version: 1}}
	dependencies.IdentityLister = settingsIdentityLister{identities: []service.OAuthIdentity{{ID: 3, UserID: 7, Provider: "example", Email: "alice@example.test"}}}
	handler, _ := newSettingsTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodGet, "/en/account/settings", 7, "")
	response := httptest.NewRecorder()
	handler.page(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"alice", "Alice", "alice@example.test", `action="/en/account/settings/profile"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
	if strings.Contains(body, "password_hash") {
		t.Errorf("settings page exposes credential fields")
	}
}

func TestSettingsProfileUpdate(t *testing.T) {
	tests := []struct {
		name           string
		updater        ProfileSettingsUpdater
		body           string
		expectedStatus int
		wantContains   string
	}{
		{name: "success", updater: settingsProfileUpdater{}, body: "username=bob&display_name=Bob", expectedStatus: http.StatusOK, wantContains: "Profile updated."},
		{name: "duplicate username", updater: settingsProfileUpdater{err: service.ErrUsernameUnavailable}, body: "username=taken", expectedStatus: http.StatusUnprocessableEntity, wantContains: "already in use"},
		{name: "invalid username", updater: settingsProfileUpdater{err: service.ErrInvalidUsername}, body: "username=bad user", expectedStatus: http.StatusUnprocessableEntity, wantContains: "cannot be used"},
		{name: "conflict", updater: settingsProfileUpdater{err: service.ErrOptimisticLockConflict}, body: "username=bob", expectedStatus: http.StatusUnprocessableEntity, wantContains: "changed elsewhere"},
		{name: "missing dependency", updater: nil, body: "username=bob", expectedStatus: http.StatusInternalServerError, wantContains: "could not be saved"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := settingsStubDependencies(t)
			dependencies.Users = testUserFinder{user: service.User{ID: 7, Version: 1}}
			if test.updater != nil {
				dependencies.ProfileSettings = test.updater
			}
			handler, _ := newSettingsTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/account/settings/profile", 7, test.body)
			response := httptest.NewRecorder()
			handler.updateProfile(response, request)
			if response.Code != test.expectedStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.expectedStatus)
			}
			if strings.Contains(response.Body.String(), test.wantContains) {
				return
			}
			t.Errorf("body missing %q: %s", test.wantContains, response.Body.String())
		})
	}
}

func TestSettingsPasswordUpdate(t *testing.T) {
	tests := []struct {
		name           string
		updater        PasswordSettingsUpdater
		body           string
		expectedStatus int
		wantContains   string
	}{
		{name: "success", updater: settingsPasswordUpdater{}, body: "current_password=old&new_password=new-password", expectedStatus: http.StatusOK, wantContains: "Password updated."},
		{name: "wrong current", updater: settingsPasswordUpdater{err: service.ErrCurrentPasswordMismatch}, body: "current_password=wrong&new_password=new-password", expectedStatus: http.StatusUnprocessableEntity, wantContains: "not correct"},
		{name: "missing current", updater: settingsPasswordUpdater{err: service.ErrCurrentPasswordRequired}, body: "new_password=new-password", expectedStatus: http.StatusUnprocessableEntity, wantContains: "Enter your current password"},
		{name: "weak", updater: settingsPasswordUpdater{err: service.ErrPasswordTooShort}, body: "current_password=old&new_password=short", expectedStatus: http.StatusUnprocessableEntity, wantContains: "between 8 and 128"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := settingsStubDependencies(t)
			dependencies.Users = testUserFinder{user: service.User{ID: 7, Version: 1}}
			dependencies.PasswordSettings = test.updater
			handler, _ := newSettingsTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/account/settings/password", 7, test.body)
			response := httptest.NewRecorder()
			handler.updatePassword(response, request)
			if response.Code != test.expectedStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.expectedStatus)
			}
			if !strings.Contains(response.Body.String(), test.wantContains) {
				t.Errorf("body missing %q", test.wantContains)
			}
		})
	}
}

func TestSettingsLocaleUpdateRedirectsToSelectedLanguage(t *testing.T) {
	dependencies := settingsStubDependencies(t)
	dependencies.Users = testUserFinder{user: service.User{ID: 7, Locale: "en", Version: 1}}
	dependencies.LocaleSettings = settingsLocaleUpdater{}
	handler, _ := newSettingsTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/account/settings/locale", 7, "locale=hu")
	response := httptest.NewRecorder()
	handler.updateLocale(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/hu/account/settings" {
		t.Fatalf("redirect = %q, want /hu/account/settings", location)
	}
}

func TestSettingsLocaleUpdateRejectsUnsupported(t *testing.T) {
	dependencies := settingsStubDependencies(t)
	dependencies.Users = testUserFinder{user: service.User{ID: 7, Locale: "en", Version: 1}}
	dependencies.LocaleSettings = settingsLocaleUpdater{err: service.ErrInvalidLocale}
	handler, _ := newSettingsTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/account/settings/locale", 7, "locale=de")
	response := httptest.NewRecorder()
	handler.updateLocale(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if !strings.Contains(response.Body.String(), "available languages") {
		t.Errorf("body missing invalid locale message")
	}
}

func TestSettingsIdentityUnlink(t *testing.T) {
	tests := []struct {
		name           string
		unlinker       IdentityUnlinker
		body           string
		expectedStatus int
		wantContains   string
	}{
		{name: "success", unlinker: settingsUnlinker{}, body: "identity_id=3", expectedStatus: http.StatusOK, wantContains: "identity removed"},
		{name: "last method", unlinker: settingsUnlinker{err: service.ErrOAuthLastSignInMethod}, body: "identity_id=3", expectedStatus: http.StatusUnprocessableEntity, wantContains: "before removing your last sign-in"},
		{name: "missing identity", unlinker: settingsUnlinker{err: service.ErrOAuthIdentityNotFound}, body: "identity_id=3", expectedStatus: http.StatusNotFound, wantContains: "no longer available"},
		{name: "invalid id", unlinker: settingsUnlinker{}, body: "identity_id=abc", expectedStatus: http.StatusNotFound, wantContains: "no longer available"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := settingsStubDependencies(t)
			dependencies.Users = testUserFinder{user: service.User{ID: 7, Version: 1}}
			dependencies.IdentityUnlinker = test.unlinker
			handler, _ := newSettingsTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/account/settings/identity", 7, test.body)
			response := httptest.NewRecorder()
			handler.unlinkIdentity(response, request)
			if response.Code != test.expectedStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.expectedStatus)
			}
			if !strings.Contains(response.Body.String(), test.wantContains) {
				t.Errorf("body missing %q", test.wantContains)
			}
		})
	}
}

func TestSettingsIdentityLinkRedirectsToProvider(t *testing.T) {
	dependencies := settingsStubDependencies(t)
	dependencies.Users = testUserFinder{user: service.User{ID: 7, Version: 1}}
	dependencies.IdentityLink = settingsLinker{url: "https://provider.example.test/authorize"}
	handler, _ := newSettingsTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/account/settings/identity/link", 7, "provider=example")
	response := httptest.NewRecorder()
	handler.linkIdentity(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusFound)
	}
	if location := response.Header().Get("Location"); location != "https://provider.example.test/authorize" {
		t.Fatalf("redirect = %q", location)
	}
}

func TestSettingsThemeUpdate(t *testing.T) {
	tests := []struct {
		name           string
		updater        AccountThemeUpdater
		body           string
		expectedStatus int
	}{
		{name: "success", updater: settingsThemeUpdater{}, body: "theme=dark", expectedStatus: http.StatusNoContent},
		{name: "invalid theme", updater: settingsThemeUpdater{err: service.ErrInvalidTheme}, body: "theme=blue", expectedStatus: http.StatusUnprocessableEntity},
		{name: "missing dependency", updater: nil, body: "theme=dark", expectedStatus: http.StatusInternalServerError},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := settingsStubDependencies(t)
			dependencies.Users = testUserFinder{user: service.User{ID: 7, Version: 1}}
			if test.updater != nil {
				dependencies.ThemeUpdater = test.updater
			}
			handler, _ := newSettingsTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/account/theme", 7, test.body)
			response := httptest.NewRecorder()
			handler.updateTheme(response, request)
			if response.Code != test.expectedStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.expectedStatus)
			}
		})
	}
}

func TestSettingsFragmentResponseForHTMX(t *testing.T) {
	dependencies := settingsStubDependencies(t)
	dependencies.Users = testUserFinder{user: service.User{ID: 7, Username: strPtr("alice"), Locale: "en", Version: 1}}
	handler, _ := newSettingsTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodGet, "/en/account/settings", 7, "")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.page(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Errorf("HTMX request returned a full document")
	}
	if !strings.Contains(body, `id="page-content"`) {
		t.Errorf("HTMX fragment missing page-content region")
	}
}

func TestSettingsHTMXUnauthenticatedRedirect(t *testing.T) {
	handler, _ := newSettingsTestHandler(t, settingsStubDependencies(t))
	request := httptest.NewRequest(http.MethodGet, "/en/account/settings", nil)
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.page(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("HX-Redirect"); got != "/en/sign-in" {
		t.Fatalf("HX-Redirect = %q, want /en/sign-in", got)
	}
}

func newSettingsTestHandler(t *testing.T, dependencies Dependencies) (*settingsHandler, *PageRenderer) {
	t.Helper()
	renderer, err := NewPageRenderer()
	if err != nil {
		t.Fatalf("NewPageRenderer() error = %v", err)
	}
	return newSettingsHandler(renderer, dependencies), renderer
}

func settingsStubDependencies(t *testing.T) Dependencies {
	t.Helper()
	return Dependencies{
		Users:         testUserFinder{user: service.User{ID: 7, Version: 1}},
		Sessions:      testSessionLookup{session: service.Session{ID: "opaque-session", UserID: 7, CreatedAt: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}},
		SessionCookie: testSessionCookie(t),
	}
}

func authenticatedRequest(method, target string, _ int64, form string) *http.Request {
	body := strings.NewReader(form)
	request := httptest.NewRequest(method, target, body)
	if form != "" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	segments := strings.Split(strings.Trim(strings.SplitN(target, "?", 2)[0], "/"), "/")
	if len(segments) >= 3 && segments[1] == "groups" {
		request.SetPathValue("id", segments[2])
	}
	if len(segments) >= 5 && segments[3] == "members" {
		request.SetPathValue("memberID", segments[4])
	}
	request.AddCookie(&http.Cookie{Name: middleware.DefaultSessionCookieName, Value: "opaque-session"})
	return request
}

type settingsProfileUpdater struct{ err error }

func (u settingsProfileUpdater) Update(context.Context, int64, service.ProfileSettingsInput) (service.User, error) {
	if u.err != nil {
		return service.User{}, u.err
	}
	return service.User{ID: 7}, nil
}

type settingsPasswordUpdater struct{ err error }

func (u settingsPasswordUpdater) Update(context.Context, int64, service.PasswordSettingsInput) (service.User, error) {
	if u.err != nil {
		return service.User{}, u.err
	}
	return service.User{ID: 7}, nil
}

type settingsLocaleUpdater struct{ err error }

func (u settingsLocaleUpdater) Update(context.Context, int64, string) (service.User, error) {
	if u.err != nil {
		return service.User{}, u.err
	}
	return service.User{ID: 7}, nil
}

type settingsThemeUpdater struct{ err error }

func (u settingsThemeUpdater) UpdateTheme(context.Context, int64, string) error { return u.err }

type settingsIdentityLister struct {
	identities []service.OAuthIdentity
	err        error
}

func (l settingsIdentityLister) ListOAuthIdentities(context.Context, int64) ([]service.OAuthIdentity, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.identities, nil
}

type settingsUnlinker struct{ err error }

func (u settingsUnlinker) Unlink(context.Context, int64, int64) error { return u.err }

type settingsLinker struct {
	url string
	err error
}

func (l settingsLinker) StartLink(context.Context, int64, string) (string, error) {
	if l.err != nil {
		return "", l.err
	}
	return l.url, nil
}

var errSettingsUnexpected = errors.New("unexpected")

func strPtr(value string) *string { return &value }
