package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tewecske/goweb/internal/service"
)

func newAdminTestHandler(t *testing.T, dependencies Dependencies) *adminHandler {
	t.Helper()
	renderer, err := NewPageRenderer()
	if err != nil {
		t.Fatalf("NewPageRenderer() error = %v", err)
	}
	return newAdminHandler(renderer, dependencies)
}

func adminStubDependencies(t *testing.T, admin bool) Dependencies {
	t.Helper()
	dependencies := settingsStubDependencies(t)
	dependencies.Users = testUserFinder{user: service.User{ID: 7, IsAdmin: admin, Version: 1}}
	return dependencies
}

func TestAdminIndexRedirectsUnauthenticated(t *testing.T) {
	handler := newAdminTestHandler(t, settingsStubDependencies(t))
	request := httptest.NewRequest(http.MethodGet, "/en/admin", nil)
	response := httptest.NewRecorder()
	handler.index(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/en/sign-in" {
		t.Fatalf("redirect = %q, want /en/sign-in", location)
	}
}

func TestAdminIndexHTMXUnauthenticatedRedirect(t *testing.T) {
	handler := newAdminTestHandler(t, settingsStubDependencies(t))
	request := httptest.NewRequest(http.MethodGet, "/en/admin", nil)
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.index(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("HX-Redirect"); got != "/en/sign-in" {
		t.Fatalf("HX-Redirect = %q, want /en/sign-in", got)
	}
}

func TestAdminIndexDeniesNonAdministrator(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, false))

	response := httptest.NewRecorder()
	handler.index(response, authenticatedRequest(http.MethodGet, "/en/admin", 7, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Access denied") {
		t.Errorf("body missing access-denied heading")
	}
	if !strings.Contains(body, "<!doctype html>") {
		t.Errorf("expected a full document for a normal request")
	}
}

func TestAdminIndexDeniesNonAdministratorFragment(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, false))
	request := authenticatedRequest(http.MethodGet, "/en/admin", 7, "")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.index(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Access denied") {
		t.Errorf("fragment missing access-denied heading")
	}
	if strings.Contains(body, "<!doctype html>") {
		t.Errorf("HTMX request returned a full document")
	}
	if !strings.Contains(body, `id="page-heading"`) {
		t.Errorf("fragment missing accessible heading")
	}
}

func TestAdminIndexAllowsAdministrator(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, true))
	response := httptest.NewRecorder()
	handler.index(response, authenticatedRequest(http.MethodGet, "/en/admin", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Administration") {
		t.Errorf("body missing administration heading")
	}
	if strings.Contains(body, "Access denied") {
		t.Errorf("administrator unexpectedly denied")
	}
}

func TestAdminIndexRejectsNonGET(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, true))
	response := httptest.NewRecorder()
	handler.index(response, authenticatedRequest(http.MethodPost, "/en/admin", 7, ""))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminIndexLocalizesAccessDenied(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, false))
	response := httptest.NewRecorder()
	handler.index(response, authenticatedRequest(http.MethodGet, "/hu/admin", 7, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if !strings.Contains(response.Body.String(), "Hozzáférés megtagadva") {
		t.Errorf("body missing localized access-denied heading")
	}
}
