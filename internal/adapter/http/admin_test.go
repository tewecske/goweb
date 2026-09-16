package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/internal/service"
	"github.com/tewecske/goweb/templates"
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

func TestAdminListRendersAccountsAndPagination(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccounts = &adminAccountListerStub{page: service.AdminUserPage{
		Total: 45,
		Page:  2,
		Size:  20,
		Pages: 3,
		Users: []service.User{
			{ID: 1, Email: strPtr("alice@example.test"), IsAdmin: true, CreatedAt: 1700000000},
			{ID: 2, Email: strPtr("bob@example.test"), CreatedAt: 1700000600, EmailVerifiedAt: intPtr(1700000600)},
		},
	}}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.list(response, authenticatedRequest(http.MethodGet, "/en/admin/users?page=2", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"alice@example.test", "bob@example.test", "Administrator", "Unconfirmed", "Confirmed", `data-account-id="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("list body missing %q", want)
		}
	}
	if !strings.Contains(body, "Previous") || !strings.Contains(body, "Next") {
		t.Errorf("list body missing pagination controls")
	}
}

func TestAdminListRendersEmptyState(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccounts = &adminAccountListerStub{page: service.AdminUserPage{Total: 0, Page: 1, Size: 20, Pages: 0}}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.list(response, authenticatedRequest(http.MethodGet, "/en/admin/users?q=missing", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "No accounts match") {
		t.Errorf("body missing empty-state message")
	}
}

func TestAdminListNormalizesQueryAndReflectsState(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	lister := &adminAccountListerStub{}
	dependencies.AdminAccounts = lister
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	request := authenticatedRequest(http.MethodGet, "/en/admin/users?page=-3&size=9999&admin=yes&q=%20alice%20", 7, "")
	handler.list(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if lister.received.Page != 1 || lister.received.Size != service.MaxAdminPageSize {
		t.Fatalf("received query = %+v, want page 1 size %d", lister.received, service.MaxAdminPageSize)
	}
	if lister.received.Admin != service.AdminFilterYes || lister.received.Search != "alice" {
		t.Fatalf("received filters = %+v, want admin yes search alice", lister.received)
	}
	if !strings.Contains(response.Body.String(), `value="alice"`) {
		t.Errorf("body missing preserved search value")
	}
}

func TestAdminListFragmentForHTMX(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccounts = &adminAccountListerStub{page: service.AdminUserPage{Total: 1, Page: 1, Size: 20, Pages: 1, Users: []service.User{{ID: 1, Email: strPtr("alice@example.test")}}}}
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodGet, "/en/admin/users", 7, "")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.list(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Errorf("HTMX request returned a full document")
	}
	if !strings.Contains(body, `id="page-content"`) {
		t.Errorf("fragment missing page-content region")
	}
	if !strings.Contains(body, "alice@example.test") {
		t.Errorf("fragment missing account row")
	}
}

func TestAdminListReportsRepositoryFailure(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccounts = &adminAccountListerStub{err: errListFailure}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.list(response, authenticatedRequest(http.MethodGet, "/en/admin/users", 7, ""))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
}

func intPtr(value int64) *int64 { return &value }

var errListFailure = errors.New("list failure")

type adminAccountListerStub struct {
	page     service.AdminUserPage
	err      error
	received service.AdminUserQuery
}

func (s *adminAccountListerStub) List(_ context.Context, query service.AdminUserQuery) (service.AdminUserPage, error) {
	s.received = query
	if s.err != nil {
		return service.AdminUserPage{}, s.err
	}
	return s.page, nil
}

func TestAdminCreateAccountRendersForm(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountCreator = &adminAccountCreatorStub{}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.createAccount(response, authenticatedRequest(http.MethodGet, "/en/admin/users/new", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"Create account", `name="email"`, `name="password"`, `name="is_admin"`} {
		if !strings.Contains(body, want) {
			t.Errorf("create form missing %q", want)
		}
	}
}

func TestAdminCreateAccountSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	creator := &adminAccountCreatorStub{created: service.User{ID: 11}}
	dependencies.AdminAccountCreator = creator
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.createAccount(response, authenticatedRequest(http.MethodPost, "/en/admin/users/new", 7, "email=New@Example.Test&password=correct-horse-battery&is_admin=true"))
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/en/admin/users" {
		t.Fatalf("redirect = %q, want /en/admin/users", location)
	}
	if creator.received.Email != "New@Example.Test" || !creator.received.IsAdmin {
		t.Fatalf("input = %+v, want submitted values", creator.received)
	}
	if creator.actor.ActorID != 7 {
		t.Fatalf("actor = %+v, want id 7", creator.actor)
	}
}

func TestAdminCreateAccountHTMXRedirect(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountCreator = &adminAccountCreatorStub{created: service.User{ID: 11}}
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/new", 7, "email=new@example.test")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.createAccount(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("HX-Redirect"); got != "/en/admin/users" {
		t.Fatalf("HX-Redirect = %q, want /en/admin/users", got)
	}
}

func TestAdminCreateAccountRejectsDuplicateEmail(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountCreator = &adminAccountCreatorStub{err: service.ErrDuplicateEmail}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.createAccount(response, authenticatedRequest(http.MethodPost, "/en/admin/users/new", 7, "email=dup@example.test"))
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if !strings.Contains(response.Body.String(), "already uses this email") {
		t.Errorf("body missing duplicate-email message")
	}
}

func TestAdminCreateAccountRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{name: "invalid email", err: service.ErrInvalidEmail, contains: "valid email"},
		{name: "weak password", err: service.ErrPasswordTooShort, contains: "between 8 and 128"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := adminStubDependencies(t, true)
			dependencies.AdminAccountCreator = &adminAccountCreatorStub{err: test.err}
			handler := newAdminTestHandler(t, dependencies)
			response := httptest.NewRecorder()
			handler.createAccount(response, authenticatedRequest(http.MethodPost, "/en/admin/users/new", 7, "email=a@example.test"))
			if response.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
			}
			if !strings.Contains(response.Body.String(), test.contains) {
				t.Errorf("body missing %q", test.contains)
			}
		})
	}
}

func TestAdminCreateAccountRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminAccountCreator = &adminAccountCreatorStub{}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.createAccount(response, authenticatedRequest(http.MethodGet, "/en/admin/users/new", 7, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminAccountCreatorStub struct {
	created  service.User
	err      error
	actor    service.AdminActionContext
	received service.AdminAccountInput
}

func (s *adminAccountCreatorStub) Create(_ context.Context, actor service.AdminActionContext, input service.AdminAccountInput) (service.User, error) {
	s.actor = actor
	s.received = input
	if s.err != nil {
		return service.User{}, s.err
	}
	return s.created, nil
}

func TestAdminEditAccountRendersPrefilledForm(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountEditor = &adminAccountEditorStub{found: service.User{ID: 9, Email: strPtr("edit@example.test"), IsAdmin: true, Version: 4}}
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodGet, "/en/admin/users/9/edit", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.editAccount(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{`value="edit@example.test"`, `name="version" value="4"`, "checked"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form missing %q", want)
		}
	}
}

func TestAdminEditAccountSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	editor := &adminAccountEditorStub{found: service.User{ID: 9, Email: strPtr("old@example.test"), Version: 2}, updated: service.User{ID: 9}}
	dependencies.AdminAccountEditor = editor
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/edit", 7, "email=new@example.test&version=2&is_admin=true")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.editAccount(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/en/admin/users/9" {
		t.Fatalf("redirect = %q, want /en/admin/users/9", location)
	}
	if editor.received.Version != 2 || !editor.received.IsAdmin || editor.received.Email != "new@example.test" {
		t.Fatalf("update input = %+v, want submitted values", editor.received)
	}
	if editor.targetID != 9 {
		t.Fatalf("target = %d, want 9", editor.targetID)
	}
}

func TestAdminEditAccountErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "conflict", err: service.ErrOptimisticLockConflict, status: http.StatusConflict},
		{name: "duplicate email", err: service.ErrDuplicateEmail, status: http.StatusConflict},
		{name: "invalid email", err: service.ErrInvalidEmail, status: http.StatusUnprocessableEntity},
		{name: "weak password", err: service.ErrPasswordTooShort, status: http.StatusUnprocessableEntity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := adminStubDependencies(t, true)
			dependencies.AdminAccountEditor = &adminAccountEditorStub{found: service.User{ID: 9, Version: 1}, updateErr: test.err}
			handler := newAdminTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/edit", 7, "email=a@example.test&version=1")
			request.SetPathValue("id", "9")
			response := httptest.NewRecorder()
			handler.editAccount(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestAdminEditAccountMissingRecordRendersNotFound(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountEditor = &adminAccountEditorStub{findErr: service.ErrRecordNotFound}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodGet, "/en/admin/users/9/edit", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.editAccount(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAdminEditAccountRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminAccountEditor = &adminAccountEditorStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodGet, "/en/admin/users/9/edit", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.editAccount(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestAdminDeleteAccountSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	editor := &adminAccountEditorStub{}
	dependencies.AdminAccountEditor = editor
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/delete", 7, "version=3&confirm=true")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.deleteAccount(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if location := response.Header().Get("Location"); location != "/en/admin/users" {
		t.Fatalf("redirect = %q, want /en/admin/users", location)
	}
	if editor.deleteID != 9 || editor.deleteVer != 3 {
		t.Fatalf("delete = id %d version %d, want 9/3", editor.deleteID, editor.deleteVer)
	}
}

func TestAdminDeleteAccountRequiresConfirmation(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	editor := &adminAccountEditorStub{}
	dependencies.AdminAccountEditor = editor
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/delete", 7, "version=3")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.deleteAccount(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnprocessableEntity)
	}
	if !strings.Contains(response.Body.String(), "Confirm the deletion") {
		t.Errorf("body missing confirmation message")
	}
	if editor.deleteCalls != 0 {
		t.Fatal("Delete called without confirmation")
	}
}

func TestAdminDeleteAccountErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "self", err: service.ErrAdminSelfAction, status: http.StatusUnprocessableEntity},
		{name: "conflict", err: service.ErrOptimisticLockConflict, status: http.StatusConflict},
		{name: "missing", err: service.ErrRecordNotFound, status: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := adminStubDependencies(t, true)
			dependencies.AdminAccountEditor = &adminAccountEditorStub{deleteErr: test.err}
			handler := newAdminTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/delete", 7, "version=3&confirm=true")
			request.SetPathValue("id", "9")
			response := httptest.NewRecorder()
			handler.deleteAccount(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestAdminEditAccountHidesSelfDelete(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountEditor = &adminAccountEditorStub{found: service.User{ID: 7, Email: strPtr("self@example.test"), IsAdmin: true, Version: 1}}
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodGet, "/en/admin/users/7/edit", 7, "")
	request.SetPathValue("id", "7")
	response := httptest.NewRecorder()
	handler.editAccount(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if strings.Contains(response.Body.String(), `name="confirm"`) {
		t.Errorf("self account exposes a delete confirmation control")
	}
}

func TestAdminDetailRendersSafeDiagnostics(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{detail: service.AdminUserDetail{
		User:          service.User{ID: 9, Email: strPtr("target@example.test"), IsAdmin: true, Version: 2},
		Confirmed:     true,
		Sessions:      []service.Session{{ID: "super-secret-session-digest", UserID: 9, CreatedAt: 100, ExpiresAt: 200}},
		LoginAttempts: []service.LoginAttempt{{ID: 1, Email: "target@example.test", Outcome: service.LoginOutcomeSuccess, CreatedAt: 150}},
		Identities:    []service.OAuthIdentity{{ID: 4, UserID: 9, Provider: "example", Email: "target@example.test"}},
	}}
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodGet, "/en/admin/users/9", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.detail(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"target@example.test", "Active sessions", "Success", "example", "Email confirmed"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail body missing %q", want)
		}
	}
	if strings.Contains(body, "super-secret-session-digest") {
		t.Errorf("detail body exposes a session identifier")
	}
	if strings.Contains(body, "password_hash") {
		t.Errorf("detail body exposes credential fields")
	}
}

func TestAdminDetailMissingAccountRendersNotFound(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{err: service.ErrRecordNotFound}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodGet, "/en/admin/users/9", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.detail(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAdminDetailRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodGet, "/en/admin/users/9", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.detail(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminUserDetailerStub struct {
	detail service.AdminUserDetail
	err    error
}

func (s *adminUserDetailerStub) Detail(context.Context, int64) (service.AdminUserDetail, error) {
	if s.err != nil {
		return service.AdminUserDetail{}, s.err
	}
	return s.detail, nil
}

type adminAccountEditorStub struct {
	found       service.User
	findErr     error
	updated     service.User
	updateErr   error
	deleteErr   error
	actor       service.AdminActionContext
	targetID    int64
	deleteID    int64
	deleteVer   int64
	deleteCalls int
	received    service.AdminAccountUpdateInput
}

func (s *adminAccountEditorStub) Find(context.Context, int64) (service.User, error) {
	if s.findErr != nil {
		return service.User{}, s.findErr
	}
	return s.found, nil
}

func (s *adminAccountEditorStub) Update(_ context.Context, actor service.AdminActionContext, targetID int64, input service.AdminAccountUpdateInput) (service.User, error) {
	s.actor = actor
	s.targetID = targetID
	s.received = input
	if s.updateErr != nil {
		return service.User{}, s.updateErr
	}
	return s.updated, nil
}

func (s *adminAccountEditorStub) Delete(_ context.Context, actor service.AdminActionContext, targetID, version int64) error {
	s.actor = actor
	s.deleteID = targetID
	s.deleteVer = version
	s.deleteCalls++
	return s.deleteErr
}

func TestAdminRevokeSessionsSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{detail: service.AdminUserDetail{User: service.User{ID: 9, Email: strPtr("target@example.test")}}}
	revoker := &adminSessionRevokerStub{}
	dependencies.AdminSessionRevoker = revoker
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/sessions/revoke", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.revokeSessions(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if revoker.id != 9 {
		t.Fatalf("revoked id = %d, want 9", revoker.id)
	}
	if !strings.Contains(response.Body.String(), "All sessions ended") {
		t.Errorf("body missing sessions-ended message")
	}
}

func TestAdminRevokeSessionsMissingAccount(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{}
	dependencies.AdminSessionRevoker = &adminSessionRevokerStub{err: service.ErrRecordNotFound}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/sessions/revoke", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.revokeSessions(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAdminRevokeSessionsRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminSessionRevoker = &adminSessionRevokerStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/sessions/revoke", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.revokeSessions(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminSessionRevokerStub struct {
	id  int64
	err error
}

func (s *adminSessionRevokerStub) RevokeSessions(_ context.Context, _ service.AdminActionContext, id int64) error {
	s.id = id
	return s.err
}

func TestAdminConfirmEmailSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{detail: service.AdminUserDetail{User: service.User{ID: 9, Email: strPtr("target@example.test")}}}
	confirmation := &adminConfirmationStub{}
	dependencies.AdminConfirmation = confirmation
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/confirm-email", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.confirmEmailAccount(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if confirmation.confirmID != 9 {
		t.Fatalf("confirmed id = %d, want 9", confirmation.confirmID)
	}
	if !strings.Contains(response.Body.String(), "Email confirmed") {
		t.Errorf("body missing confirmation success message")
	}
}

func TestAdminSendConfirmationSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{detail: service.AdminUserDetail{User: service.User{ID: 9, Email: strPtr("target@example.test")}}}
	confirmation := &adminConfirmationStub{}
	dependencies.AdminConfirmation = confirmation
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/send-confirmation", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.sendConfirmation(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if confirmation.sendID != 9 {
		t.Fatalf("sent id = %d, want 9", confirmation.sendID)
	}
	if !strings.Contains(response.Body.String(), "Confirmation link sent") {
		t.Errorf("body missing sent message")
	}
}

func TestAdminConfirmationActionErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "missing", err: service.ErrRecordNotFound, status: http.StatusNotFound},
		{name: "no email", err: service.ErrInvalidConfirmationAccount, status: http.StatusUnprocessableEntity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := adminStubDependencies(t, true)
			dependencies.AdminUserDetailer = &adminUserDetailerStub{}
			dependencies.AdminConfirmation = &adminConfirmationStub{err: test.err}
			handler := newAdminTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/confirm-email", 7, "")
			request.SetPathValue("id", "9")
			response := httptest.NewRecorder()
			handler.confirmEmailAccount(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestAdminConfirmationRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminConfirmation = &adminConfirmationStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/send-confirmation", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.sendConfirmation(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminConfirmationStub struct {
	confirmID int64
	sendID    int64
	err       error
}

func (s *adminConfirmationStub) ConfirmEmail(_ context.Context, _ service.AdminActionContext, id int64) error {
	s.confirmID = id
	return s.err
}

func (s *adminConfirmationStub) SendConfirmation(_ context.Context, _ service.AdminActionContext, id int64) error {
	s.sendID = id
	return s.err
}

func TestAdminRemoveIdentitySucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminUserDetailer = &adminUserDetailerStub{detail: service.AdminUserDetail{User: service.User{ID: 9, Email: strPtr("target@example.test")}}}
	identity := &adminIdentityStub{}
	dependencies.AdminIdentity = identity
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/identities/4/remove", 7, "")
	request.SetPathValue("id", "9")
	request.SetPathValue("identityID", "4")
	response := httptest.NewRecorder()
	handler.removeIdentity(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if identity.accountID != 9 || identity.identityID != 4 {
		t.Fatalf("remove = account %d identity %d, want 9/4", identity.accountID, identity.identityID)
	}
	if !strings.Contains(response.Body.String(), "Linked provider removed") {
		t.Errorf("body missing removal message")
	}
}

func TestAdminRemoveIdentityErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "missing account", err: service.ErrRecordNotFound, status: http.StatusNotFound},
		{name: "last method", err: service.ErrOAuthLastSignInMethod, status: http.StatusUnprocessableEntity},
		{name: "missing identity", err: service.ErrOAuthIdentityNotFound, status: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dependencies := adminStubDependencies(t, true)
			dependencies.AdminUserDetailer = &adminUserDetailerStub{}
			dependencies.AdminIdentity = &adminIdentityStub{err: test.err}
			handler := newAdminTestHandler(t, dependencies)
			request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/identities/4/remove", 7, "")
			request.SetPathValue("id", "9")
			request.SetPathValue("identityID", "4")
			response := httptest.NewRecorder()
			handler.removeIdentity(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestAdminRemoveIdentityInvalidIdentityID(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminIdentity = &adminIdentityStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/identities/abc/remove", 7, "")
	request.SetPathValue("id", "9")
	request.SetPathValue("identityID", "abc")
	response := httptest.NewRecorder()
	handler.removeIdentity(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAdminRemoveIdentityRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminIdentity = &adminIdentityStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/identities/4/remove", 7, "")
	request.SetPathValue("id", "9")
	request.SetPathValue("identityID", "4")
	response := httptest.NewRecorder()
	handler.removeIdentity(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminIdentityStub struct {
	accountID  int64
	identityID int64
	err        error
}

func (s *adminIdentityStub) RemoveIdentity(_ context.Context, _ service.AdminActionContext, accountID, identityID int64) error {
	s.accountID = accountID
	s.identityID = identityID
	return s.err
}

func TestAdminLabelsCoverTemplate(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, true))
	labels := handler.labels(locale.English)
	raw, err := templates.FS.ReadFile("admin.html")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	pattern := regexp.MustCompile(`\$?\.?Labels\.([a-z0-9_]+)`)
	matches := pattern.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatal("no label references found in admin template")
	}
	for _, match := range matches {
		if _, ok := labels[match[1]]; !ok {
			t.Errorf("template references missing label %q", match[1])
		}
	}
}

func TestAdminClearLockoutSucceeds(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountEditor = &adminAccountEditorStub{found: service.User{ID: 9, Email: strPtr("locked@example.test")}}
	dependencies.AdminUserDetailer = &adminUserDetailerStub{detail: service.AdminUserDetail{User: service.User{ID: 9, Email: strPtr("locked@example.test")}}}
	lockout := &adminLockoutStub{}
	dependencies.AdminLockout = lockout
	handler := newAdminTestHandler(t, dependencies)

	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/lockout/clear", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.clearLockout(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if lockout.clearedID != 9 {
		t.Fatalf("cleared id = %d, want 9", lockout.clearedID)
	}
	if !strings.Contains(response.Body.String(), "Lockout cleared") {
		t.Errorf("body missing lockout-cleared message")
	}
}

func TestAdminClearLockoutMissingAccount(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAccountEditor = &adminAccountEditorStub{findErr: service.ErrRecordNotFound}
	dependencies.AdminLockout = &adminLockoutStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/lockout/clear", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.clearLockout(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAdminClearLockoutRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminLockout = &adminLockoutStub{}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodPost, "/en/admin/users/9/lockout/clear", 7, "")
	request.SetPathValue("id", "9")
	response := httptest.NewRecorder()
	handler.clearLockout(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminLockoutStub struct {
	clearedID int64
	status    service.LockoutStatus
	err       error
}

func (s *adminLockoutStub) Status(context.Context, service.User) (service.LockoutStatus, error) {
	if s.err != nil {
		return service.LockoutStatus{}, s.err
	}
	return s.status, nil
}

func (s *adminLockoutStub) Clear(_ context.Context, _ service.AdminActionContext, account service.User) error {
	if s.err != nil {
		return s.err
	}
	s.clearedID = account.ID
	return nil
}

func TestAdminAuditRendersEntries(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	actorEmail := "actor@example.test"
	targetType, targetID, detail, ip := "user", "9", "created account", "203.0.113.1"
	dependencies.AdminAudit = &adminAuditReaderStub{page: service.AuditPage{
		Total: 1, Page: 1, Size: 20, Pages: 1,
		Entries: []service.AuditEntry{{
			ID: 1, OccurredAt: 1700000000, ActorEmail: &actorEmail, Action: service.AuditActionAccountCreated,
			TargetType: &targetType, TargetID: &targetID, Detail: &detail, IP: &ip,
		}},
	}}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.audit(response, authenticatedRequest(http.MethodGet, "/en/admin/audit?action=created&actor=actor", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"actor@example.test", service.AuditActionAccountCreated, "created account", "203.0.113.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit body missing %q", want)
		}
	}
}

func TestAdminAuditRendersEmptyState(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAudit = &adminAuditReaderStub{page: service.AuditPage{Total: 0, Page: 1, Size: 20, Pages: 0}}
	handler := newAdminTestHandler(t, dependencies)
	response := httptest.NewRecorder()
	handler.audit(response, authenticatedRequest(http.MethodGet, "/en/admin/audit", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "No audit entries match") {
		t.Errorf("body missing empty-state message")
	}
}

func TestAdminAuditFragmentAndPaging(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminAudit = &adminAuditReaderStub{page: service.AuditPage{Total: 60, Page: 2, Size: 20, Pages: 3}}
	handler := newAdminTestHandler(t, dependencies)
	request := authenticatedRequest(http.MethodGet, "/en/admin/audit?page=2", 7, "")
	request.Header.Set("HX-Request", "true")
	response := httptest.NewRecorder()
	handler.audit(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if strings.Contains(body, "<!doctype html>") {
		t.Errorf("HTMX request returned a full document")
	}
	if !strings.Contains(body, "Previous") || !strings.Contains(body, "Next") {
		t.Errorf("audit fragment missing pagination controls")
	}
}

func TestAdminAuditRejectsNonAdmin(t *testing.T) {
	dependencies := adminStubDependencies(t, false)
	dependencies.AdminAudit = &adminAuditReaderStub{}
	handler := newAdminTestHandler(t, dependencies)
	response := httptest.NewRecorder()
	handler.audit(response, authenticatedRequest(http.MethodGet, "/en/admin/audit", 7, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

type adminAuditReaderStub struct {
	page     service.AuditPage
	err      error
	received service.AuditQuery
}

func (s *adminAuditReaderStub) List(_ context.Context, query service.AuditQuery) (service.AuditPage, error) {
	s.received = query
	if s.err != nil {
		return service.AuditPage{}, s.err
	}
	return s.page, nil
}

func TestAdminSystemRendersJobHealth(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminMaintenance = &adminMaintenanceStub{statuses: []service.MaintenanceStatus{
		{Job: service.MaintenanceJobGuestCleanup, Runs: 4, Failures: 1, LastFinishedAt: 1700000000, LastDuration: 2 * time.Second, LastDeleted: 3, LastError: "postgres: database operation failed"},
	}}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.system(response, authenticatedRequest(http.MethodGet, "/en/admin/system", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"Background jobs", "Guest cleanup", `data-job="guest_cleanup"`, "postgres: database operation failed"} {
		if !strings.Contains(body, want) {
			t.Errorf("system body missing %q", want)
		}
	}
}

func TestAdminSystemDeniesNonAdmin(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, false))
	response := httptest.NewRecorder()
	handler.system(response, authenticatedRequest(http.MethodGet, "/en/admin/system", 7, ""))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestAdminSystemRejectsNonGET(t *testing.T) {
	handler := newAdminTestHandler(t, adminStubDependencies(t, true))
	response := httptest.NewRecorder()
	handler.system(response, authenticatedRequest(http.MethodPost, "/en/admin/system", 7, ""))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func TestAdminRunMaintenanceAuditsAndReportsSuccess(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	maintenance := &adminMaintenanceStub{runs: []service.MaintenanceRun{
		{Job: service.MaintenanceJobGuestCleanup, Deleted: 2},
	}}
	recorder := &adminAuditRecorderStub{}
	dependencies.AdminMaintenance = maintenance
	dependencies.AdminAuditRecorder = recorder
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.runMaintenance(response, authenticatedRequest(http.MethodPost, "/en/admin/system/maintenance/run", 7, "_csrf=token"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if maintenance.calls != 1 {
		t.Fatalf("RunOnce calls = %d, want 1", maintenance.calls)
	}
	if !strings.Contains(response.Body.String(), "Cleanup jobs completed.") {
		t.Errorf("body missing success alert")
	}
	if len(recorder.records) != 1 || recorder.records[0].Action != service.AuditActionMaintenanceRun {
		t.Fatalf("audit records = %+v, want maintenance run", recorder.records)
	}
	if !strings.Contains(recorder.records[0].Detail, "jobs=1") {
		t.Errorf("audit detail = %q, want job count", recorder.records[0].Detail)
	}
}

func TestAdminRunMaintenanceReportsPartialFailure(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminMaintenance = &adminMaintenanceStub{runs: []service.MaintenanceRun{
		{Job: service.MaintenanceJobGuestCleanup, Err: "boom"},
	}}
	dependencies.AdminAuditRecorder = &adminAuditRecorderStub{}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.runMaintenance(response, authenticatedRequest(http.MethodPost, "/en/admin/system/maintenance/run", 7, "_csrf=token"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "one or more job failures") {
		t.Errorf("body missing partial-failure alert")
	}
}

func TestAdminRunMaintenanceRejectsNonPOST(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminMaintenance = &adminMaintenanceStub{}
	handler := newAdminTestHandler(t, dependencies)
	response := httptest.NewRecorder()
	handler.runMaintenance(response, authenticatedRequest(http.MethodGet, "/en/admin/system/maintenance/run", 7, ""))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

type adminMaintenanceStub struct {
	statuses []service.MaintenanceStatus
	runs     []service.MaintenanceRun
	err      error
	calls    int
}

func (s *adminMaintenanceStub) RunOnce(context.Context) ([]service.MaintenanceRun, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.runs, nil
}

func (s *adminMaintenanceStub) RunJob(context.Context, string) (service.MaintenanceRun, error) {
	if s.err != nil {
		return service.MaintenanceRun{}, s.err
	}
	return service.MaintenanceRun{}, nil
}

func (s *adminMaintenanceStub) Status() []service.MaintenanceStatus {
	return s.statuses
}

type adminAuditRecorderStub struct {
	records []service.AuditRecord
	err     error
}

func (s *adminAuditRecorderStub) Record(_ context.Context, record service.AuditRecord) error {
	s.records = append(s.records, record)
	return s.err
}

func TestAdminSystemRendersSanitizedConfiguration(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminSystemConfig = adminSystemConfigStub{configuration: service.SystemConfiguration{
		Environment:               "production",
		PublicAddress:             ":8443",
		PublicURL:                 "https://example.test",
		EmailConfirmationRequired: true,
		SecureSessionCookies:      true,
		Providers:                 []string{"example"},
		MailConfigured:            true,
		MailRelay:                 "smtp://mail.example.test:587",
		SessionLifetime:           24 * time.Hour,
		GuestRetention:            720 * time.Hour,
		LoginAttemptRetention:     720 * time.Hour,
		UsageRetention:            2160 * time.Hour,
		MaintenanceInterval:       6 * time.Hour,
		AuthRateLimit:             10,
		AuthRateLimitWindow:       time.Minute,
		TrustedProxy:              "10.0.0.0/8",
	}}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.system(response, authenticatedRequest(http.MethodGet, "/en/admin/system", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"Configuration", "https://example.test", "smtp://mail.example.test:587", "10.0.0.0/8", "example"} {
		if !strings.Contains(body, want) {
			t.Errorf("system body missing %q", want)
		}
	}
	if strings.Contains(body, "password") || strings.Contains(body, "user:") {
		t.Errorf("system body leaked a credential")
	}
}

type adminSystemConfigStub struct {
	configuration service.SystemConfiguration
}

func (s adminSystemConfigStub) SystemConfiguration() service.SystemConfiguration {
	return s.configuration
}

func TestAdminSystemRendersRuntimeAndMigrations(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	installedAt := time.Unix(1700000000, 0)
	dependencies.AdminRuntime = adminRuntimeStub{
		info: service.RuntimeInfo{
			Version:        "1.2.3",
			StartedAt:      1700000000,
			Uptime:         90 * time.Minute,
			GoVersion:      "go1.26.5",
			GOOS:           "linux",
			GOARCH:         "arm64",
			NumCPU:         8,
			GOMAXPROCS:     8,
			Goroutines:     12,
			HeapAllocBytes: 4 * 1024 * 1024,
			SysBytes:       8 * 1024 * 1024,
			NumGC:          3,
		},
		migrations: []service.MigrationInfo{
			{Rank: 1, Version: 1, Description: "create_users", Installed: true, InstalledAt: &installedAt},
			{Rank: 2, Version: 2, Description: "pending_change", Installed: false},
		},
	}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.system(response, authenticatedRequest(http.MethodGet, "/en/admin/system", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"Runtime", "1.2.3", "go1.26.5", "linux/arm64", "Migrations", "create_users", "pending_change", "Installed", "Pending"} {
		if !strings.Contains(body, want) {
			t.Errorf("system body missing %q", want)
		}
	}
}

type adminRuntimeStub struct {
	info       service.RuntimeInfo
	migrations []service.MigrationInfo
	err        error
}

func (s adminRuntimeStub) RuntimeInfo() service.RuntimeInfo { return s.info }

func (s adminRuntimeStub) Migrations(context.Context) ([]service.MigrationInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.migrations, nil
}

func TestAdminSystemRendersDatastoreCounts(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminDatastoreStats = adminDatastoreStatsStub{counts: service.DatastoreCounts{
		TotalAccounts:              12,
		GuestAccounts:              3,
		AdministratorAccounts:      2,
		UnconfirmedAccounts:        4,
		AccountsWithoutPassword:    5,
		ActiveSessions:             6,
		ExpiredSessions:            1,
		ExpiredEmailTokens:         2,
		ExpiredPasswordResetTokens: 3,
		ExpiredOAuthStates:         4,
		RecentFailedSignIns:        7,
		CurrentLockouts:            1,
	}}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.system(response, authenticatedRequest(http.MethodGet, "/en/admin/system", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"Data store", "Accounts", "Guests", "Current lockouts", "Failed sign-ins"} {
		if !strings.Contains(body, want) {
			t.Errorf("system body missing %q", want)
		}
	}
}

type adminDatastoreStatsStub struct {
	counts service.DatastoreCounts
	err    error
}

func (s adminDatastoreStatsStub) Counts(context.Context) (service.DatastoreCounts, error) {
	if s.err != nil {
		return service.DatastoreCounts{}, s.err
	}
	return s.counts, nil
}

func TestAdminRateLimitsListsRedactedBuckets(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminRateLimits = &adminRateLimitStub{
		overview: []service.RateLimitActionInfo{{Action: "signin.identifier", Limit: 5, Window: time.Minute, Buckets: 1, Locked: 1}},
		buckets:  []service.RateLimitBucketInfo{{Action: "signin.identifier", KeyHint: "s***********t", Count: 5, Limit: 5, RetryAfter: 30 * time.Second}},
	}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.rateLimits(response, authenticatedRequest(http.MethodGet, "/en/admin/ratelimits", 7, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	for _, want := range []string{"Rate limits", "signin.identifier", "s***********t", "Locked"} {
		if !strings.Contains(body, want) {
			t.Errorf("rate-limit body missing %q", want)
		}
	}
	if strings.Contains(body, "sensitive@example.test") {
		t.Errorf("rate-limit body leaked a raw limiter key")
	}
}

func TestAdminRateLimitClearIsAuditedThroughService(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	manager := &adminRateLimitStub{}
	dependencies.AdminRateLimits = manager
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.clearRateLimit(response, authenticatedRequest(http.MethodPost, "/en/admin/ratelimits/clear", 7, "_csrf=token&action=signin.identifier"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if manager.clearedAction != "signin.identifier" {
		t.Fatalf("cleared action = %q, want signin.identifier", manager.clearedAction)
	}
	if !strings.Contains(response.Body.String(), "Rate-limit budgets cleared.") {
		t.Errorf("body missing cleared alert")
	}
}

func TestAdminRateLimitClearAllClearsEveryBudget(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	manager := &adminRateLimitStub{}
	dependencies.AdminRateLimits = manager
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.clearRateLimit(response, authenticatedRequest(http.MethodPost, "/en/admin/ratelimits/clear", 7, "_csrf=token"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if manager.clearAllCalls != 1 {
		t.Fatalf("ClearAll calls = %d, want 1", manager.clearAllCalls)
	}
}

func TestAdminRateLimitUnknownActionReturnsNotFound(t *testing.T) {
	dependencies := adminStubDependencies(t, true)
	dependencies.AdminRateLimits = &adminRateLimitStub{clearErr: service.ErrUnknownRateLimitAction}
	handler := newAdminTestHandler(t, dependencies)

	response := httptest.NewRecorder()
	handler.clearRateLimit(response, authenticatedRequest(http.MethodPost, "/en/admin/ratelimits/clear", 7, "_csrf=token&action=missing.action"))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

type adminRateLimitStub struct {
	overview      []service.RateLimitActionInfo
	buckets       []service.RateLimitBucketInfo
	clearedAction string
	clearErr      error
	clearAllCalls int
}

func (s *adminRateLimitStub) Overview() []service.RateLimitActionInfo { return s.overview }

func (s *adminRateLimitStub) Buckets(string) ([]service.RateLimitBucketInfo, error) {
	return s.buckets, nil
}

func (s *adminRateLimitStub) ClearAction(_ context.Context, _ service.AdminActionContext, action string) (int, error) {
	s.clearedAction = action
	return 1, s.clearErr
}

func (s *adminRateLimitStub) ClearAll(context.Context, service.AdminActionContext) (int, error) {
	s.clearAllCalls++
	return 1, nil
}
