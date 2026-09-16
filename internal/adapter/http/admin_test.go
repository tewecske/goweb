package httpadapter

import (
	"context"
	"errors"
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
