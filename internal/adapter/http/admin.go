package httpadapter

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/internal/service"
)

// adminHandler owns every administrator page and mutation. Each route first
// passes through authorize, which repeats the administrator check on the
// server for full-page, fragment, and mutation requests alike.
type adminHandler struct {
	renderer      *PageRenderer
	settings      *SettingsRenderer
	dependencies  Dependencies
	authenticator *SessionAuthenticator
}

func newAdminHandler(renderer *PageRenderer, dependencies Dependencies) *adminHandler {
	authenticator, _ := NewSessionAuthenticator(dependencies.Users, dependencies.Sessions, dependencies.SessionCookie)
	return &adminHandler{
		renderer:      renderer,
		settings:      NewSettingsRenderer(renderer, dependencies),
		dependencies:  dependencies,
		authenticator: authenticator,
	}
}

// account list render modes.
const (
	adminModeList   = "list"
	adminModeCreate = "create"
	adminModeEdit   = "edit"
)

// index renders the administrator landing page for administrators.
func (h *adminHandler) index(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	h.renderAdmin(writer, request, language, user, nil, http.StatusOK)
}

// list renders one bounded, URL-driven page of accounts.
func (h *adminHandler) list(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.dependencies.AdminAccounts == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	state := parseAdminListState(request)
	page, err := h.dependencies.AdminAccounts.List(request.Context(), state.Query)
	if err != nil {
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: state, form: FormData{}, mode: adminModeList, status: http.StatusInternalServerError,
			alerts: []Alert{{Level: "error", Message: h.t(language, "admin.error.generic")}},
		})
		return
	}
	h.renderUsers(writer, request, language, user, adminUsersRequest{state: state, page: page, form: FormData{}, mode: adminModeList, status: http.StatusOK})
}

// createAccount renders and handles administrator account creation.
func (h *adminHandler) createAccount(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request),
			form:  FormData{Submitted: true, Values: map[string]string{}},
			mode:  adminModeCreate,
			accountForm: &AdminAccountFormView{
				Heading:     h.t(language, "admin.account.create_heading"),
				ActionURL:   localizedPath(language, "/admin/users/new"),
				CancelURL:   localizedPath(language, "/admin/users"),
				SubmitLabel: h.t(language, "admin.account.submit"),
			},
			status: http.StatusOK,
		})
	case http.MethodPost:
		h.submitCreateAccount(writer, request, language, user)
	default:
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *adminHandler) submitCreateAccount(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User) {
	_ = request.ParseForm()
	form := accountFormData(request)
	formView := &AdminAccountFormView{
		Heading:     h.t(language, "admin.account.create_heading"),
		ActionURL:   localizedPath(language, "/admin/users/new"),
		CancelURL:   localizedPath(language, "/admin/users"),
		Email:       request.PostFormValue("email"),
		IsAdmin:     isChecked(request.PostFormValue("is_admin")),
		SubmitLabel: h.t(language, "admin.account.submit"),
	}
	if h.dependencies.AdminAccountCreator == nil {
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: form, mode: adminModeCreate, accountForm: formView,
			alerts: []Alert{{Level: "error", Message: h.t(language, "admin.error.generic")}}, status: http.StatusInternalServerError,
		})
		return
	}
	_, err := h.dependencies.AdminAccountCreator.Create(request.Context(), adminActionContext(user, request), service.AdminAccountInput{
		Email:    request.PostFormValue("email"),
		Password: request.PostFormValue("password"),
		IsAdmin:  formView.IsAdmin,
	})
	if err != nil {
		form.Errors = adminAccountFieldErrors(language, err, h.t)
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: form, mode: adminModeCreate, accountForm: formView,
			alerts: []Alert{{Level: "error", Message: h.t(language, adminAccountErrorMessage(err))}},
			status: http.StatusUnprocessableEntity,
		})
		return
	}
	h.redirectLocalized(writer, request, language, "/admin/users")
}

// editAccount renders and handles atomic administrator account editing.
func (h *adminHandler) editAccount(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	switch request.Method {
	case http.MethodGet:
		h.renderEditAccount(writer, request, language, user, accountID, nil)
	case http.MethodPost:
		h.submitEditAccount(writer, request, language, user, accountID)
	default:
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *adminHandler) renderEditAccount(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, accountID int64, alerts []Alert) {
	if h.dependencies.AdminAccountEditor == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	account, err := h.dependencies.AdminAccountEditor.Find(request.Context(), accountID)
	if err != nil {
		if errors.Is(err, service.ErrRecordNotFound) {
			h.renderState(writer, request, language, PageStateNotFound)
			return
		}
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	email := ""
	if account.Email != nil {
		email = *account.Email
	}
	formView := &AdminAccountFormView{
		Heading:     h.t(language, "admin.account.edit_heading"),
		ActionURL:   localizedPath(language, "/admin/users/"+strconv.FormatInt(accountID, 10)+"/edit"),
		CancelURL:   localizedPath(language, "/admin/users"),
		Email:       email,
		IsAdmin:     account.IsAdmin,
		Version:     account.Version,
		SubmitLabel: h.t(language, "admin.account.save"),
	}
	h.renderUsers(writer, request, language, user, adminUsersRequest{
		state: parseAdminListState(request),
		form:  FormData{Submitted: true, Values: map[string]string{"email": email, "is_admin": boolValue(account.IsAdmin)}},
		mode:  adminModeEdit, accountForm: formView, alerts: alerts, status: http.StatusOK,
	})
}

func (h *adminHandler) submitEditAccount(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, accountID int64) {
	_ = request.ParseForm()
	form := accountFormData(request)
	version, versionErr := strconv.ParseInt(strings.TrimSpace(request.PostFormValue("version")), 10, 64)
	formView := &AdminAccountFormView{
		Heading:     h.t(language, "admin.account.edit_heading"),
		ActionURL:   localizedPath(language, "/admin/users/"+strconv.FormatInt(accountID, 10)+"/edit"),
		CancelURL:   localizedPath(language, "/admin/users"),
		Email:       request.PostFormValue("email"),
		IsAdmin:     isChecked(request.PostFormValue("is_admin")),
		Version:     version,
		SubmitLabel: h.t(language, "admin.account.save"),
	}
	if h.dependencies.AdminAccountEditor == nil || versionErr != nil || version < 0 {
		form.Errors = adminAccountFieldErrors(language, service.ErrInvalidEmail, h.t)
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: form, mode: adminModeEdit, accountForm: formView,
			alerts: []Alert{{Level: "error", Message: h.t(language, "admin.account.error.generic")}}, status: http.StatusUnprocessableEntity,
		})
		return
	}
	_, err := h.dependencies.AdminAccountEditor.Update(request.Context(), adminActionContext(user, request), accountID, service.AdminAccountUpdateInput{
		Email:    request.PostFormValue("email"),
		Password: request.PostFormValue("password"),
		IsAdmin:  formView.IsAdmin,
		Version:  version,
	})
	if err != nil {
		form.Errors = adminAccountFieldErrors(language, err, h.t)
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, service.ErrRecordNotFound):
			status = http.StatusNotFound
		case errors.Is(err, service.ErrOptimisticLockConflict), errors.Is(err, service.ErrDuplicateEmail):
			status = http.StatusConflict
		}
		if status == http.StatusNotFound {
			h.renderState(writer, request, language, PageStateNotFound)
			return
		}
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: form, mode: adminModeEdit, accountForm: formView,
			alerts: []Alert{{Level: "error", Message: h.t(language, adminAccountErrorMessage(err))}}, status: status,
		})
		return
	}
	h.redirectLocalized(writer, request, language, "/admin/users/"+strconv.FormatInt(accountID, 10))
}

// adminUsersRequest bundles the inputs for one account-list or account-form
// render so handlers stay readable.
type adminUsersRequest struct {
	state       adminListState
	page        service.AdminUserPage
	form        FormData
	alerts      []Alert
	status      int
	mode        string
	accountForm *AdminAccountFormView
}

// renderUsers writes the account list or account form as a document or fragment.
func (h *adminHandler) renderUsers(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, render adminUsersRequest) {
	base := localizedPath(language, "/admin/users")
	view := &AdminListView{
		BaseURL:         base,
		SearchURL:       base,
		SearchValue:     render.state.Query.Search,
		AdminFilter:     render.state.Query.Admin,
		GuestFilter:     render.state.Query.Guest,
		ConfirmedFilter: render.state.Query.Confirmed,
		Sort:            render.state.Query.Sort,
		Direction:       render.state.Query.Direction,
		Page:            render.state.Query.Page,
		Size:            render.state.Query.Size,
		Total:           render.page.Total,
		Pages:           render.page.Pages,
		Mode:            render.mode,
		CreateURL:       localizedPath(language, "/admin/users/new"),
		CreateLabel:     h.t(language, "admin.accounts.create"),
		Form:            render.accountForm,
		SortURLs: map[string]string{
			service.AdminSortCreatedAt:   render.state.WithSort(service.AdminSortCreatedAt).URL(base),
			service.AdminSortID:          render.state.WithSort(service.AdminSortID).URL(base),
			service.AdminSortEmail:       render.state.WithSort(service.AdminSortEmail).URL(base),
			service.AdminSortUsername:    render.state.WithSort(service.AdminSortUsername).URL(base),
			service.AdminSortDisplayName: render.state.WithSort(service.AdminSortDisplayName).URL(base),
		},
		FilterURLs: map[string]string{
			"admin_all":     render.state.WithFilter(adminParamAdmin, service.AdminFilterAll).URL(base),
			"admin_yes":     render.state.WithFilter(adminParamAdmin, service.AdminFilterYes).URL(base),
			"admin_no":      render.state.WithFilter(adminParamAdmin, service.AdminFilterNo).URL(base),
			"guest_all":     render.state.WithFilter(adminParamGuest, service.AdminFilterAll).URL(base),
			"guest_yes":     render.state.WithFilter(adminParamGuest, service.AdminFilterYes).URL(base),
			"guest_no":      render.state.WithFilter(adminParamGuest, service.AdminFilterNo).URL(base),
			"confirmed_all": render.state.WithFilter(adminParamConfirmed, service.AdminFilterAll).URL(base),
			"confirmed_yes": render.state.WithFilter(adminParamConfirmed, service.AdminFilterYes).URL(base),
			"confirmed_no":  render.state.WithFilter(adminParamConfirmed, service.AdminFilterNo).URL(base),
		},
	}
	view.HasPrevious = render.state.Query.Page > 1
	view.HasNext = render.page.Pages > 0 && render.state.Query.Page < render.page.Pages
	if view.HasPrevious {
		view.PreviousURL = render.state.WithPage(render.state.Query.Page - 1).URL(base)
	}
	if view.HasNext {
		view.NextURL = render.state.WithPage(render.state.Query.Page + 1).URL(base)
	}
	for _, account := range render.page.Users {
		view.Rows = append(view.Rows, adminUserRowView(language, account))
	}

	pageData := PageData{
		Language:         string(language),
		Title:            h.t(language, "admin.accounts.title"),
		Heading:          h.t(language, "admin.accounts.heading"),
		Description:      h.t(language, "admin.accounts.description"),
		Kind:             "admin",
		CSRFToken:        csrfToken(request),
		Form:             render.form,
		Template:         "admin",
		FragmentTemplate: "admin-fragment",
		Alerts:           render.alerts,
		Labels:           h.labels(language),
		Account:          settingsAccountMenu(language, user),
		Admin: &AdminView{
			IsAdmin: true,
			Page:    "users",
			List:    view,
		},
	}
	if err := h.settings.Render(writer, request, pageData, render.status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

// redirectLocalized redirects a normal request and asks an HTMX request to
// perform a full-page navigation.
func (h *adminHandler) redirectLocalized(writer http.ResponseWriter, request *http.Request, language locale.Code, route string) {
	if IsHTMX(request) {
		writer.Header().Set("HX-Redirect", localizedPath(language, route))
		writer.WriteHeader(http.StatusOK)
		return
	}
	redirectLocalized(writer, request, language, route)
}

func adminActionContext(user service.User, request *http.Request) service.AdminActionContext {
	return service.AdminActionContext{ActorID: user.ID, Origin: requestOrigin(request)}
}

func accountFormData(request *http.Request) FormData {
	return FormData{Submitted: true, Values: map[string]string{
		"email":    request.PostFormValue("email"),
		"is_admin": request.PostFormValue("is_admin"),
	}}
}

func isChecked(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
	}
}

func boolValue(value bool) string {
	if value {
		return "true"
	}
	return ""
}

func adminAccountErrorMessage(err error) string {
	switch {
	case errors.Is(err, service.ErrInvalidEmail):
		return "admin.account.error.invalid_email"
	case errors.Is(err, service.ErrDuplicateEmail):
		return "admin.account.error.duplicate_email"
	case errors.Is(err, service.ErrPasswordTooShort), errors.Is(err, service.ErrPasswordTooLong), errors.Is(err, service.ErrInvalidPassword):
		return "admin.account.error.weak_password"
	case errors.Is(err, service.ErrOptimisticLockConflict):
		return "admin.account.error.conflict"
	case errors.Is(err, service.ErrRecordNotFound):
		return "admin.account.error.not_found"
	default:
		return "admin.account.error.generic"
	}
}

func adminAccountFieldErrors(language locale.Code, err error, translate func(locale.Code, string) string) []FieldError {
	switch {
	case errors.Is(err, service.ErrInvalidEmail):
		return []FieldError{{Field: "email", Message: translate(language, "admin.account.error.invalid_email")}}
	case errors.Is(err, service.ErrDuplicateEmail):
		return []FieldError{{Field: "email", Message: translate(language, "admin.account.error.duplicate_email")}}
	case errors.Is(err, service.ErrPasswordTooShort), errors.Is(err, service.ErrPasswordTooLong), errors.Is(err, service.ErrInvalidPassword):
		return []FieldError{{Field: "password", Message: translate(language, "admin.account.error.weak_password")}}
	default:
		return nil
	}
}

func adminUserRowView(language locale.Code, account service.User) AdminUserRowView {
	row := AdminUserRowView{
		ID:        account.ID,
		Label:     adminAccountLabel(account),
		IsAdmin:   account.IsAdmin,
		IsGuest:   account.IsGuest,
		Confirmed: account.EmailVerifiedAt != nil,
	}
	if account.Email != nil {
		row.Email = *account.Email
	}
	if account.CreatedAt > 0 {
		row.CreatedAt = time.Unix(account.CreatedAt, 0).UTC().Format("2006-01-02 15:04")
	}
	id := strconv.FormatInt(account.ID, 10)
	row.DetailURL = localizedPath(language, "/admin/users/"+id)
	row.EditURL = localizedPath(language, "/admin/users/"+id+"/edit")
	return row
}

func adminAccountLabel(account service.User) string {
	if account.DisplayName != nil && *account.DisplayName != "" {
		return *account.DisplayName
	}
	if account.Username != nil && *account.Username != "" {
		return *account.Username
	}
	if account.Email != nil && *account.Email != "" {
		return *account.Email
	}
	return "Account #" + strconv.FormatInt(account.ID, 10)
}

// authorize authenticates the acting session and requires administrator
// permission. Unauthenticated visitors are redirected to sign-in; authenticated
// non-administrators receive an access-denied page or fragment.
func (h *adminHandler) authorize(writer http.ResponseWriter, request *http.Request) (service.User, locale.Code, bool) {
	language := recoveryLanguage(request)
	if h.authenticator == nil || h.dependencies.Users == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return service.User{}, language, false
	}
	principal, err := h.authenticator.Authenticate(request.Context(), request)
	if errors.Is(err, middleware.ErrUnauthenticated) {
		if IsHTMX(request) {
			writer.Header().Set("HX-Redirect", localizedPath(language, "/sign-in"))
			writer.WriteHeader(http.StatusOK)
			return service.User{}, language, false
		}
		redirectLocalized(writer, request, language, "/sign-in")
		return service.User{}, language, false
	}
	if err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return service.User{}, language, false
	}
	userID, err := strconv.ParseInt(principal.ID, 10, 64)
	if err != nil || userID <= 0 {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return service.User{}, language, false
	}
	user, err := h.dependencies.Users.FindUserByID(request.Context(), userID)
	if err != nil || user.ID != userID {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return service.User{}, language, false
	}
	if !user.IsAdmin {
		h.renderState(writer, request, language, PageStateAccessDenied)
		return service.User{}, language, false
	}
	return user, language, true
}

// renderState renders a localized state page or fragment and never fails the
// response silently.
func (h *adminHandler) renderState(writer http.ResponseWriter, request *http.Request, language locale.Code, state PageState) {
	if h.renderer == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	if err := h.renderer.RenderState(writer, request, language, state); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func (h *adminHandler) renderAdmin(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, alerts []Alert, status int) {
	page := PageData{
		Language:         string(language),
		Title:            h.t(language, "admin.title"),
		Heading:          h.t(language, "admin.heading"),
		Description:      h.t(language, "admin.description"),
		Kind:             "admin",
		CSRFToken:        csrfToken(request),
		Template:         "admin",
		FragmentTemplate: "admin-fragment",
		Alerts:           alerts,
		Labels:           h.labels(language),
		Account:          settingsAccountMenu(language, user),
		Admin: &AdminView{
			IsAdmin: true,
			Page:    "overview",
			Sections: []AdminSectionView{
				{ID: "accounts", Label: h.t(language, "admin.nav.accounts"), URL: localizedPath(language, "/admin/users")},
			},
		},
	}
	if err := h.settings.Render(writer, request, page, status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func (h *adminHandler) labels(language locale.Code) map[string]string {
	return map[string]string{
		"admin_title":                 h.t(language, "admin.title"),
		"admin_heading":               h.t(language, "admin.heading"),
		"admin_description":           h.t(language, "admin.description"),
		"admin_sections":              h.t(language, "admin.sections"),
		"admin_nav_accounts":          h.t(language, "admin.nav.accounts"),
		"admin_search":                h.t(language, "admin.accounts.search"),
		"admin_search_placeholder":    h.t(language, "admin.accounts.search_placeholder"),
		"admin_filter_admin":          h.t(language, "admin.accounts.filter_admin"),
		"admin_filter_guest":          h.t(language, "admin.accounts.filter_guest"),
		"admin_filter_confirmed":      h.t(language, "admin.accounts.filter_confirmed"),
		"admin_filter_all":            h.t(language, "admin.accounts.filter.all"),
		"admin_filter_yes":            h.t(language, "admin.accounts.filter.yes"),
		"admin_filter_no":             h.t(language, "admin.accounts.filter.no"),
		"admin_column_account":        h.t(language, "admin.accounts.column.account"),
		"admin_column_email":          h.t(language, "admin.accounts.column.email"),
		"admin_column_role":           h.t(language, "admin.accounts.column.role"),
		"admin_column_status":         h.t(language, "admin.accounts.column.status"),
		"admin_column_created":        h.t(language, "admin.accounts.column.created"),
		"admin_role_admin":            h.t(language, "admin.accounts.role.admin"),
		"admin_role_user":             h.t(language, "admin.accounts.role.user"),
		"admin_status_confirmed":      h.t(language, "admin.accounts.status.confirmed"),
		"admin_status_unconfirmed":    h.t(language, "admin.accounts.status.unconfirmed"),
		"admin_status_guest":          h.t(language, "admin.accounts.status.guest"),
		"admin_prev":                  h.t(language, "admin.accounts.previous"),
		"admin_next":                  h.t(language, "admin.accounts.next"),
		"admin_empty":                 h.t(language, "admin.accounts.empty"),
		"admin_view":                  h.t(language, "admin.accounts.view"),
		"admin_edit":                  h.t(language, "admin.accounts.edit"),
		"admin_create":                h.t(language, "admin.accounts.create"),
		"admin_create_heading":        h.t(language, "admin.account.create_heading"),
		"admin_account_email":         h.t(language, "admin.account.email"),
		"admin_account_password":      h.t(language, "admin.account.password"),
		"admin_account_password_help": h.t(language, "admin.account.password_help"),
		"admin_account_is_admin":      h.t(language, "admin.account.is_admin"),
		"admin_account_submit":        h.t(language, "admin.account.submit"),
		"admin_account_cancel":        h.t(language, "admin.account.cancel"),
	}
}

func (h *adminHandler) t(language locale.Code, id string) string {
	if h.renderer == nil {
		return id
	}
	value, err := h.renderer.Translate(language, id)
	if err != nil {
		return id
	}
	return value
}
