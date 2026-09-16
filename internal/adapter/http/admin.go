package httpadapter

import (
	"errors"
	"fmt"
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

// audit renders one bounded, filtered page of administrator action history.
func (h *adminHandler) audit(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.dependencies.AdminAudit == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	state := parseAuditListState(request)
	page, err := h.dependencies.AdminAudit.List(request.Context(), state.Query)
	alerts := []Alert(nil)
	status := http.StatusOK
	if err != nil {
		alerts = []Alert{{Level: "error", Message: h.t(language, "admin.error.generic")}}
		status = http.StatusInternalServerError
	}
	h.renderAudit(writer, request, language, user, state, page, alerts, status)
}

func (h *adminHandler) renderAudit(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, state auditListState, page service.AuditPage, alerts []Alert, status int) {
	base := localizedPath(language, "/admin/audit")
	view := &AdminAuditView{
		BaseURL:      base,
		ActionFilter: state.Query.Action,
		ActorFilter:  state.Query.Actor,
		TargetFilter: state.Query.Target,
		Page:         state.Query.Page,
		Size:         state.Query.Size,
		Total:        page.Total,
		Pages:        page.Pages,
	}
	view.HasPrevious = state.Query.Page > 1
	view.HasNext = page.Pages > 0 && state.Query.Page < page.Pages
	if view.HasPrevious {
		view.PreviousURL = state.WithPage(state.Query.Page - 1).URL(base)
	}
	if view.HasNext {
		view.NextURL = state.WithPage(state.Query.Page + 1).URL(base)
	}
	for _, entry := range page.Entries {
		view.Entries = append(view.Entries, adminAuditEntryView(entry))
	}
	pageData := PageData{
		Language:         string(language),
		Title:            h.t(language, "admin.audit.title"),
		Heading:          h.t(language, "admin.audit.heading"),
		Description:      h.t(language, "admin.audit.description"),
		Kind:             "admin",
		CSRFToken:        csrfToken(request),
		Template:         "admin",
		FragmentTemplate: "admin-fragment",
		Alerts:           alerts,
		Labels:           h.labels(language),
		Account:          settingsAccountMenu(language, user),
		Admin: &AdminView{
			IsAdmin: true,
			Page:    "audit",
			Audit:   view,
		},
	}
	if err := h.settings.Render(writer, request, pageData, status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func adminAuditEntryView(entry service.AuditEntry) AdminAuditEntryView {
	view := AdminAuditEntryView{
		Time:   formatAdminTime(entry.OccurredAt),
		Action: entry.Action,
	}
	if entry.ActorEmail != nil {
		view.Actor = *entry.ActorEmail
	}
	if entry.TargetType != nil && entry.TargetID != nil {
		view.Target = *entry.TargetType + " " + *entry.TargetID
	} else if entry.TargetID != nil {
		view.Target = *entry.TargetID
	}
	if entry.Detail != nil {
		view.Detail = *entry.Detail
	}
	if entry.IP != nil {
		view.Origin = *entry.IP
	}
	return view
}

// detail renders one account's safe diagnostics.
func (h *adminHandler) detail(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	h.renderDetail(writer, request, language, user, accountID, nil, http.StatusOK)
}

// revokeSessions ends every active session for an account as an audited action.
func (h *adminHandler) revokeSessions(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	if h.dependencies.AdminSessionRevoker == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	err = h.dependencies.AdminSessionRevoker.RevokeSessions(request.Context(), adminActionContext(user, request), accountID)
	switch {
	case err == nil:
		h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "success", Message: h.t(language, "admin.sessions.revoked")}}, http.StatusOK)
	case errors.Is(err, service.ErrRecordNotFound):
		h.renderState(writer, request, language, PageStateNotFound)
	default:
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

// confirmEmailAccount marks an address verified after support verification.
func (h *adminHandler) confirmEmailAccount(writer http.ResponseWriter, request *http.Request) {
	h.adminConfirmationAction(writer, request, "admin.confirmation.confirmed", func(actor service.AdminActionContext, accountID int64) error {
		return h.dependencies.AdminConfirmation.ConfirmEmail(request.Context(), actor, accountID)
	})
}

// sendConfirmation issues a fresh confirmation link for an account.
func (h *adminHandler) sendConfirmation(writer http.ResponseWriter, request *http.Request) {
	h.adminConfirmationAction(writer, request, "admin.confirmation.sent", func(actor service.AdminActionContext, accountID int64) error {
		return h.dependencies.AdminConfirmation.SendConfirmation(request.Context(), actor, accountID)
	})
}

func (h *adminHandler) adminConfirmationAction(writer http.ResponseWriter, request *http.Request, successMessage string, action func(service.AdminActionContext, int64) error) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	if h.dependencies.AdminConfirmation == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	err = action(adminActionContext(user, request), accountID)
	switch {
	case err == nil:
		h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "success", Message: h.t(language, successMessage)}}, http.StatusOK)
	case errors.Is(err, service.ErrRecordNotFound):
		h.renderState(writer, request, language, PageStateNotFound)
	case errors.Is(err, service.ErrInvalidConfirmationAccount):
		h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "error", Message: h.t(language, "admin.account.error.no_email")}}, http.StatusUnprocessableEntity)
	default:
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

// removeIdentity removes a linked provider while enforcing the last-credential
// rule on the server.
func (h *adminHandler) removeIdentity(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	identityID, err := pathIdentityID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	if h.dependencies.AdminIdentity == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	err = h.dependencies.AdminIdentity.RemoveIdentity(request.Context(), adminActionContext(user, request), accountID, identityID)
	switch {
	case err == nil:
		h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "success", Message: h.t(language, "admin.identity.removed")}}, http.StatusOK)
	case errors.Is(err, service.ErrRecordNotFound):
		h.renderState(writer, request, language, PageStateNotFound)
	case errors.Is(err, service.ErrOAuthLastSignInMethod):
		h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "error", Message: h.t(language, "admin.error.last_identity")}}, http.StatusUnprocessableEntity)
	case errors.Is(err, service.ErrOAuthIdentityNotFound):
		h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "error", Message: h.t(language, "admin.error.identity_not_found")}}, http.StatusNotFound)
	default:
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

// clearLockout removes every identifier and recent-origin budget for an
// account as an audited action.
func (h *adminHandler) clearLockout(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	if h.dependencies.AdminLockout == nil || h.dependencies.AdminAccountEditor == nil {
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
	if err := h.dependencies.AdminLockout.Clear(request.Context(), adminActionContext(user, request), account); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	h.renderDetail(writer, request, language, user, accountID, []Alert{{Level: "success", Message: h.t(language, "admin.lockout.cleared")}}, http.StatusOK)
}

func pathIdentityID(request *http.Request) (int64, error) {
	value := strings.TrimSpace(request.PathValue("identityID"))
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return 0, service.ErrOAuthIdentityNotFound
	}
	return id, nil
}

// renderDetail re-reads authoritative diagnostics and renders them.
func (h *adminHandler) renderDetail(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, accountID int64, alerts []Alert, status int) {
	if h.dependencies.AdminUserDetailer == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	detail, err := h.dependencies.AdminUserDetailer.Detail(request.Context(), accountID)
	if err != nil {
		if errors.Is(err, service.ErrRecordNotFound) {
			h.renderState(writer, request, language, PageStateNotFound)
			return
		}
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	var lockout *service.LockoutStatus
	if h.dependencies.AdminLockout != nil {
		if status, err := h.dependencies.AdminLockout.Status(request.Context(), detail.User); err == nil {
			lockout = &status
		}
	}
	pageData := PageData{
		Language:         string(language),
		Title:            h.t(language, "admin.account.detail_title"),
		Heading:          adminAccountLabel(detail.User),
		Description:      h.t(language, "admin.account.detail_description"),
		Kind:             "admin",
		CSRFToken:        csrfToken(request),
		Template:         "admin",
		FragmentTemplate: "admin-fragment",
		Alerts:           alerts,
		Labels:           h.labels(language),
		Account:          settingsAccountMenu(language, user),
		Admin: &AdminView{
			IsAdmin: true,
			Page:    "detail",
			Detail:  h.detailView(language, detail, lockout),
		},
	}
	if err := h.settings.Render(writer, request, pageData, status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func (h *adminHandler) detailView(language locale.Code, detail service.AdminUserDetail, lockout *service.LockoutStatus) *AdminDetailView {
	account := detail.User
	view := &AdminDetailView{
		UserID:    account.ID,
		Label:     adminAccountLabel(account),
		IsAdmin:   account.IsAdmin,
		IsGuest:   account.IsGuest,
		Confirmed: detail.Confirmed,
		Locale:    account.Locale,
		Theme:     account.Theme,
		CreatedAt: formatAdminTime(account.CreatedAt),
		Version:   account.Version,
		ListURL:   localizedPath(language, "/admin/users"),
		EditURL:   localizedPath(language, "/admin/users/"+strconv.FormatInt(account.ID, 10)+"/edit"),
	}
	view.SessionsRevokeURL = localizedPath(language, "/admin/users/"+strconv.FormatInt(account.ID, 10)+"/sessions/revoke")
	view.ConfirmationLinkActive = detail.ConfirmationLinkActive
	view.ConfirmationLinkExpiry = formatAdminTime(detail.ConfirmationLinkExpiry)
	base := "/admin/users/" + strconv.FormatInt(account.ID, 10)
	view.ConfirmURL = localizedPath(language, base+"/confirm-email")
	view.SendConfirmationURL = localizedPath(language, base+"/send-confirmation")
	if account.Email != nil {
		view.Email = *account.Email
	}
	if account.Username != nil {
		view.Username = *account.Username
	}
	if account.DisplayName != nil {
		view.DisplayName = *account.DisplayName
	}
	for _, session := range detail.Sessions {
		view.Sessions = append(view.Sessions, AdminSessionView{
			CreatedAt: formatAdminTime(session.CreatedAt),
			ExpiresAt: formatAdminTime(session.ExpiresAt),
		})
	}
	view.SessionCount = len(view.Sessions)
	for _, attempt := range detail.LoginAttempts {
		attemptView := AdminLoginAttemptView{
			CreatedAt:    formatAdminTime(attempt.CreatedAt),
			Outcome:      attempt.Outcome,
			OutcomeLabel: h.t(language, "admin.attempt.outcome."+attempt.Outcome),
		}
		if attempt.IP != nil {
			attemptView.Origin = *attempt.IP
		}
		view.LoginAttempts = append(view.LoginAttempts, attemptView)
	}
	for _, identity := range detail.Identities {
		view.Identities = append(view.Identities, IdentityView{
			ID:        identity.ID,
			Provider:  identity.Provider,
			Label:     identityLabelFor(identity),
			Removable: true,
			RemoveURL: localizedPath(language, "/admin/users/"+strconv.FormatInt(account.ID, 10)+"/identities/"+strconv.FormatInt(identity.ID, 10)+"/remove"),
		})
	}
	if lockout != nil {
		lockoutView := &AdminLockoutView{
			Locked:          lockout.Locked,
			IdentifierKey:   lockout.IdentifierKey,
			IdentifierCount: lockout.IdentifierCount,
			IdentifierLimit: lockout.IdentifierLimit,
			IdentifierRetry: formatAdminDuration(lockout.IdentifierRetryAfter),
			ClearURL:        localizedPath(language, "/admin/users/"+strconv.FormatInt(account.ID, 10)+"/lockout/clear"),
		}
		for _, origin := range lockout.Origins {
			lockoutView.Origins = append(lockoutView.Origins, AdminLockoutOriginView{
				Key:   origin.Key,
				Count: origin.Count,
				Limit: origin.Limit,
				Retry: formatAdminDuration(origin.RetryAfter),
			})
		}
		view.Lockout = lockoutView
	}
	return view
}

func formatAdminDuration(value time.Duration) string {
	if value <= 0 {
		return ""
	}
	return value.Round(time.Second).String()
}

func identityLabelFor(identity service.OAuthIdentity) string {
	if strings.TrimSpace(identity.Email) != "" {
		return identity.Email
	}
	return identity.Provider
}

func formatAdminTime(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04")
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
		DeleteURL:   localizedPath(language, "/admin/users/"+strconv.FormatInt(accountID, 10)+"/delete"),
		IsSelf:      accountID == user.ID,
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

// deleteAccount removes an account after an explicit server-validated
// confirmation. Self-deletion is refused on the server.
func (h *adminHandler) deleteAccount(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	accountID, err := pathID(request)
	if err != nil {
		h.renderState(writer, request, language, PageStateNotFound)
		return
	}
	_ = request.ParseForm()
	if !isChecked(request.PostFormValue("confirm")) {
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: FormData{}, mode: adminModeList,
			alerts: []Alert{{Level: "error", Message: h.t(language, "admin.account.error.confirm_required")}},
			status: http.StatusUnprocessableEntity,
		})
		return
	}
	version, versionErr := strconv.ParseInt(strings.TrimSpace(request.PostFormValue("version")), 10, 64)
	if h.dependencies.AdminAccountEditor == nil || versionErr != nil || version < 0 {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	err = h.dependencies.AdminAccountEditor.Delete(request.Context(), adminActionContext(user, request), accountID, version)
	switch {
	case err == nil:
		h.redirectLocalized(writer, request, language, "/admin/users")
	case errors.Is(err, service.ErrAdminSelfAction):
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: FormData{}, mode: adminModeList,
			alerts: []Alert{{Level: "error", Message: h.t(language, "admin.account.error.self_action")}},
			status: http.StatusUnprocessableEntity,
		})
	case errors.Is(err, service.ErrRecordNotFound):
		h.renderState(writer, request, language, PageStateNotFound)
	case errors.Is(err, service.ErrOptimisticLockConflict):
		h.renderUsers(writer, request, language, user, adminUsersRequest{
			state: parseAdminListState(request), form: FormData{}, mode: adminModeList,
			alerts: []Alert{{Level: "error", Message: h.t(language, "admin.account.error.conflict")}},
			status: http.StatusConflict,
		})
	default:
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
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
	case errors.Is(err, service.ErrAdminSelfAction):
		return "admin.account.error.self_action"
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
				{ID: "audit", Label: h.t(language, "admin.nav.audit"), URL: localizedPath(language, "/admin/audit")},
				{ID: "system", Label: h.t(language, "admin.nav.system"), URL: localizedPath(language, "/admin/system")},
			},
		},
	}
	if err := h.settings.Render(writer, request, page, status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func (h *adminHandler) labels(language locale.Code) map[string]string {
	return map[string]string{
		"admin_title":                        h.t(language, "admin.title"),
		"admin_heading":                      h.t(language, "admin.heading"),
		"admin_description":                  h.t(language, "admin.description"),
		"admin_sections":                     h.t(language, "admin.sections"),
		"admin_nav_accounts":                 h.t(language, "admin.nav.accounts"),
		"admin_search":                       h.t(language, "admin.accounts.search"),
		"admin_search_placeholder":           h.t(language, "admin.accounts.search_placeholder"),
		"admin_filter_admin":                 h.t(language, "admin.accounts.filter_admin"),
		"admin_filter_guest":                 h.t(language, "admin.accounts.filter_guest"),
		"admin_filter_confirmed":             h.t(language, "admin.accounts.filter_confirmed"),
		"admin_filter_all":                   h.t(language, "admin.accounts.filter.all"),
		"admin_filter_yes":                   h.t(language, "admin.accounts.filter.yes"),
		"admin_filter_no":                    h.t(language, "admin.accounts.filter.no"),
		"admin_column_account":               h.t(language, "admin.accounts.column.account"),
		"admin_column_email":                 h.t(language, "admin.accounts.column.email"),
		"admin_column_role":                  h.t(language, "admin.accounts.column.role"),
		"admin_column_status":                h.t(language, "admin.accounts.column.status"),
		"admin_column_created":               h.t(language, "admin.accounts.column.created"),
		"admin_role_admin":                   h.t(language, "admin.accounts.role.admin"),
		"admin_role_user":                    h.t(language, "admin.accounts.role.user"),
		"admin_status_confirmed":             h.t(language, "admin.accounts.status.confirmed"),
		"admin_status_unconfirmed":           h.t(language, "admin.accounts.status.unconfirmed"),
		"admin_status_guest":                 h.t(language, "admin.accounts.status.guest"),
		"admin_prev":                         h.t(language, "admin.accounts.previous"),
		"admin_next":                         h.t(language, "admin.accounts.next"),
		"admin_empty":                        h.t(language, "admin.accounts.empty"),
		"admin_view":                         h.t(language, "admin.accounts.view"),
		"admin_edit":                         h.t(language, "admin.accounts.edit"),
		"admin_create":                       h.t(language, "admin.accounts.create"),
		"admin_create_heading":               h.t(language, "admin.account.create_heading"),
		"admin_account_email":                h.t(language, "admin.account.email"),
		"admin_account_password":             h.t(language, "admin.account.password"),
		"admin_account_password_help":        h.t(language, "admin.account.password_help"),
		"admin_account_is_admin":             h.t(language, "admin.account.is_admin"),
		"admin_account_submit":               h.t(language, "admin.account.submit"),
		"admin_account_cancel":               h.t(language, "admin.account.cancel"),
		"admin_account_delete":               h.t(language, "admin.account.delete"),
		"admin_account_delete_confirm":       h.t(language, "admin.account.delete_confirm"),
		"admin_account_confirm_delete":       h.t(language, "admin.account.confirm_delete"),
		"admin_detail_confirmation":          h.t(language, "admin.detail.confirmation"),
		"admin_detail_sessions":              h.t(language, "admin.detail.sessions"),
		"admin_detail_attempts":              h.t(language, "admin.detail.attempts"),
		"admin_detail_providers":             h.t(language, "admin.detail.providers"),
		"admin_detail_username":              h.t(language, "admin.detail.username"),
		"admin_detail_display_name":          h.t(language, "admin.detail.display_name"),
		"admin_detail_role":                  h.t(language, "admin.detail.role"),
		"admin_detail_locale":                h.t(language, "admin.detail.locale"),
		"admin_detail_theme":                 h.t(language, "admin.detail.theme"),
		"admin_detail_created":               h.t(language, "admin.detail.created"),
		"admin_detail_version":               h.t(language, "admin.detail.version"),
		"admin_detail_confirmed":             h.t(language, "admin.detail.confirmed"),
		"admin_detail_unconfirmed":           h.t(language, "admin.detail.unconfirmed"),
		"admin_detail_edit":                  h.t(language, "admin.detail.edit"),
		"admin_detail_back":                  h.t(language, "admin.detail.back"),
		"admin_sessions_created":             h.t(language, "admin.sessions.created"),
		"admin_sessions_expires":             h.t(language, "admin.sessions.expires"),
		"admin_sessions_empty":               h.t(language, "admin.sessions.empty"),
		"admin_sessions_revoke":              h.t(language, "admin.sessions.revoke"),
		"admin_sessions_revoke_confirm":      h.t(language, "admin.sessions.revoke_confirm"),
		"admin_confirmation_confirm":         h.t(language, "admin.confirmation.confirm"),
		"admin_confirmation_send":            h.t(language, "admin.confirmation.send"),
		"admin_confirmation_confirm_confirm": h.t(language, "admin.confirmation.confirm_confirm"),
		"admin_detail_link_active":           h.t(language, "admin.detail.link_active"),
		"admin_detail_link_none":             h.t(language, "admin.detail.link_none"),
		"admin_identity_remove":              h.t(language, "admin.identity.remove"),
		"admin_lockout_heading":              h.t(language, "admin.lockout.heading"),
		"admin_lockout_locked":               h.t(language, "admin.lockout.locked"),
		"admin_lockout_clear_state":          h.t(language, "admin.lockout.clear_state"),
		"admin_lockout_attempts":             h.t(language, "admin.lockout.attempts"),
		"admin_lockout_limit":                h.t(language, "admin.lockout.limit"),
		"admin_lockout_retry":                h.t(language, "admin.lockout.retry"),
		"admin_lockout_origins":              h.t(language, "admin.lockout.origins"),
		"admin_lockout_origin":               h.t(language, "admin.lockout.origin"),
		"admin_lockout_origin_attempts":      h.t(language, "admin.lockout.origin_attempts"),
		"admin_lockout_clear":                h.t(language, "admin.lockout.clear"),
		"admin_lockout_clear_confirm":        h.t(language, "admin.lockout.clear_confirm"),
		"admin_lockout_none":                 h.t(language, "admin.lockout.none"),
		"admin_audit_action":                 h.t(language, "admin.audit.filter_action"),
		"admin_audit_actor":                  h.t(language, "admin.audit.filter_actor"),
		"admin_audit_target":                 h.t(language, "admin.audit.filter_target"),
		"admin_audit_apply":                  h.t(language, "admin.audit.apply"),
		"admin_audit_clear":                  h.t(language, "admin.audit.clear"),
		"admin_audit_time":                   h.t(language, "admin.audit.column.time"),
		"admin_audit_actor_column":           h.t(language, "admin.audit.column.actor"),
		"admin_audit_action_column":          h.t(language, "admin.audit.column.action"),
		"admin_audit_target_column":          h.t(language, "admin.audit.column.target"),
		"admin_audit_detail_column":          h.t(language, "admin.audit.column.detail"),
		"admin_audit_origin_column":          h.t(language, "admin.audit.column.origin"),
		"admin_audit_empty":                  h.t(language, "admin.audit.empty"),
		"admin_audit_heading":                h.t(language, "admin.audit.heading"),
		"admin_attempt_time":                 h.t(language, "admin.attempt.time"),
		"admin_attempt_outcome":              h.t(language, "admin.attempt.outcome"),
		"admin_attempt_origin":               h.t(language, "admin.attempt.origin"),
		"admin_attempts_empty":               h.t(language, "admin.attempts.empty"),
		"admin_providers_provider":           h.t(language, "admin.providers.provider"),
		"admin_providers_account":            h.t(language, "admin.providers.account"),
		"admin_providers_empty":              h.t(language, "admin.providers.empty"),
		"admin_system_jobs_heading":          h.t(language, "admin.system.jobs.heading"),
		"admin_system_job":                   h.t(language, "admin.system.jobs.job"),
		"admin_system_job_runs":              h.t(language, "admin.system.jobs.runs"),
		"admin_system_job_failures":          h.t(language, "admin.system.jobs.failures"),
		"admin_system_job_last_run":          h.t(language, "admin.system.jobs.last_run"),
		"admin_system_job_duration":          h.t(language, "admin.system.jobs.duration"),
		"admin_system_job_removed":           h.t(language, "admin.system.jobs.removed"),
		"admin_system_job_error":             h.t(language, "admin.system.jobs.error"),
		"admin_system_job_empty":             h.t(language, "admin.system.jobs.empty"),
		"admin_system_run":                   h.t(language, "admin.system.maintenance.run"),
		"admin_system_run_confirm":           h.t(language, "admin.system.maintenance.run_confirm"),
		"admin_system_config_heading":        h.t(language, "admin.system.config.heading"),
		"admin_system_config_environment":    h.t(language, "admin.system.config.environment"),
		"admin_system_config_public_address": h.t(language, "admin.system.config.public_address"),
		"admin_system_config_public_url":     h.t(language, "admin.system.config.public_url"),
		"admin_system_config_email":          h.t(language, "admin.system.config.email_confirmation"),
		"admin_system_config_secure_cookies": h.t(language, "admin.system.config.secure_cookies"),
		"admin_system_config_providers":      h.t(language, "admin.system.config.providers"),
		"admin_system_config_mail":           h.t(language, "admin.system.config.mail"),
		"admin_system_config_mail_relay":     h.t(language, "admin.system.config.mail_relay"),
		"admin_system_config_session":        h.t(language, "admin.system.config.session_lifetime"),
		"admin_system_config_guest":          h.t(language, "admin.system.config.guest_retention"),
		"admin_system_config_login":          h.t(language, "admin.system.config.login_retention"),
		"admin_system_config_usage":          h.t(language, "admin.system.config.usage_retention"),
		"admin_system_config_interval":       h.t(language, "admin.system.config.maintenance_interval"),
		"admin_system_config_rate_limit":     h.t(language, "admin.system.config.rate_limit"),
		"admin_system_config_trusted_proxy":  h.t(language, "admin.system.config.trusted_proxy"),
		"admin_system_config_not_configured": h.t(language, "admin.system.config.not_configured"),
		"admin_system_yes":                   h.t(language, "admin.system.yes"),
		"admin_system_no":                    h.t(language, "admin.system.no"),
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

// system renders the administrator system health page.
func (h *adminHandler) system(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	h.renderSystem(writer, request, language, user, nil, http.StatusOK)
}

// runMaintenance executes every scheduled cleanup job immediately as a separate,
// confirmed, audited administrator action.
func (h *adminHandler) runMaintenance(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authorize(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.dependencies.AdminMaintenance == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	runs, err := h.dependencies.AdminMaintenance.RunOnce(request.Context())
	if err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	h.recordMaintenanceAudit(request, user, runs)
	alerts := []Alert{{Level: "success", Message: h.t(language, "admin.system.maintenance.ran")}}
	if maintenanceFailed(runs) {
		alerts = []Alert{{Level: "warning", Message: h.t(language, "admin.system.maintenance.partial")}}
	}
	h.renderSystem(writer, request, language, user, alerts, http.StatusOK)
}

func (h *adminHandler) renderSystem(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, alerts []Alert, status int) {
	base := localizedPath(language, "/admin/system")
	view := &AdminSystemView{RunURL: base + "/maintenance/run"}
	if h.dependencies.AdminMaintenance != nil {
		for _, job := range h.dependencies.AdminMaintenance.Status() {
			view.Jobs = append(view.Jobs, adminMaintenanceJobView(h, language, job))
		}
	}
	if h.dependencies.AdminSystemConfig != nil {
		configuration := h.dependencies.AdminSystemConfig.SystemConfiguration()
		view.Configuration = adminSystemConfigView(configuration)
	}
	pageData := PageData{
		Language:         string(language),
		Title:            h.t(language, "admin.system.title"),
		Heading:          h.t(language, "admin.system.heading"),
		Description:      h.t(language, "admin.system.description"),
		Kind:             "admin",
		CSRFToken:        csrfToken(request),
		Template:         "admin",
		FragmentTemplate: "admin-fragment",
		Alerts:           alerts,
		Labels:           h.labels(language),
		Account:          settingsAccountMenu(language, user),
		Admin: &AdminView{
			IsAdmin: true,
			Page:    "system",
			System:  view,
		},
	}
	if err := h.settings.Render(writer, request, pageData, status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func adminMaintenanceJobView(h *adminHandler, language locale.Code, status service.MaintenanceStatus) AdminMaintenanceJobView {
	view := AdminMaintenanceJobView{
		Job:          status.Job,
		Runs:         status.Runs,
		Failures:     status.Failures,
		LastDeleted:  status.LastDeleted,
		LastError:    status.LastError,
		Failed:       status.LastError != "",
		LastDuration: status.LastDuration.String(),
	}
	if status.LastFinishedAt > 0 {
		view.LastRun = formatAdminTime(status.LastFinishedAt)
	}
	view.Label = h.jobLabel(language, status.Job)
	return view
}

func adminSystemConfigView(configuration service.SystemConfiguration) *AdminSystemConfigView {
	return &AdminSystemConfigView{
		Environment:               configuration.Environment,
		PublicAddress:             configuration.PublicAddress,
		PublicURL:                 configuration.PublicURL,
		EmailConfirmationRequired: configuration.EmailConfirmationRequired,
		SecureSessionCookies:      configuration.SecureSessionCookies,
		Providers:                 strings.Join(configuration.Providers, ", "),
		MailConfigured:            configuration.MailConfigured,
		MailRelay:                 configuration.MailRelay,
		SessionLifetime:           configuration.SessionLifetime.String(),
		GuestRetention:            configuration.GuestRetention.String(),
		LoginAttemptRetention:     configuration.LoginAttemptRetention.String(),
		UsageRetention:            configuration.UsageRetention.String(),
		MaintenanceInterval:       configuration.MaintenanceInterval.String(),
		AuthRateLimit:             fmt.Sprintf("%d / %s", configuration.AuthRateLimit, configuration.AuthRateLimitWindow),
		TrustedProxy:              configuration.TrustedProxy,
	}
}

func (h *adminHandler) jobLabel(language locale.Code, job string) string {
	switch job {
	case service.MaintenanceJobGuestCleanup:
		return h.t(language, "admin.system.job.guest_cleanup")
	case service.MaintenanceJobTokenRetention:
		return h.t(language, "admin.system.job.token_retention")
	case service.MaintenanceJobLoginAttemptRetention:
		return h.t(language, "admin.system.job.login_attempt_retention")
	case service.MaintenanceJobUsageRetention:
		return h.t(language, "admin.system.job.usage_retention")
	default:
		return job
	}
}

func (h *adminHandler) recordMaintenanceAudit(request *http.Request, user service.User, runs []service.MaintenanceRun) {
	if h.dependencies.AdminAuditRecorder == nil {
		return
	}
	_ = h.dependencies.AdminAuditRecorder.Record(request.Context(), service.AuditRecord{
		ActorUserID: user.ID,
		ActorEmail:  adminActorEmail(user),
		Action:      service.AuditActionMaintenanceRun,
		TargetType:  "maintenance",
		Detail:      maintenanceAuditDetail(runs),
		IP:          requestOrigin(request),
	})
}

func maintenanceAuditDetail(runs []service.MaintenanceRun) string {
	removed := 0
	failures := 0
	for _, run := range runs {
		removed += run.Deleted
		if run.Failed() {
			failures++
		}
	}
	return "jobs=" + strconv.Itoa(len(runs)) + " removed=" + strconv.Itoa(removed) + " failures=" + strconv.Itoa(failures)
}

func maintenanceFailed(runs []service.MaintenanceRun) bool {
	for _, run := range runs {
		if run.Failed() {
			return true
		}
	}
	return false
}

func adminActorEmail(user service.User) string {
	if user.Email != nil {
		return *user.Email
	}
	return ""
}
