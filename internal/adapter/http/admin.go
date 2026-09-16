package httpadapter

import (
	"errors"
	"net/http"
	"strconv"

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
		},
	}
	if err := h.settings.Render(writer, request, page, status); err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
	}
}

func (h *adminHandler) labels(language locale.Code) map[string]string {
	return map[string]string{
		"admin_title":       h.t(language, "admin.title"),
		"admin_heading":     h.t(language, "admin.heading"),
		"admin_description": h.t(language, "admin.description"),
		"admin_sections":    h.t(language, "admin.sections"),
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
