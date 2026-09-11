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

type authHandler struct {
	renderer      *PageRenderer
	dependencies  Dependencies
	authenticator *SessionAuthenticator
}

func newAuthHandler(renderer *PageRenderer, dependencies Dependencies) *authHandler {
	authenticator, _ := NewSessionAuthenticator(dependencies.Users, dependencies.Sessions, dependencies.SessionCookie)
	return &authHandler{renderer: renderer, dependencies: dependencies, authenticator: authenticator}
}

func (h *authHandler) signUp(writer http.ResponseWriter, request *http.Request) {
	h.handlePasswordPage(writer, request, "sign-up")
}

func (h *authHandler) signIn(writer http.ResponseWriter, request *http.Request) {
	h.handlePasswordPage(writer, request, "sign-in")
}

func (h *authHandler) handlePasswordPage(writer http.ResponseWriter, request *http.Request, kind string) {
	language, ok := requestLanguage(request)
	if !ok {
		h.renderError(writer, request, http.StatusNotFound)
		return
	}
	if request.Method == http.MethodGet {
		if h.authenticator != nil {
			if _, err := h.authenticator.Authenticate(request.Context(), request); err == nil {
				h.redirectLocalized(writer, request, language, "/home")
				return
			}
		}
		h.renderPasswordPage(writer, request, language, kind, FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.renderer == nil || h.dependencies.SessionCookie == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	if err := request.ParseForm(); err != nil {
		h.renderPasswordPageWithStatus(writer, request, language, kind, FormData{Submitted: true}, http.StatusUnprocessableEntity, Alert{Level: "error", Message: h.translate(language, "auth.error.invalid")})
		return
	}
	form := passwordForm(request, kind)
	if kind == "sign-up" {
		if h.dependencies.SignUp == nil {
			h.renderError(writer, request, http.StatusInternalServerError)
			return
		}
		result, err := h.dependencies.SignUp.SignUp(request.Context(), service.SignUpInput{
			Email:       request.PostFormValue("email"),
			Password:    request.PostFormValue("password"),
			Username:    request.PostFormValue("username"),
			DisplayName: request.PostFormValue("display_name"),
		})
		if err != nil {
			handle, fieldErrors := h.signUpError(language, err)
			form.Errors = fieldErrors
			h.renderPasswordPageWithStatus(writer, request, language, kind, form, http.StatusUnprocessableEntity, handle)
			return
		}
		h.finishSignIn(writer, request, language, result.Session.ID, "/home")
		return
	}
	if h.dependencies.SignIn == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	result, err := h.dependencies.SignIn.SignIn(request.Context(), service.SignInInput{
		Identifier: request.PostFormValue("identifier"),
		Password:   request.PostFormValue("password"),
	}, requestOrigin(request))
	if err != nil {
		messageID := "auth.error.invalid_credentials"
		if errors.Is(err, service.ErrEmailUnconfirmed) {
			messageID = "auth.error.unconfirmed"
		}
		h.renderPasswordPageWithStatus(writer, request, language, kind, form, http.StatusUnauthorized, Alert{Level: "error", Message: h.translate(language, messageID)})
		return
	}
	h.finishSignIn(writer, request, language, result.Session.ID, "/home")
}

func (h *authHandler) home(writer http.ResponseWriter, request *http.Request) {
	language, ok := requestLanguage(request)
	if !ok || h.authenticator == nil {
		h.renderError(writer, request, http.StatusUnauthorized)
		return
	}
	principal, err := h.authenticator.Authenticate(request.Context(), request)
	if errors.Is(err, middleware.ErrUnauthenticated) {
		h.redirectLocalized(writer, request, language, "/sign-in")
		return
	}
	if err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	userID, err := strconv.ParseInt(principal.ID, 10, 64)
	if err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	user, err := h.dependencies.Users.FindUserByID(request.Context(), userID)
	if err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	settingsURL := h.path(language, "/account/settings")
	themeURL := h.path(language, "/account/theme")
	page := PageData{
		Language:         string(language),
		Title:            "GoWeb",
		Heading:          "Your home",
		Kind:             "home",
		Template:         "home",
		FragmentTemplate: "home-fragment",
		CSRFToken:        csrfToken(request),
		Account: &AccountMenu{
			Label:       accountLabel(user),
			SettingsURL: settingsURL,
			SignOutURL:  h.path(language, "/sign-out"),
			Theme:       user.Theme,
			ThemeURL:    themeURL,
		},
	}
	h.renderPage(writer, request, page)
}

func (h *authHandler) signOut(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.dependencies.SessionCookie == nil || h.dependencies.SessionAdmin == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	if sessionID, ok := h.dependencies.SessionCookie.Read(request); ok {
		if err := h.dependencies.SessionAdmin.SignOut(request.Context(), sessionID); err != nil {
			h.renderError(writer, request, http.StatusInternalServerError)
			return
		}
	}
	if err := h.dependencies.SessionCookie.Clear(writer, time.Now()); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	language, ok := requestLanguage(request)
	if !ok {
		language = locale.Default
	}
	h.redirectLocalized(writer, request, language, "/sign-in")
}

func passwordForm(request *http.Request, kind string) FormData {
	values := map[string]string{}
	if kind == "sign-up" {
		values["email"] = request.PostFormValue("email")
		values["username"] = request.PostFormValue("username")
	} else {
		values["identifier"] = request.PostFormValue("identifier")
	}
	return FormData{Submitted: true, Values: values}
}

func (h *authHandler) signUpError(language locale.Code, err error) (Alert, []FieldError) {
	messageID := "auth.error.invalid"
	field := ""
	if errors.Is(err, service.ErrDuplicateEmail) {
		messageID = "auth.error.duplicate_email"
		field = "email"
	}
	if errors.Is(err, service.ErrDuplicateUsername) {
		messageID = "auth.error.duplicate_username"
		field = "username"
	}
	if errors.Is(err, service.ErrInvalidEmail) {
		field = "email"
	}
	if errors.Is(err, service.ErrPasswordTooShort) || errors.Is(err, service.ErrPasswordTooLong) || errors.Is(err, service.ErrInvalidPassword) {
		field = "password"
	}
	var fields []FieldError
	if field != "" {
		fields = []FieldError{{Field: field, Message: h.translate(language, messageID)}}
	}
	return Alert{Level: "error", Message: h.translate(language, messageID)}, fields
}

func (h *authHandler) renderPasswordPage(writer http.ResponseWriter, request *http.Request, language locale.Code, kind string, form FormData) {
	h.renderPasswordPageWithStatus(writer, request, language, kind, form, http.StatusOK)
}

func (h *authHandler) renderPasswordPageWithStatus(writer http.ResponseWriter, request *http.Request, language locale.Code, kind string, form FormData, status int, alerts ...Alert) {
	prefix := "auth." + strings.ReplaceAll(kind, "-", "_")
	page := PageData{
		Language:         string(language),
		Title:            h.translate(language, prefix+".title"),
		Heading:          h.translate(language, prefix+".heading"),
		Description:      h.translate(language, prefix+".description"),
		Kind:             kind,
		CSRFToken:        csrfToken(request),
		Form:             form,
		FormAction:       h.path(language, "/"+kind),
		FormMethod:       http.MethodPost,
		SubmitLabel:      h.translate(language, prefix+".submit"),
		SignInURL:        h.path(language, "/sign-in"),
		SignUpURL:        h.path(language, "/sign-up"),
		Template:         "auth",
		FragmentTemplate: "auth-fragment",
		Alerts:           alerts,
	}
	if kind == "sign-in" {
		for _, provider := range h.oauthProviders(language) {
			page.OAuthProviders = append(page.OAuthProviders, provider)
		}
		if request.URL.Query().Get("oauth") == "error" {
			page.Alerts = append(page.Alerts, Alert{Level: "error", Message: h.translate(language, "oauth.error.generic")})
		}
	}
	h.renderPageWithStatus(writer, request, page, status)
}

func (h *authHandler) oauthProviders(language locale.Code) []OAuthProviderView {
	if h.dependencies.OAuthProviders == nil {
		return nil
	}
	names := h.dependencies.OAuthProviders.Names()
	providers := make([]OAuthProviderView, 0, len(names))
	for _, name := range names {
		providers = append(providers, OAuthProviderView{Name: name, URL: h.path(language, "/oauth/"+name)})
	}
	return providers
}

func (h *authHandler) finishSignIn(writer http.ResponseWriter, request *http.Request, language locale.Code, sessionID, destination string) {
	if err := h.dependencies.SessionCookie.Set(writer, sessionID, time.Now()); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	h.redirectLocalized(writer, request, language, destination)
}

func (h *authHandler) renderPage(writer http.ResponseWriter, request *http.Request, page PageData) {
	h.renderPageWithStatus(writer, request, page, http.StatusOK)
}

func (h *authHandler) renderPageWithStatus(writer http.ResponseWriter, request *http.Request, page PageData, status int) {
	if err := h.renderer.RenderRequestStatus(writer, request, page, status); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
	}
}

func (h *authHandler) renderError(writer http.ResponseWriter, request *http.Request, status int) {
	http.Error(writer, http.StatusText(status), status)
}

func (h *authHandler) redirectLocalized(writer http.ResponseWriter, request *http.Request, language locale.Code, route string) {
	path, err := locale.Path(language, route)
	if err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	http.Redirect(writer, request, path, http.StatusSeeOther)
}

func (h *authHandler) path(language locale.Code, route string) string {
	path, _ := locale.Path(language, route)
	return path
}

func (h *authHandler) translate(language locale.Code, id string) string {
	value, err := h.renderer.Translate(language, id)
	if err != nil {
		return id
	}
	return value
}

func requestLanguage(request *http.Request) (locale.Code, bool) {
	language, _, ok := locale.ParsePath(request.URL.Path)
	return language, ok
}

func csrfToken(request *http.Request) string {
	token, _ := middleware.CSRFTokenFromContext(request.Context())
	return token
}

func requestOrigin(request *http.Request) string {
	origin := strings.TrimSpace(request.RemoteAddr)
	if origin == "" {
		return "unknown"
	}
	return origin
}

func accountLabel(user service.User) string {
	if user.DisplayName != nil && strings.TrimSpace(*user.DisplayName) != "" {
		return *user.DisplayName
	}
	if user.Username != nil && strings.TrimSpace(*user.Username) != "" {
		return *user.Username
	}
	if user.Email != nil {
		return *user.Email
	}
	return "Account"
}
