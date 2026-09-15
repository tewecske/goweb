package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/internal/service"
)

// ProfileSettingsUpdater persists optional account profile fields.
type ProfileSettingsUpdater interface {
	Update(context.Context, int64, service.ProfileSettingsInput) (service.User, error)
}

// PasswordSettingsUpdater persists an account password.
type PasswordSettingsUpdater interface {
	Update(context.Context, int64, service.PasswordSettingsInput) (service.User, error)
}

// LocaleSettingsUpdater persists an account language preference.
type LocaleSettingsUpdater interface {
	Update(context.Context, int64, string) (service.User, error)
}

// IdentityLister lists external identities linked to an account.
type IdentityLister interface {
	ListOAuthIdentities(context.Context, int64) ([]service.OAuthIdentity, error)
}

// IdentityUnlinker removes an external identity unless it is the last sign-in method.
type IdentityUnlinker interface {
	Unlink(context.Context, int64, int64) error
}

// IdentityLinkStarter begins an external-identity attachment flow.
type IdentityLinkStarter interface {
	StartLink(context.Context, int64, string) (string, error)
}

// AccountThemeUpdater persists an account visual theme.
type AccountThemeUpdater interface {
	UpdateTheme(context.Context, int64, string) error
}

// SettingsRenderer renders localized settings pages and fragments.
type SettingsRenderer struct {
	renderer     *PageRenderer
	dependencies Dependencies
}

// NewSettingsRenderer constructs settings rendering with its page dependencies.
func NewSettingsRenderer(renderer *PageRenderer, dependencies Dependencies) *SettingsRenderer {
	return &SettingsRenderer{renderer: renderer, dependencies: dependencies}
}

// Render writes one settings page or fragment with the given status.
func (r *SettingsRenderer) Translate(language locale.Code, id string) (string, error) {
	if r == nil || r.renderer == nil {
		return "", ErrInvalidPage
	}
	return r.renderer.Translate(language, id)
}

func (r *SettingsRenderer) Render(writer http.ResponseWriter, request *http.Request, page PageData, status int) error {
	if r == nil || r.renderer == nil {
		return ErrInvalidPage
	}
	return r.renderer.RenderRequestStatus(writer, request, page, status)
}

type settingsHandler struct {
	auth          *authHandler
	settings      *SettingsRenderer
	dependencies  Dependencies
	authenticator *SessionAuthenticator
}

func newSettingsHandler(renderer *PageRenderer, dependencies Dependencies) *settingsHandler {
	authenticator, _ := NewSessionAuthenticator(dependencies.Users, dependencies.Sessions, dependencies.SessionCookie)
	return &settingsHandler{auth: newAuthHandler(renderer, dependencies), settings: NewSettingsRenderer(renderer, dependencies), dependencies: dependencies, authenticator: authenticator}
}

func (h *settingsHandler) page(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user, language, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	h.renderSettings(writer, request, language, user, FormData{}, nil, http.StatusOK)
}

func (h *settingsHandler) updateProfile(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	form := FormData{Submitted: true, Values: map[string]string{
		"username":     request.PostFormValue("username"),
		"display_name": request.PostFormValue("display_name"),
	}}
	if h.dependencies.ProfileSettings == nil {
		h.renderSettings(writer, request, language, user, form, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")}}, http.StatusInternalServerError)
		return
	}
	updated, err := h.dependencies.ProfileSettings.Update(request.Context(), user.ID, service.ProfileSettingsInput{
		Username:    request.PostFormValue("username"),
		DisplayName: request.PostFormValue("display_name"),
	})
	if err != nil {
		form.Errors = h.profileFieldErrors(language, err)
		message := "settings.error.generic"
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, service.ErrUsernameUnavailable):
			message = "settings.error.username_unavailable"
		case errors.Is(err, service.ErrInvalidUsername):
			message = "settings.error.invalid_username"
		case errors.Is(err, service.ErrInvalidDisplayName):
			message = "settings.error.invalid_display_name"
		case errors.Is(err, service.ErrOptimisticLockConflict):
			message = "settings.error.conflict"
		case errors.Is(err, service.ErrRecordNotFound):
			message = "settings.error.not_found"
			status = http.StatusNotFound
		}
		h.renderSettings(writer, request, language, user, form, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, message)}}, status)
		return
	}
	h.renderSettings(writer, request, language, updated, FormData{}, []Alert{{Level: "success", Message: settingsTranslate(h.settings, language, "settings.success.profile")}}, http.StatusOK)
}

func (h *settingsHandler) updatePassword(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	if h.dependencies.PasswordSettings == nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")}}, http.StatusInternalServerError)
		return
	}
	_, err := h.dependencies.PasswordSettings.Update(request.Context(), user.ID, service.PasswordSettingsInput{
		CurrentPassword: request.PostFormValue("current_password"),
		NewPassword:     request.PostFormValue("new_password"),
	})
	if err != nil {
		form := FormData{Submitted: true}
		message := "settings.error.generic"
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, service.ErrCurrentPasswordRequired):
			form.Errors = []FieldError{{Field: "current_password", Message: settingsTranslate(h.settings, language, "settings.error.current_required")}}
			message = "settings.error.current_required"
		case errors.Is(err, service.ErrCurrentPasswordMismatch):
			form.Errors = []FieldError{{Field: "current_password", Message: settingsTranslate(h.settings, language, "settings.error.current_mismatch")}}
			message = "settings.error.current_mismatch"
		case errors.Is(err, service.ErrPasswordTooShort) || errors.Is(err, service.ErrPasswordTooLong) || errors.Is(err, service.ErrInvalidPassword):
			form.Errors = []FieldError{{Field: "new_password", Message: settingsTranslate(h.settings, language, "settings.error.weak_password")}}
			message = "settings.error.weak_password"
		case errors.Is(err, service.ErrOptimisticLockConflict):
			message = "settings.error.conflict"
		case errors.Is(err, service.ErrRecordNotFound):
			message = "settings.error.not_found"
			status = http.StatusNotFound
		}
		h.renderSettings(writer, request, language, user, form, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, message)}}, status)
		return
	}
	fresh, err := h.dependencies.Users.FindUserByID(request.Context(), user.ID)
	if err != nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "success", Message: settingsTranslate(h.settings, language, "settings.success.password")}}, http.StatusOK)
		return
	}
	h.renderSettings(writer, request, language, fresh, FormData{}, []Alert{{Level: "success", Message: settingsTranslate(h.settings, language, "settings.success.password")}}, http.StatusOK)
}

func (h *settingsHandler) updateLocale(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	if h.dependencies.LocaleSettings == nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")}}, http.StatusInternalServerError)
		return
	}
	selected := strings.TrimSpace(request.PostFormValue("locale"))
	if _, err := h.dependencies.LocaleSettings.Update(request.Context(), user.ID, selected); err != nil {
		form := FormData{Submitted: true}
		message := "settings.error.generic"
		status := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, service.ErrInvalidLocale):
			form.Errors = []FieldError{{Field: "locale", Message: settingsTranslate(h.settings, language, "settings.error.invalid_locale")}}
			message = "settings.error.invalid_locale"
		case errors.Is(err, service.ErrOptimisticLockConflict):
			message = "settings.error.conflict"
		case errors.Is(err, service.ErrRecordNotFound):
			message = "settings.error.not_found"
			status = http.StatusNotFound
		}
		h.renderSettings(writer, request, language, user, form, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, message)}}, status)
		return
	}
	destination, err := locale.Path(locale.Code(selected), "/account/settings")
	if err != nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")}}, http.StatusInternalServerError)
		return
	}
	h.redirectWithStatus(writer, request, destination, http.StatusSeeOther)
}

func (h *settingsHandler) unlinkIdentity(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	if h.dependencies.IdentityUnlinker == nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")}}, http.StatusInternalServerError)
		return
	}
	identityID, err := strconv.ParseInt(strings.TrimSpace(request.PostFormValue("identity_id")), 10, 64)
	if err != nil || identityID <= 0 {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.identity_not_found")}}, http.StatusNotFound)
		return
	}
	err = h.dependencies.IdentityUnlinker.Unlink(request.Context(), user.ID, identityID)
	if err == nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "success", Message: settingsTranslate(h.settings, language, "settings.success.identity_removed")}}, http.StatusOK)
		return
	}
	status := http.StatusUnprocessableEntity
	message := "settings.error.generic"
	if errors.Is(err, service.ErrOAuthIdentityNotFound) {
		status, message = http.StatusNotFound, "settings.error.identity_not_found"
	} else if errors.Is(err, service.ErrOAuthLastSignInMethod) {
		message = "settings.error.last_identity"
	}
	h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, message)}}, status)
}

func (h *settingsHandler) linkIdentity(writer http.ResponseWriter, request *http.Request) {
	user, language, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	provider := strings.ToLower(strings.TrimSpace(request.PostFormValue("provider")))
	if h.dependencies.IdentityLink == nil || provider == "" {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")}}, http.StatusUnprocessableEntity)
		return
	}
	url, err := h.dependencies.IdentityLink.StartLink(request.Context(), user.ID, provider)
	if err != nil {
		h.renderSettings(writer, request, language, user, FormData{}, []Alert{{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.identity_link")}}, http.StatusUnprocessableEntity)
		return
	}
	http.Redirect(writer, request, url, http.StatusFound)
}

func (h *settingsHandler) updateTheme(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.dependencies.ThemeUpdater == nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	user, _, ok := h.authenticatedUser(writer, request)
	if !ok {
		return
	}
	_ = request.ParseForm()
	if err := h.dependencies.ThemeUpdater.UpdateTheme(request.Context(), user.ID, request.PostFormValue("theme")); err != nil {
		if errors.Is(err, service.ErrInvalidTheme) {
			renderSimpleError(writer, request, http.StatusUnprocessableEntity)
			return
		}
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	writer.Header().Set("HX-Trigger", "theme-updated")
	writer.WriteHeader(http.StatusNoContent)
}

func (h *settingsHandler) authenticatedUser(writer http.ResponseWriter, request *http.Request) (service.User, locale.Code, bool) {
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
	if err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return service.User{}, language, false
	}
	user, err := h.dependencies.Users.FindUserByID(request.Context(), userID)
	if err != nil || user.ID != userID {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return service.User{}, language, false
	}
	return user, language, true
}

func (h *settingsHandler) renderSettings(writer http.ResponseWriter, request *http.Request, language locale.Code, user service.User, form FormData, alerts []Alert, status int) {
	identities, providers, identityErr := h.identityViews(request, user.ID)
	if identityErr != nil {
		alerts = append(alerts, Alert{Level: "error", Message: settingsTranslate(h.settings, language, "settings.error.generic")})
	}
	page := PageData{
		Language:         string(language),
		Title:            settingsTranslate(h.settings, language, "settings.title"),
		Heading:          settingsTranslate(h.settings, language, "settings.heading"),
		Kind:             "settings",
		CSRFToken:        csrfToken(request),
		Form:             form,
		Template:         "settings",
		FragmentTemplate: "settings-fragment",
		Alerts:           alerts,
		Labels:           h.auth.formLabels(language),
		Account:          settingsAccountMenu(language, user),
		Settings: &SettingsView{
			Username:       optionalValueString(user.Username),
			DisplayName:    optionalValueString(user.DisplayName),
			HasPassword:    user.PasswordHash != nil,
			Locale:         user.Locale,
			Theme:          user.Theme,
			Languages:      languageOptions(language),
			Identities:     identities,
			Providers:      providers,
			FormActionBase: localizedPath(language, "/account/settings"),
			ProfileAction:  localizedPath(language, "/account/settings/profile"),
			PasswordAction: localizedPath(language, "/account/settings/password"),
			LocaleAction:   localizedPath(language, "/account/settings/locale"),
			IdentityAction: localizedPath(language, "/account/settings/identity"),
			LinkAction:     localizedPath(language, "/account/settings/identity/link"),
			ThemeURL:       localizedPath(language, "/account/theme"),
			UnlinkLabel:    settingsTranslate(h.settings, language, "settings.identity.remove"),
			LinkLabel:      settingsTranslate(h.settings, language, "settings.identity.add"),
		},
	}
	h.settings.Render(writer, request, page, status)
}

func (h *settingsHandler) identityViews(request *http.Request, userID int64) ([]IdentityView, []OAuthProviderView, error) {
	var identities []IdentityView
	if h.dependencies.IdentityLister != nil {
		linked, err := h.dependencies.IdentityLister.ListOAuthIdentities(request.Context(), userID)
		if err != nil {
			return nil, nil, err
		}
		for _, identity := range linked {
			identities = append(identities, IdentityView{
				ID:        identity.ID,
				Provider:  identity.Provider,
				Label:     identityLabel(identity),
				Removable: true,
			})
		}
	}
	var providers []OAuthProviderView
	if h.dependencies.OAuthProviders != nil {
		for _, name := range h.dependencies.OAuthProviders.Names() {
			providers = append(providers, OAuthProviderView{Name: name, URL: localizedPath(recoveryLanguage(request), "/oauth/"+name)})
		}
	}
	return identities, providers, nil
}

func (h *settingsHandler) profileFieldErrors(language locale.Code, err error) []FieldError {
	switch {
	case errors.Is(err, service.ErrUsernameUnavailable):
		return []FieldError{{Field: "username", Message: settingsTranslate(h.settings, language, "settings.error.username_unavailable")}}
	case errors.Is(err, service.ErrInvalidUsername):
		return []FieldError{{Field: "username", Message: settingsTranslate(h.settings, language, "settings.error.invalid_username")}}
	case errors.Is(err, service.ErrInvalidDisplayName):
		return []FieldError{{Field: "display_name", Message: settingsTranslate(h.settings, language, "settings.error.invalid_display_name")}}
	default:
		return nil
	}
}

func (h *settingsHandler) redirectWithStatus(writer http.ResponseWriter, request *http.Request, destination string, status int) {
	if IsHTMX(request) {
		writer.Header().Set("HX-Redirect", destination)
		writer.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(writer, request, destination, status)
}

func settingsAccountMenu(language locale.Code, user service.User) *AccountMenu {
	return &AccountMenu{
		Label:       accountLabel(user),
		SettingsURL: mustLocalePath(language, "/account/settings"),
		SignOutURL:  mustLocalePath(language, "/sign-out"),
		Theme:       user.Theme,
		ThemeURL:    mustLocalePath(language, "/account/theme"),
	}
}

func languageOptions(current locale.Code) []LanguageOption {
	options := make([]LanguageOption, 0, len(locale.Codes()))
	for _, code := range locale.Codes() {
		options = append(options, LanguageOption{
			Code:    string(code),
			Label:   languageLabel(code),
			Current: code == current,
		})
	}
	return options
}

func languageLabel(code locale.Code) string {
	switch code {
	case locale.Hungarian:
		return "Magyar"
	case locale.English:
		return "English"
	default:
		return string(code)
	}
}

func identityLabel(identity service.OAuthIdentity) string {
	if strings.TrimSpace(identity.Email) != "" {
		return identity.Email
	}
	return identity.Provider
}

func optionalValueString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func settingsTranslate(renderer *SettingsRenderer, language locale.Code, id string) string {
	if renderer == nil {
		return id
	}
	value, err := renderer.Translate(language, id)
	if err != nil {
		return id
	}
	return value
}

func localizedPath(language locale.Code, route string) string {
	path, _ := locale.Path(language, route)
	return path
}

func renderSimpleError(writer http.ResponseWriter, _ *http.Request, status int) {
	http.Error(writer, http.StatusText(status), status)
}

func redirectLocalized(writer http.ResponseWriter, request *http.Request, language locale.Code, route string) {
	path, err := locale.Path(language, route)
	if err != nil {
		renderSimpleError(writer, request, http.StatusInternalServerError)
		return
	}
	http.Redirect(writer, request, path, http.StatusSeeOther)
}
