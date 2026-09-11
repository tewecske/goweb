package httpadapter

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/internal/service"
)

func (h *authHandler) guestWrite(writer http.ResponseWriter, request *http.Request) {
	language := recoveryLanguage(request)
	user, authenticated := h.currentUser(request)
	if request.Method == http.MethodGet {
		h.renderGuest(writer, request, "guest-write", user, authenticated && user.IsGuest, false, "", FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if authenticated {
		h.renderGuest(writer, request, "guest-write", user, user.IsGuest, true, "", FormData{})
		return
	}
	if h.dependencies.GuestCreator == nil || h.dependencies.SessionCookie == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	_ = request.ParseForm()
	result, err := h.dependencies.GuestCreator.Create(request.Context(), requestOrigin(request), request.PostFormValue("theme"))
	if err != nil {
		h.renderGuestAlert(writer, request, "guest-write", language, http.StatusUnprocessableEntity, FormData{}, "guest.error.create")
		return
	}
	if err := h.dependencies.SessionCookie.Set(writer, result.Session.ID, time.Now()); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	h.renderGuest(writer, request, "guest-write", result.User, true, true, "", FormData{})
}

func (h *authHandler) guestTransfer(writer http.ResponseWriter, request *http.Request) {
	language := recoveryLanguage(request)
	user, authenticated := h.currentUser(request)
	isGuest := authenticated && user.IsGuest
	if request.Method == http.MethodGet {
		h.renderGuest(writer, request, "guest-transfer", user, isGuest, false, "", FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	action := request.PostFormValue("action")
	if action == "request" {
		if !isGuest || h.dependencies.GuestClaimer == nil {
			h.renderGuestAlert(writer, request, "guest-transfer", language, http.StatusUnprocessableEntity, FormData{}, "guest.error.invalid")
			return
		}
		claim, err := h.dependencies.GuestClaimer.Issue(request.Context(), user.ID)
		if err != nil {
			h.renderGuestAlert(writer, request, "guest-transfer", language, http.StatusUnprocessableEntity, FormData{}, "guest.error.invalid")
			return
		}
		h.renderGuest(writer, request, "guest-transfer", user, true, false, claim.Code, FormData{})
		return
	}
	if action == "redeem" {
		if h.dependencies.GuestRedeemer == nil || h.dependencies.SessionCookie == nil {
			h.renderError(writer, request, http.StatusInternalServerError)
			return
		}
		code := request.PostFormValue("code")
		result, err := h.dependencies.GuestRedeemer.Redeem(request.Context(), requestOrigin(request), code)
		if err != nil {
			form := FormData{Submitted: true, Errors: []FieldError{{Field: "code", Message: h.translate(language, "guest.error.invalid_code")}}}
			h.renderGuestWithStatus(writer, request, "guest-transfer", user, false, false, "", form, http.StatusUnprocessableEntity, Alert{Level: "error", Message: h.translate(language, "guest.error.invalid_code")})
			return
		}
		if err := h.dependencies.SessionCookie.Set(writer, result.Session.ID, time.Now()); err != nil {
			h.renderError(writer, request, http.StatusInternalServerError)
			return
		}
		h.renderGuest(writer, request, "guest-transfer", result.User, true, true, "", FormData{})
		return
	}
	h.renderGuestAlert(writer, request, "guest-transfer", language, http.StatusUnprocessableEntity, FormData{}, "guest.error.invalid")
}

func (h *authHandler) guestUpgrade(writer http.ResponseWriter, request *http.Request) {
	language := recoveryLanguage(request)
	user, authenticated := h.currentUser(request)
	if request.Method == http.MethodGet {
		h.renderGuest(writer, request, "guest-upgrade", user, authenticated && user.IsGuest, false, "", FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_ = request.ParseForm()
	form := FormData{Submitted: true, Values: map[string]string{"email": request.PostFormValue("email")}}
	if !authenticated || !user.IsGuest || h.dependencies.GuestUpgrader == nil {
		h.renderGuestAlert(writer, request, "guest-upgrade", language, http.StatusUnauthorized, form, "guest.error.invalid")
		return
	}
	updated, err := h.dependencies.GuestUpgrader.Upgrade(request.Context(), user.ID, service.GuestUpgradeInput{
		Email: request.PostFormValue("email"), Password: request.PostFormValue("password"),
	})
	if err != nil {
		if errors.Is(err, service.ErrDuplicateEmail) {
			form.Errors = []FieldError{{Field: "email", Message: h.translate(language, "guest.error.duplicate_email")}}
		} else if errors.Is(err, service.ErrPasswordTooShort) || errors.Is(err, service.ErrPasswordTooLong) || errors.Is(err, service.ErrInvalidPassword) {
			form.Errors = []FieldError{{Field: "password", Message: h.translate(language, "auth.error.invalid")}}
		}
		h.renderGuestWithStatus(writer, request, "guest-upgrade", user, true, false, "", form, http.StatusUnprocessableEntity, Alert{Level: "error", Message: h.translate(language, "guest.error.invalid")})
		return
	}
	h.renderGuest(writer, request, "guest-upgrade", updated, false, true, "", FormData{})
}

func (h *authHandler) currentUser(request *http.Request) (service.User, bool) {
	if h.authenticator == nil || h.dependencies.Users == nil {
		return service.User{}, false
	}
	principal, err := h.authenticator.Authenticate(request.Context(), request)
	if err != nil {
		return service.User{}, false
	}
	userID, err := strconv.ParseInt(principal.ID, 10, 64)
	if err != nil {
		return service.User{}, false
	}
	user, err := h.dependencies.Users.FindUserByID(request.Context(), userID)
	return user, err == nil && user.ID == userID
}

func (h *authHandler) renderGuest(writer http.ResponseWriter, request *http.Request, kind string, user service.User, guest, owned bool, code string, form FormData) {
	h.renderGuestWithStatus(writer, request, kind, user, guest, owned, code, form, http.StatusOK)
}

func (h *authHandler) renderGuestWithStatus(writer http.ResponseWriter, request *http.Request, kind string, user service.User, guest, owned bool, code string, form FormData, status int, alerts ...Alert) {
	language := recoveryLanguage(request)
	page := PageData{
		Language:          string(language),
		Title:             h.translate(language, "guest."+strings.TrimPrefix(kind, "guest-")+".title"),
		Heading:           h.translate(language, "guest."+strings.TrimPrefix(kind, "guest-")+".heading"),
		Kind:              kind,
		CSRFToken:         csrfToken(request),
		Form:              form,
		FormAction:        mustLocalePath(language, "/"+strings.ReplaceAll(kind, "guest-", "guest/")),
		FormMethod:        http.MethodPost,
		Template:          "guest",
		FragmentTemplate:  "guest-fragment",
		GuestBanner:       guest,
		GuestOwned:        owned,
		GuestTransferCode: code,
		SignInURL:         mustLocalePath(language, "/sign-in"),
		Alerts:            alerts,
		Labels:            h.formLabels(language),
	}
	if user.ID > 0 {
		page.Account = &AccountMenu{Label: accountLabel(user), SettingsURL: mustLocalePath(language, "/account/settings"), SignOutURL: mustLocalePath(language, "/sign-out"), Theme: user.Theme, ThemeURL: mustLocalePath(language, "/account/theme")}
	}
	if err := h.renderer.RenderRequestStatus(writer, request, page, status); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
	}
}

func (h *authHandler) renderGuestAlert(writer http.ResponseWriter, request *http.Request, kind string, language locale.Code, status int, form FormData, messageID string) {
	h.renderGuestWithStatus(writer, request, kind, service.User{}, false, false, "", form, status, Alert{Level: "error", Message: h.translate(language, messageID)})
}
