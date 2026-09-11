package httpadapter

import (
	"errors"
	"net/http"
	"time"

	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/internal/service"
)

func (h *authHandler) resendConfirmation(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		h.renderRecovery(writer, request, "resend-confirmation", FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	language := recoveryLanguage(request)
	if h.dependencies.ConfirmationResender == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	_ = request.ParseForm()
	form := FormData{Submitted: true, Values: map[string]string{"email": request.PostFormValue("email")}}
	if err := h.dependencies.ConfirmationResender.Resend(request.Context(), request.PostFormValue("email")); err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrRateLimited) {
			status = http.StatusTooManyRequests
		}
		h.renderRecoveryWithStatus(writer, request, "resend-confirmation", form, status, Alert{Level: "error", Message: h.translate(language, "auth.error.invalid")})
		return
	}
	h.renderRecoveryWithStatus(writer, request, "resend-confirmation", form, http.StatusOK, Alert{Level: "info", Message: h.translate(language, "recovery.request.accepted")})
}

func (h *authHandler) forgotPassword(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		h.renderRecovery(writer, request, "forgot-password", FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	language := recoveryLanguage(request)
	if h.dependencies.PasswordResetter == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	_ = request.ParseForm()
	form := FormData{Submitted: true, Values: map[string]string{"email": request.PostFormValue("email")}}
	if err := h.dependencies.PasswordResetter.Request(request.Context(), request.PostFormValue("email")); err != nil {
		status := http.StatusUnprocessableEntity
		if errors.Is(err, service.ErrRateLimited) {
			status = http.StatusTooManyRequests
		}
		h.renderRecoveryWithStatus(writer, request, "forgot-password", form, status, Alert{Level: "error", Message: h.translate(language, "auth.error.invalid")})
		return
	}
	h.renderRecoveryWithStatus(writer, request, "forgot-password", form, http.StatusOK, Alert{Level: "info", Message: h.translate(language, "recovery.request.accepted")})
}

func (h *authHandler) confirmEmail(writer http.ResponseWriter, request *http.Request) {
	language := recoveryLanguage(request)
	alert := Alert{Level: "error", Message: h.translate(language, "recovery.confirm.failure")}
	if request.Method == http.MethodGet && h.dependencies.ConfirmationConsumer != nil {
		if err := h.dependencies.ConfirmationConsumer.Confirm(request.Context(), request.URL.Query().Get("token")); err == nil {
			alert = Alert{Level: "success", Message: h.translate(language, "recovery.confirm.success")}
		}
	}
	h.renderRecoveryWithStatus(writer, request, "confirm-email", FormData{}, http.StatusOK, alert)
}

func (h *authHandler) resetPassword(writer http.ResponseWriter, request *http.Request) {
	language := recoveryLanguage(request)
	if request.Method == http.MethodGet {
		h.renderRecovery(writer, request, "reset-password", FormData{})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.dependencies.PasswordResetterUse == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	_ = request.ParseForm()
	form := FormData{Submitted: true}
	if err := h.dependencies.PasswordResetterUse.Redeem(request.Context(), request.URL.Query().Get("token"), request.PostFormValue("password")); err != nil {
		fieldErrors := []FieldError{}
		if errors.Is(err, service.ErrPasswordTooShort) || errors.Is(err, service.ErrPasswordTooLong) || errors.Is(err, service.ErrInvalidPassword) {
			fieldErrors = append(fieldErrors, FieldError{Field: "password", Message: h.translate(language, "auth.error.invalid")})
		}
		form.Errors = fieldErrors
		messageID := "recovery.reset.failure"
		if len(fieldErrors) > 0 {
			messageID = "auth.error.invalid"
		}
		h.renderRecoveryWithStatus(writer, request, "reset-password", form, http.StatusUnprocessableEntity, Alert{Level: "error", Message: h.translate(language, messageID)})
		return
	}
	if h.dependencies.SessionCookie != nil {
		_ = h.dependencies.SessionCookie.Clear(writer, time.Now())
	}
	h.renderRecoveryWithStatus(writer, request, "reset-password", FormData{}, http.StatusOK, Alert{Level: "success", Message: h.translate(language, "recovery.reset.success")})
}

func (h *authHandler) renderRecovery(writer http.ResponseWriter, request *http.Request, kind string, form FormData) {
	h.renderRecoveryWithStatus(writer, request, kind, form, http.StatusOK)
}

func (h *authHandler) renderRecoveryWithStatus(writer http.ResponseWriter, request *http.Request, kind string, form FormData, status int, alerts ...Alert) {
	language := recoveryLanguage(request)
	prefix := "recovery."
	switch kind {
	case "resend-confirmation":
		prefix += "resend"
	case "forgot-password":
		prefix += "forgot"
	case "confirm-email":
		prefix += "confirm"
	case "reset-password":
		prefix += "reset"
	default:
		h.renderError(writer, request, http.StatusNotFound)
		return
	}
	page := PageData{
		Language:         string(language),
		Title:            h.translate(language, prefix+".title"),
		Heading:          h.translate(language, prefix+".heading"),
		Description:      h.translate(language, prefix+".description"),
		Kind:             kind,
		CSRFToken:        csrfToken(request),
		Form:             form,
		FormAction:       "",
		FormMethod:       http.MethodPost,
		SubmitLabel:      h.translate(language, prefix+".submit"),
		SignInURL:        mustLocalePath(language, "/sign-in"),
		Template:         "recovery",
		FragmentTemplate: "recovery-fragment",
		Alerts:           alerts,
	}
	if kind == "resend-confirmation" {
		page.FormAction = mustLocalePath(language, "/resend-confirmation")
	}
	if kind == "forgot-password" {
		page.FormAction = mustLocalePath(language, "/forgot-password")
	}
	if err := h.renderer.RenderRequestStatus(writer, request, page, status); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
	}
}

func recoveryLanguage(request *http.Request) locale.Code {
	if language, _, ok := locale.ParsePath(request.URL.Path); ok {
		return language
	}
	return resolveRequestLanguage(request, "")
}
