package httpadapter

import (
	"net/http"
	"time"

	"github.com/tewecske/goweb/internal/locale"
)

func (h *authHandler) oauthStart(writer http.ResponseWriter, request *http.Request, provider string) {
	if request.Method != http.MethodGet || h.dependencies.OAuth == nil {
		writer.Header().Set("Allow", http.MethodGet)
		h.renderError(writer, request, http.StatusNotFound)
		return
	}
	url, err := h.dependencies.OAuth.Start(request.Context(), provider)
	if err != nil {
		h.oauthFailureRedirect(writer, request)
		return
	}
	http.Redirect(writer, request, url, http.StatusFound)
}

func (h *authHandler) oauthCallback(writer http.ResponseWriter, request *http.Request, provider string) {
	if request.Method != http.MethodGet || h.dependencies.OAuth == nil {
		h.oauthFailureRedirect(writer, request)
		return
	}
	result, err := h.dependencies.OAuth.Callback(
		request.Context(),
		provider,
		request.URL.Query().Get("code"),
		request.URL.Query().Get("state"),
	)
	if err != nil {
		h.oauthFailureRedirect(writer, request)
		return
	}
	language := recoveryLanguage(request)
	if h.dependencies.SessionCookie == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	if err := h.dependencies.SessionCookie.Set(writer, result.Session.ID, time.Now()); err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	h.redirectLocalized(writer, request, language, "/home")
}

func (h *authHandler) oauthFailureRedirect(writer http.ResponseWriter, request *http.Request) {
	language := recoveryLanguage(request)
	path, err := locale.Path(language, "/sign-in")
	if err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	if IsHTMX(request) {
		writer.Header().Set("HX-Redirect", path+"?oauth=error")
		writer.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(writer, request, path+"?oauth=error", http.StatusSeeOther)
}
