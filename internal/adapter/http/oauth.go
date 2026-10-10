package httpadapter

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"time"

	"github.com/tewecske/goweb/internal/locale"
	"github.com/tewecske/goweb/internal/service"
)

// oauthStateCookieName binds a provider flow to the browser that started it,
// so a callback URL carrying someone else's state cannot complete here.
const oauthStateCookieName = "goweb_oauth_state"

func (h *authHandler) oauthStart(writer http.ResponseWriter, request *http.Request, provider string) {
	if request.Method != http.MethodGet || h.dependencies.OAuth == nil {
		writer.Header().Set("Allow", http.MethodGet)
		h.renderError(writer, request, http.StatusNotFound)
		return
	}
	url, state, err := h.dependencies.OAuth.Start(request.Context(), provider)
	if err != nil {
		h.oauthFailureRedirect(writer, request)
		return
	}
	setOAuthStateCookie(writer, h.dependencies, state)
	http.Redirect(writer, request, url, http.StatusFound)
}

func (h *authHandler) oauthCallback(writer http.ResponseWriter, request *http.Request, provider string) {
	if request.Method != http.MethodGet || h.dependencies.OAuth == nil {
		h.oauthFailureRedirect(writer, request)
		return
	}
	state := request.URL.Query().Get("state")
	bound := oauthStateBound(request, state)
	clearOAuthStateCookie(writer, h.dependencies)
	if !bound {
		h.oauthFailureRedirect(writer, request)
		return
	}
	var actorUserID int64
	if h.authenticator != nil {
		if principal, err := h.authenticator.Authenticate(request.Context(), request); err == nil {
			actorUserID, _ = strconv.ParseInt(principal.ID, 10, 64)
		}
	}
	result, err := h.dependencies.OAuth.CompleteCallback(
		request.Context(),
		actorUserID,
		provider,
		request.URL.Query().Get("code"),
		state,
	)
	if err != nil {
		h.oauthFailureRedirect(writer, request)
		return
	}
	language := recoveryLanguage(request)
	if result.Linked {
		h.redirectLocalized(writer, request, language, "/account/settings?identity=linked")
		return
	}
	if h.dependencies.SessionCookie == nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	h.finishSignIn(writer, request, language, result.SignIn.Session.ID, "/home")
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

// setOAuthStateCookie uses SameSite=Lax because the provider returns the
// browser through a cross-site top-level redirect.
func setOAuthStateCookie(writer http.ResponseWriter, dependencies Dependencies, state string) {
	http.SetCookie(writer, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int(service.DefaultOAuthStateLifetime / time.Second),
		HttpOnly: true,
		Secure:   dependencies.SessionCookie.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearOAuthStateCookie(writer http.ResponseWriter, dependencies Dependencies) {
	http.SetCookie(writer, &http.Cookie{
		Name:     oauthStateCookieName,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   dependencies.SessionCookie.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func oauthStateBound(request *http.Request, state string) bool {
	cookie, err := request.Cookie(oauthStateCookieName)
	return err == nil && state != "" && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}
