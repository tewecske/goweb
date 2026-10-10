package httpadapter

import (
	"net/http"
	"strconv"
	"time"

	"github.com/tewecske/goweb/internal/locale"
)

// loginChallengeCookieName carries a pending Hydra login challenge across the
// sign-in form, the Google round trip, and sign-up, so whichever path signs
// the visitor in can complete the single sign-on flow.
const (
	loginChallengeCookieName = "goweb_login_challenge"
	loginChallengeLifetime   = 30 * time.Minute
	maxLoginChallengeBytes   = 4096
)

// ssoLogin answers Hydra's login redirect. It completes immediately when Hydra
// or this browser already has a session; otherwise it remembers the challenge
// and sends the visitor to the sign-in page.
func (h *authHandler) ssoLogin(writer http.ResponseWriter, request *http.Request) {
	challenge := request.URL.Query().Get("login_challenge")
	if !validLoginChallenge(challenge) {
		h.renderError(writer, request, http.StatusBadRequest)
		return
	}
	var currentUserID int64
	if h.authenticator != nil {
		if principal, err := h.authenticator.Authenticate(request.Context(), request); err == nil {
			currentUserID, _ = strconv.ParseInt(principal.ID, 10, 64)
		}
	}
	target, err := h.dependencies.SSOProvider.BeginLogin(request.Context(), challenge, currentUserID)
	if err != nil {
		h.ssoFailureRedirect(writer, request)
		return
	}
	if target != "" {
		http.Redirect(writer, request, target, http.StatusFound)
		return
	}
	http.SetCookie(writer, h.loginChallengeCookie(challenge, int(loginChallengeLifetime/time.Second)))
	h.redirectLocalized(writer, request, resolveRequestLanguage(request, ""), "/sign-in")
}

// ssoConsent answers Hydra's consent redirect without a screen: clients are
// first-party apps, and claims come from the account.
func (h *authHandler) ssoConsent(writer http.ResponseWriter, request *http.Request) {
	challenge := request.URL.Query().Get("consent_challenge")
	if !validLoginChallenge(challenge) {
		h.renderError(writer, request, http.StatusBadRequest)
		return
	}
	target, err := h.dependencies.SSOProvider.Consent(request.Context(), challenge)
	if err != nil {
		h.ssoFailureRedirect(writer, request)
		return
	}
	http.Redirect(writer, request, target, http.StatusFound)
}

// ssoLogout answers Hydra's logout redirect and ends this browser's provider
// session as well.
func (h *authHandler) ssoLogout(writer http.ResponseWriter, request *http.Request) {
	challenge := request.URL.Query().Get("logout_challenge")
	if !validLoginChallenge(challenge) {
		h.renderError(writer, request, http.StatusBadRequest)
		return
	}
	target, logoutErr := h.dependencies.SSOProvider.Logout(request.Context(), challenge)
	if h.dependencies.SessionCookie != nil {
		if sessionID, ok := h.dependencies.SessionCookie.Read(request); ok && h.dependencies.SessionAdmin != nil {
			_ = h.dependencies.SessionAdmin.SignOut(request.Context(), sessionID)
		}
		_ = h.dependencies.SessionCookie.Clear(writer, time.Now())
	}
	if logoutErr != nil {
		h.redirectLocalized(writer, request, resolveRequestLanguage(request, ""), "/sign-in")
		return
	}
	http.Redirect(writer, request, target, http.StatusFound)
}

// completeSSOLogin finishes a pending single sign-on flow after a sign-in. It
// reports whether it redirected; an expired challenge falls back to the
// caller's normal destination.
func (h *authHandler) completeSSOLogin(writer http.ResponseWriter, request *http.Request, sessionID string) bool {
	if h.dependencies.SSOProvider == nil || h.dependencies.Sessions == nil {
		return false
	}
	cookie, err := request.Cookie(loginChallengeCookieName)
	if err != nil {
		return false
	}
	http.SetCookie(writer, h.loginChallengeCookie("", -1))
	if !validLoginChallenge(cookie.Value) {
		return false
	}
	session, err := h.dependencies.Sessions.Lookup(request.Context(), sessionID)
	if err != nil {
		return false
	}
	target, err := h.dependencies.SSOProvider.CompleteLogin(request.Context(), cookie.Value, session.UserID)
	if err != nil || target == "" {
		return false
	}
	if IsHTMX(request) {
		writer.Header().Set("HX-Redirect", target)
		writer.WriteHeader(http.StatusOK)
		return true
	}
	http.Redirect(writer, request, target, http.StatusSeeOther)
	return true
}

// ssoErrorMessages maps the OAuth error codes Hydra reports to catalog
// messages. Hydra's free-text description and hint are never shown: anyone can
// craft this URL, and the debug text is meant for operators.
var ssoErrorMessages = map[string]string{
	"invalid_client":            "sso.error_page.invalid_client",
	"unauthorized_client":       "sso.error_page.invalid_client",
	"invalid_request":           "sso.error_page.invalid_request",
	"invalid_scope":             "sso.error_page.invalid_request",
	"unsupported_response_type": "sso.error_page.invalid_request",
	"access_denied":             "sso.error_page.access_denied",
	"login_required":            "sso.error_page.access_denied",
	"request_forbidden":         "sso.error_page.access_denied",
}

// ssoError is Hydra's urls.error page. It explains the failure in the
// visitor's language and offers a way back, instead of Hydra's bare fallback.
func (h *authHandler) ssoError(writer http.ResponseWriter, request *http.Request) {
	language := resolveRequestLanguage(request, "")
	messageID, known := ssoErrorMessages[request.URL.Query().Get("error")]
	if !known {
		messageID = "sso.error_page.generic"
	}
	page := PageData{
		Language:         string(language),
		Title:            h.translate(language, "sso.error_page.title"),
		Heading:          h.translate(language, "sso.error_page.heading"),
		Kind:             "state",
		Message:          h.translate(language, messageID),
		Template:         "state",
		FragmentTemplate: "state-fragment",
		SignInURL:        h.path(language, "/sign-in"),
		Navigation:       primaryNavigation(h.renderer, language, false),
		Labels:           h.formLabels(language),
	}
	// Bad Request: the flow that led here cannot continue.
	h.renderPageWithStatus(writer, request, page, http.StatusBadRequest)
}

func (h *authHandler) ssoFailureRedirect(writer http.ResponseWriter, request *http.Request) {
	path, err := locale.Path(resolveRequestLanguage(request, ""), "/sign-in")
	if err != nil {
		h.renderError(writer, request, http.StatusInternalServerError)
		return
	}
	http.Redirect(writer, request, path+"?sso=expired", http.StatusSeeOther)
}

// loginChallengeCookie uses SameSite=Lax because Hydra sends the browser here
// through a cross-site top-level redirect.
func (h *authHandler) loginChallengeCookie(value string, maxAge int) *http.Cookie {
	secure := h.dependencies.SessionCookie != nil && h.dependencies.SessionCookie.Secure()
	return &http.Cookie{
		Name:     loginChallengeCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// validLoginChallenge accepts the padded base64url alphabet Hydra uses and
// bounds the size so the value always fits a cookie.
func validLoginChallenge(value string) bool {
	if value == "" || len(value) > maxLoginChallengeBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' || c == '=') {
			return false
		}
	}
	return true
}
