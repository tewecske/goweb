// Package hydra implements the Ory Hydra admin API client used by the single
// sign-on provider deployment.
package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tewecske/goweb/internal/service"
)

const (
	// maxResponseBytes caps how much of an admin response is read.
	maxResponseBytes = 1 << 20
	requestTimeout   = 10 * time.Second
)

// ErrInvalidConfig identifies an unusable admin API address.
var ErrInvalidConfig = errors.New("hydra: invalid admin configuration")

// AdminClient calls the private Hydra admin API. It never logs challenges,
// subjects, session IDs, or response bodies.
type AdminClient struct {
	base       *url.URL
	httpClient *http.Client
}

var _ service.SSOAdmin = (*AdminClient)(nil)

// NewAdminClient builds a client for the admin API at baseURL. A nil
// httpClient uses one with a bounded timeout.
func NewAdminClient(baseURL string, httpClient *http.Client) (*AdminClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, ErrInvalidConfig
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &AdminClient{base: parsed, httpClient: httpClient}, nil
}

type redirectResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// LoginRequest fetches a login request.
func (c *AdminClient) LoginRequest(ctx context.Context, challenge string) (service.SSOLoginRequest, error) {
	var payload struct {
		Skip      bool   `json:"skip"`
		Subject   string `json:"subject"`
		SessionID string `json:"session_id"`
	}
	if err := c.call(ctx, http.MethodGet, "/admin/oauth2/auth/requests/login", url.Values{"login_challenge": {challenge}}, nil, &payload); err != nil {
		return service.SSOLoginRequest{}, err
	}
	return service.SSOLoginRequest{Skip: payload.Skip, Subject: payload.Subject, SessionID: payload.SessionID}, nil
}

// AcceptLogin accepts a login request for subject and asks Hydra to remember
// the browser for rememberFor.
func (c *AdminClient) AcceptLogin(ctx context.Context, challenge, subject string, rememberFor time.Duration) (string, error) {
	body := map[string]any{"subject": subject, "remember": true, "remember_for": int64(rememberFor / time.Second)}
	return c.redirect(ctx, "/admin/oauth2/auth/requests/login/accept", url.Values{"login_challenge": {challenge}}, body)
}

// RejectLogin denies a login request.
func (c *AdminClient) RejectLogin(ctx context.Context, challenge string) (string, error) {
	return c.redirect(ctx, "/admin/oauth2/auth/requests/login/reject", url.Values{"login_challenge": {challenge}}, accessDenied())
}

// ConsentRequest fetches a consent request.
func (c *AdminClient) ConsentRequest(ctx context.Context, challenge string) (service.SSOConsentRequest, error) {
	var payload struct {
		Subject           string   `json:"subject"`
		LoginSessionID    string   `json:"login_session_id"`
		RequestedScope    []string `json:"requested_scope"`
		RequestedAudience []string `json:"requested_access_token_audience"`
	}
	if err := c.call(ctx, http.MethodGet, "/admin/oauth2/auth/requests/consent", url.Values{"consent_challenge": {challenge}}, nil, &payload); err != nil {
		return service.SSOConsentRequest{}, err
	}
	return service.SSOConsentRequest{
		Subject:           payload.Subject,
		LoginSessionID:    payload.LoginSessionID,
		RequestedScope:    payload.RequestedScope,
		RequestedAudience: payload.RequestedAudience,
	}, nil
}

// AcceptConsent grants scopes, audiences, and ID token claims.
func (c *AdminClient) AcceptConsent(ctx context.Context, challenge string, grant service.SSOConsentGrant) (string, error) {
	claims := grant.IDTokenClaims
	if claims == nil {
		claims = map[string]any{}
	}
	body := map[string]any{
		"grant_scope":                 nonNil(grant.Scope),
		"grant_access_token_audience": nonNil(grant.Audience),
		"remember":                    true,
		"remember_for":                int64(grant.RememberFor / time.Second),
		"session":                     map[string]any{"id_token": claims},
	}
	return c.redirect(ctx, "/admin/oauth2/auth/requests/consent/accept", url.Values{"consent_challenge": {challenge}}, body)
}

// RejectConsent denies a consent request.
func (c *AdminClient) RejectConsent(ctx context.Context, challenge string) (string, error) {
	return c.redirect(ctx, "/admin/oauth2/auth/requests/consent/reject", url.Values{"consent_challenge": {challenge}}, accessDenied())
}

// LogoutRequest fetches a logout request.
func (c *AdminClient) LogoutRequest(ctx context.Context, challenge string) (service.SSOLogoutRequest, error) {
	var payload struct {
		Subject   string `json:"subject"`
		SessionID string `json:"sid"`
	}
	if err := c.call(ctx, http.MethodGet, "/admin/oauth2/auth/requests/logout", url.Values{"logout_challenge": {challenge}}, nil, &payload); err != nil {
		return service.SSOLogoutRequest{}, err
	}
	return service.SSOLogoutRequest{Subject: payload.Subject, SessionID: payload.SessionID}, nil
}

// AcceptLogout accepts a logout request.
func (c *AdminClient) AcceptLogout(ctx context.Context, challenge string) (string, error) {
	return c.redirect(ctx, "/admin/oauth2/auth/requests/logout/accept", url.Values{"logout_challenge": {challenge}}, nil)
}

// RevokeLoginSession revokes one Hydra login session, which triggers
// back-channel logout to client apps. An unknown session counts as revoked.
func (c *AdminClient) RevokeLoginSession(ctx context.Context, sid string) error {
	err := c.call(ctx, http.MethodDelete, "/admin/oauth2/auth/sessions/login", url.Values{"sid": {sid}}, nil, nil)
	if errors.Is(err, service.ErrSSOChallengeExpired) {
		return nil
	}
	return err
}

// RevokeConsentSessions revokes every consent of subject, which invalidates
// the access and refresh tokens issued to client apps.
func (c *AdminClient) RevokeConsentSessions(ctx context.Context, subject string) error {
	err := c.call(ctx, http.MethodDelete, "/admin/oauth2/auth/sessions/consent", url.Values{"subject": {subject}, "all": {"true"}}, nil, nil)
	if errors.Is(err, service.ErrSSOChallengeExpired) {
		return nil
	}
	return err
}

func (c *AdminClient) redirect(ctx context.Context, path string, query url.Values, body any) (string, error) {
	var payload redirectResponse
	if err := c.call(ctx, http.MethodPut, path, query, body, &payload); err != nil {
		return "", err
	}
	target, err := url.Parse(payload.RedirectTo)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return "", fmt.Errorf("%w: invalid redirect", service.ErrSSOUnavailable)
	}
	return target.String(), nil
}

// call sends one admin request. Hydra answers 404 for unknown and 410 for
// already-handled requests; both mean the challenge can no longer be used.
func (c *AdminClient) call(ctx context.Context, method, path string, query url.Values, body, out any) error {
	if c == nil || c.base == nil || c.httpClient == nil {
		return ErrInvalidConfig
	}
	endpoint := *c.base
	endpoint.Path = c.base.Path + path
	endpoint.RawQuery = query.Encode()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%w: encode request", service.ErrSSOUnavailable)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return fmt.Errorf("%w: build request", service.ErrSSOUnavailable)
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %s %s unreachable", service.ErrSSOUnavailable, method, path)
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone:
		return service.ErrSSOChallengeExpired
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return fmt.Errorf("%w: %s %s returned status %d", service.ErrSSOUnavailable, method, path, response.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("%w: decode %s response", service.ErrSSOUnavailable, path)
	}
	return nil
}

func accessDenied() map[string]any {
	return map[string]any{"error": "access_denied", "error_description": "The account cannot sign in to this application."}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
