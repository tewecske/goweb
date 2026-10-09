// Package oauth implements external identity provider clients.
package oauth

import (
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
	// GoogleProviderName is the canonical registry name of the Google client.
	GoogleProviderName = "google"

	googleAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint         = "https://oauth2.googleapis.com/token"
	googleUserInfoEndpoint      = "https://openidconnect.googleapis.com/v1/userinfo"
	googleScopes                = "openid email profile"
	// maxGoogleResponseBytes caps how much of a provider response is read so a
	// hostile or broken endpoint cannot exhaust memory.
	maxGoogleResponseBytes = 1 << 20
	googleRequestTimeout   = 10 * time.Second
)

// ErrInvalidGoogleConfig identifies unusable Google client configuration.
var ErrInvalidGoogleConfig = errors.New("oauth: invalid google configuration")

// GoogleConfig configures one Google OAuth client.
type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// GoogleClient implements the service OAuth provider port for Google.
type GoogleClient struct {
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client

	authorizationEndpoint string
	tokenEndpoint         string
	userInfoEndpoint      string
}

var _ service.OAuthProviderClient = (*GoogleClient)(nil)

// NewGoogleClient validates configuration and builds a Google provider client.
func NewGoogleClient(configuration GoogleConfig) (*GoogleClient, error) {
	clientID := strings.TrimSpace(configuration.ClientID)
	clientSecret := strings.TrimSpace(configuration.ClientSecret)
	redirectURL := strings.TrimSpace(configuration.RedirectURL)
	if clientID == "" || clientSecret == "" || !validRedirectURL(redirectURL) {
		return nil, ErrInvalidGoogleConfig
	}
	return &GoogleClient{
		clientID:              clientID,
		clientSecret:          clientSecret,
		redirectURL:           redirectURL,
		httpClient:            &http.Client{Timeout: googleRequestTimeout},
		authorizationEndpoint: googleAuthorizationEndpoint,
		tokenEndpoint:         googleTokenEndpoint,
		userInfoEndpoint:      googleUserInfoEndpoint,
	}, nil
}

// Name returns the canonical provider name used by the registry.
func (c *GoogleClient) Name() string {
	return GoogleProviderName
}

// AuthorizationURL builds the Google consent redirect for one callback state
// and PKCE S256 code challenge.
func (c *GoogleClient) AuthorizationURL(_ context.Context, state, codeChallenge string) (string, error) {
	if c == nil || !validRedirectURL(c.redirectURL) || strings.TrimSpace(state) == "" || strings.TrimSpace(codeChallenge) == "" {
		return "", ErrInvalidGoogleConfig
	}
	endpoint, err := url.Parse(c.authorizationEndpoint)
	if err != nil {
		return "", ErrInvalidGoogleConfig
	}
	query := endpoint.Query()
	query.Set("client_id", c.clientID)
	query.Set("redirect_uri", c.redirectURL)
	query.Set("response_type", "code")
	query.Set("scope", googleScopes)
	query.Set("state", state)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	query.Set("prompt", "select_account")
	query.Set("include_granted_scopes", "true")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

// Exchange redeems an authorization code and its PKCE code verifier for the
// Google profile asserted by the provider. It resolves the stable subject,
// never a reported email.
func (c *GoogleClient) Exchange(ctx context.Context, code, codeVerifier string) (service.OAuthProfile, error) {
	if c == nil || c.httpClient == nil {
		return service.OAuthProfile{}, ErrInvalidGoogleConfig
	}
	accessToken, err := c.exchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return service.OAuthProfile{}, err
	}
	return c.fetchProfile(ctx, accessToken)
}

func (c *GoogleClient) exchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(codeVerifier) == "" {
		return "", ErrInvalidGoogleConfig
	}
	form := url.Values{
		"code":          {code},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"redirect_uri":  {c.redirectURL},
		"grant_type":    {"authorization_code"},
		"code_verifier": {codeVerifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errTokenExchange
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", errTokenExchange
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errTokenExchange
	}
	payload, err := decodeLimitedJSON[struct {
		AccessToken string `json:"access_token"`
	}](response.Body)
	if err != nil || strings.TrimSpace(payload.AccessToken) == "" {
		return "", errTokenExchange
	}
	return payload.AccessToken, nil
}

func (c *GoogleClient) fetchProfile(ctx context.Context, accessToken string) (service.OAuthProfile, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoEndpoint, nil)
	if err != nil {
		return service.OAuthProfile{}, errUserInfo
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return service.OAuthProfile{}, errUserInfo
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return service.OAuthProfile{}, errUserInfo
	}
	payload, err := decodeLimitedJSON[struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}](response.Body)
	if err != nil || strings.TrimSpace(payload.Subject) == "" {
		return service.OAuthProfile{}, errUserInfo
	}
	return service.OAuthProfile{
		Subject:       payload.Subject,
		Email:         payload.Email,
		EmailVerified: payload.EmailVerified,
		DisplayName:   payload.Name,
	}, nil
}

var (
	errTokenExchange = errors.New("oauth: google token exchange failed")
	errUserInfo      = errors.New("oauth: google user info failed")
)

func decodeLimitedJSON[T any](reader io.Reader) (T, error) {
	var value T
	limited := io.LimitReader(reader, maxGoogleResponseBytes)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	return value, nil
}

func validRedirectURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

// String keeps the configured client secret out of formatted diagnostics.
func (c *GoogleClient) String() string {
	if c == nil {
		return "oauth.GoogleClient{}"
	}
	return fmt.Sprintf("oauth.GoogleClient{client_id_configured:%t}", c.clientID != "")
}

// GoString keeps %#v diagnostics redacted too.
func (c *GoogleClient) GoString() string {
	return c.String()
}
