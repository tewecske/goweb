package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/tewecske/goweb/internal/adapter/http/middleware"
	"github.com/tewecske/goweb/internal/service"
)

var (
	ErrInvalidHTTPDependencies = errors.New("http: invalid service dependencies")
	ErrSessionAuthentication   = errors.New("http: session authentication failed")
)

// Dependencies contains consuming-side ports used by HTTP handlers. Concrete
// repositories and services are assembled by the application composition
// package and passed here by process startup.
type Dependencies struct {
	Users         UserFinder
	Sessions      SessionLookup
	SessionAdmin  SessionSignOut
	SessionCookie *middleware.SessionCookie

	SignUp  SignUpper
	SignIn  SignInner
	SignOut SignOuter

	ConfirmationIssuer   ConfirmationIssuer
	ConfirmationResender ConfirmationResender
	ConfirmationConsumer ConfirmationConsumer
	PasswordResetter     PasswordResetter
	PasswordResetterUse  PasswordResetterUse
	OAuth                OAuthAuthenticator
	OAuthProviders       OAuthProviderLister
}

// UserFinder resolves an account for an authenticated session.
type UserFinder interface {
	FindUserByID(context.Context, int64) (service.User, error)
}

// SessionLookup validates an opaque session credential.
type SessionLookup interface {
	Lookup(context.Context, string) (service.Session, error)
}

// SessionSignOut revokes one opaque session credential.
type SessionSignOut interface {
	SignOut(context.Context, string) error
}

// SignUpper creates password-backed accounts.
type SignUpper interface {
	SignUp(context.Context, service.SignUpInput) (service.SignUpResult, error)
}

// SignInner authenticates password-backed accounts.
type SignInner interface {
	SignIn(context.Context, service.SignInInput, string) (service.SignInResult, error)
}

// SignOuter revokes the current session.
type SignOuter interface {
	SignOut(context.Context, string) error
}

type ConfirmationIssuer interface {
	Issue(context.Context, int64) error
}

type ConfirmationResender interface {
	Resend(context.Context, string) error
}

type ConfirmationConsumer interface {
	Confirm(context.Context, string) error
}

type PasswordResetter interface {
	Request(context.Context, string) error
}

type PasswordResetterUse interface {
	Redeem(context.Context, string, string) error
}

type OAuthAuthenticator interface {
	Start(context.Context, string) (string, error)
	Callback(context.Context, string, string, string) (service.OAuthSignInResult, error)
}

type OAuthProviderLister interface {
	Names() []string
}

// Validate checks dependencies needed by session-aware routes.
func (d Dependencies) Validate() error {
	if d.Users == nil || d.Sessions == nil || d.SessionAdmin == nil || d.SessionCookie == nil {
		return ErrInvalidHTTPDependencies
	}
	return nil
}

// SessionAuthenticator resolves an authenticated account from its opaque
// browser cookie. It never exposes the cookie value through Principal.
type SessionAuthenticator struct {
	users    UserFinder
	sessions SessionLookup
	cookie   *middleware.SessionCookie
}

// NewSessionAuthenticator constructs request authentication from explicit
// session and account ports.
func NewSessionAuthenticator(users UserFinder, sessions SessionLookup, cookie *middleware.SessionCookie) (*SessionAuthenticator, error) {
	if users == nil || sessions == nil || cookie == nil {
		return nil, ErrInvalidHTTPDependencies
	}
	return &SessionAuthenticator{users: users, sessions: sessions, cookie: cookie}, nil
}

// Authenticate validates the current browser session and returns only safe
// account identity and authorization state.
func (a *SessionAuthenticator) Authenticate(ctx context.Context, request *http.Request) (middleware.Principal, error) {
	if a == nil || a.users == nil || a.sessions == nil || a.cookie == nil || ctx == nil || request == nil {
		return middleware.Principal{}, ErrSessionAuthentication
	}
	sessionID, ok := a.cookie.Read(request)
	if !ok {
		return middleware.Principal{}, middleware.ErrUnauthenticated
	}
	session, err := a.sessions.Lookup(ctx, sessionID)
	if err != nil {
		return middleware.Principal{}, middleware.ErrUnauthenticated
	}
	user, err := a.users.FindUserByID(ctx, session.UserID)
	if err != nil || user.ID != session.UserID {
		return middleware.Principal{}, ErrSessionAuthentication
	}
	return middleware.Principal{ID: strconv.FormatInt(user.ID, 10), IsAdmin: user.IsAdmin}, nil
}
